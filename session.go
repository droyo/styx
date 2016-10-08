package styx

import (
	"io"
	"os"
	"path"
	"strings"
	"sync"

	"context"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/internal/threadsafe"
	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/styxproto"
)

// A Session is a sequence of related 9P messages from a single client. It
// begins when a client opens the root of a file tree, and ends when all of
// its files are closed. Sessions occur over a single connection and are
// associated with a single user and file tree. Over a single session,
// a user may perform multiple operations on multiple files. Multiple
// sessions may be multiplexed over a single connection.
type Session struct {
	// User is the name of the user associated with the session.
	// When establishing a session, the client provides a username, This
	// may or may not be authenticated, depending on the Server in use.
	User string

	// Access is the name of the file tree requested by a client when
	// it establishes a session, in the "aname" field of its "Tattach"
	// request. When the EnableVHost option is used, if a client does
	// not specify one, this is set to the hostname the client used
	// to connect to the server, for non-TLS connections, and the SNI
	// provided by the client, for TLS connections.
	Access string

	// Incoming requests from the client will be sent over the requests
	// channel. When a new request is received, the previous request is
	// no longer valid. The requests channel is closed when a session
	// is ended.
	requests chan Request
	closeMu  sync.Mutex

	// This is the most recent request processed. It must be cleaned
	// up with each call to Next().
	req Request

	// To enable "middleware" like net/http allows, while still providing
	// the Serve9P API that ties a session lifetime to the lifetime
	// of a single function call, we must be able to pass a request
	// along the line and wait for any downstream handlers to finish
	// processing it. This channel coordinates that.
	pipeline chan Request

	// True when the current request is unanswered
	unhandled bool

	// Sends nil once auth is successful, err otherwise.  Closed after
	// authentication is complete, so can only be used once.
	authC chan error

	// Underlying connection this session takes place on.
	*conn

	// This tracks the number of fids pointing to this session in
	// conn.sessionFid. We need to know when all references are gone
	// so we can properly close any session channels.
	util.RefCount

	// Open (or unopened) files, indexed by fid.
	files *threadsafe.Map
}

// create a new session and register its fid in the conn.
type fattach interface {
	styxproto.Msg
	Uname() []byte
	Aname() []byte
}

func newSession(c *conn, m fattach) *Session {
	s := &Session{
		User:     string(m.Uname()),
		Access:   string(m.Aname()),
		conn:     c,
		files:    threadsafe.NewMap(),
		authC:    make(chan error, 1),
		requests: make(chan Request),
	}
	return s
}

func openFlag(mode uint8) int {
	var flag int
	if mode&styxproto.OWRITE != 0 {
		flag = os.O_WRONLY
	}
	if mode&styxproto.ORDWR != 0 {
		flag = os.O_RDWR
	}
	if mode&styxproto.OEXEC != 0 {
		flag = os.O_RDONLY
	}
	if mode&styxproto.OTRUNC != 0 {
		flag |= os.O_TRUNC
	}
	return flag
}

func (s *Session) fetchFile(fid uint32) (file, bool) {
	if v, ok := s.files.Get(fid); ok {
		return v.(file), true
	}
	return file{}, false
}

// Next waits for the next Request for a 9P session. The next request for
// the session can be accessed via the Request method if and only if Next
// returns true. Any previous messages retrieved for the session should not
// be modified or responded to after Next is called; if they have not been
// answered, the styx package will send default responses for them. The
// default response for a message can be found in the comments for each
// message type. Next returns false if the session has ended or there was
// an error receiving the next Request.
func (s *Session) Next() bool {
	var ok bool
	if s.req != nil {
		if !s.req.handled() {
			if s.pipeline != nil { // this is a nested handler
				s.pipeline <- s.req
			} else {
				s.req.defaultResponse()
			}
		} else if s.pipeline != nil {
			s.pipeline <- nil
		}
	}
	if s.conn.Flush() != nil {
		return false
	}
	s.req, ok = <-s.requests
	if ok {
		s.unhandled = true
	}
	return ok
}

// Request returns the last 9P message received by the Session. It is only
// valid until the next call to Next.
func (s *Session) Request() Request {
	return s.req
}

// When multiple Handlers are combined together using Stack, a handler may
// modify the incoming request using the UpdateRequest method.  The current
// request will be overwritten with r, and reflected in calls to the Request
// method in he current and all downstream handlers.
func (s *Session) UpdateRequest(r Request) {
	s.req = r
}

func (s *Session) handleTwalk(ctx context.Context, msg styxproto.Twalk, file file) bool {
	newfid := msg.Newfid()

	// Cannot use "opened" (ready for IO) fids for walking; see walk(5)
	// in 9P manual. However, 9pfuse does this, so we'll allow it.
	//if file.rwc != nil {
	//	s.conn.Rerror(msg.Tag(), "walk on opened fid")
	//	s.conn.Flush()
	//	return true
	//}

	// newfid must be unused or equal to fid
	if newfid != msg.Fid() {
		if _, ok := s.conn.sessionFid.Get(newfid); ok {
			s.conn.clearTag(msg.Tag())
			s.conn.Rerror(msg.Tag(), "Twalk: fid %x already in use", newfid)
			s.conn.Flush()
			return true
		}
	}

	// NOTE(droyo) The clone usage of Twalk is hidden from the user
	// of the styx package; we assume that all clients who have procured
	// a fid for a file are permitted to clone that fid, and may do so without
	// side effects.
	if msg.Nwname() == 0 {
		if newfid != msg.Fid() {
			s.files.Put(newfid, file)
			s.conn.sessionFid.Put(newfid, s)
			s.IncRef()
		}
		s.conn.clearTag(msg.Tag())
		s.conn.Rwalk(msg.Tag())
		s.conn.Flush()
		return true
	}

	// see walk.go for more details
	elem := make([]string, 0, msg.Nwname())
	for i := 0; i < cap(elem); i++ {
		elem = append(elem, string(msg.Wname(i)))
	}
	walker := newWalker(s, ctx, msg, file.name, elem...)

	for i := range elem {
		fullpath := path.Join(file.name, strings.Join(elem[:i+1], "/"))
		s.requests <- Twalk{
			index:   i,
			walk:    walker,
			reqInfo: newReqInfo(ctx, s, msg, fullpath),
		}
	}
	return true
}

func (s *Session) handleTopen(ctx context.Context, msg styxproto.Topen, file file) bool {
	if file.rwc != nil {
		s.conn.clearTag(msg.Tag())
		s.conn.Rerror(msg.Tag(), "fid %d already open", msg.Fid())
		s.conn.Flush()
		return true
	}
	flag := openFlag(msg.Mode())
	s.requests <- Topen{
		Flag:    flag,
		reqInfo: newReqInfo(ctx, s, msg, file.name),
	}
	return true
}

func (s *Session) handleTcreate(ctx context.Context, msg styxproto.Tcreate, file file) bool {
	qid := s.conn.qid(file.name, 0)
	if qid.Type()&styxproto.QTDIR == 0 {
		s.conn.clearTag(msg.Tag())
		s.conn.Rerror(msg.Tag(), "not a directory: %q", file.name)
		s.conn.Flush()
		return true
	}
	s.requests <- Tcreate{
		Name:    string(msg.Name()),
		Mode:    styxfile.ModeOS(msg.Perm()),
		Flag:    openFlag(msg.Mode()),
		reqInfo: newReqInfo(ctx, s, msg, file.name),
	}
	return true
}

func (s *Session) handleTremove(ctx context.Context, msg styxproto.Tremove, file file) bool {
	s.requests <- Tremove{
		reqInfo: newReqInfo(ctx, s, msg, file.name),
	}
	return true
}

func (s *Session) handleTstat(ctx context.Context, msg styxproto.Tstat, file file) bool {
	buf := make([]byte, styxproto.MaxStatLen)
	if file.auth {
		stat, _, err := styxproto.NewStat(buf, "", "", "", "")
		if err != nil {
			// input is not user-controlled, this should
			// never happen
			panic(err)
		}
		stat.SetMode(styxproto.DMAUTH)
		stat.SetQid(s.conn.qid("", styxproto.QTAUTH))
		s.conn.clearTag(msg.Tag())
		s.conn.Rstat(msg.Tag(), stat)
		s.conn.Flush()
	} else if file.rwc != nil {
		s.conn.clearTag(msg.Tag())
		if qid, ok := s.conn.qidpool.Get(file.name); !ok {
			s.conn.Rerror(msg.Tag(), "qid for %s not found", file.name)
		} else if stat, err := styxfile.Stat(buf, file.rwc, file.name, qid); err != nil {
			s.conn.Rerror(msg.Tag(), "%s", err)
		} else {
			s.conn.Rstat(msg.Tag(), stat)
		}
		s.conn.Flush()
	} else {
		s.requests <- Tstat{
			reqInfo: newReqInfo(ctx, s, msg, file.name),
		}
	}
	return true
}

func (s *Session) handleTread(ctx context.Context, msg styxproto.Tread, file file) bool {
	var n int
	var err error
	if file.rwc == nil {
		s.conn.clearTag(msg.Tag())
		s.conn.Rerror(msg.Tag(), "file %s is not open for reading", file.name)
		s.conn.Flush()
		return true
	}

	go func() {
		// TODO(droyo) allocations could hurt here, come up with a better
		// way to do this (after measuring the impact, of course). The tricky bit
		// here is inherent to the 9P protocol; rather than using sentinel values,
		// each message is prefixed with its length. While this is generally a Good
		// Thing, this means we can't write directly to the connection, because
		// we don't know how much we are going to write until it's too late.
		buf := make([]byte, int(msg.Count()))

		if t, ok := ctx.Deadline(); ok {
			styxfile.SetDeadline(file.rwc, t)
		}
		done := make(chan struct{})
		go func() {
			n, err = file.rwc.ReadAt(buf, msg.Offset())
			close(done)
		}()
		select {
		case <-ctx.Done():
			// NOTE(droyo) deciding what to do here is somewhat
			// difficult. Many (but not all) Read/Write calls in Go can
			// be interrupted by calling Close. Obviously, calling Close
			// on a file will disrupt any current and future reads on the
			// same fid. However, that is preferrable to leaking goroutines.
			file.rwc.Close()
			s.conn.clearTag(msg.Tag())
			return
		case <-done:
		}

		s.conn.clearTag(msg.Tag())
		if n > 0 {
			s.conn.Rread(msg.Tag(), buf[:n])
		} else if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			s.conn.Rerror(msg.Tag(), "%v", err)
		} else {
			s.conn.Rread(msg.Tag(), buf[:n])
		}
		s.conn.Flush()
	}()
	return true
}

func (s *Session) handleTwrite(ctx context.Context, msg styxproto.Twrite, file file) bool {
	if file.rwc == nil {
		s.conn.clearTag(msg.Tag())
		s.conn.Rerror(msg.Tag(), "file %q is not opened for writing", file.name)
		s.conn.Flush()
		return true
	}

	// BUG(droyo): cancellation of write requests is not yet implemented.
	w := util.NewSectionWriter(file.rwc, msg.Offset(), msg.Count())
	n, err := io.Copy(w, msg)
	s.conn.clearTag(msg.Tag())
	if n == 0 && err != nil {
		s.conn.Rerror(msg.Tag(), "%v", err)
	} else {
		s.conn.Rwrite(msg.Tag(), n)
	}
	s.conn.Flush()
	return true
}

func (s *Session) handleTclunk(ctx context.Context, msg styxproto.Tclunk, file file) bool {
	defer s.conn.Flush()
	s.conn.sessionFid.Del(msg.Fid())
	s.conn.clearTag(msg.Tag())
	s.files.Del(msg.Fid())
	if file.rwc != nil {
		if err := file.rwc.Close(); err != nil {
			s.conn.Rerror(msg.Tag(), "close %s: %v", file.name, err)
		} else {
			s.conn.Rclunk(msg.Tag())
		}
	} else {
		s.conn.Rclunk(msg.Tag())
	}
	s.conn.Flush()
	if !s.DecRef() {
		s.endSession()
	}
	return true
}

// Called when there are no more fids associated with this
// session. The handler is still running and we must notify
// it.
func (s *Session) endSession() {
	s.closeMu.Lock()
	select {
	case _, ok := <-s.requests:
		if ok {
			close(s.requests)
		}
	default:
		close(s.requests)
	}
	s.closeMu.Unlock()
}

// Called when Serve9P exits. Any in-flight requests
// must be cancelled and any open files closed. Because
// this is running from the same goroutine as the connection's
// serve() method, and Serve9P has returned, we can be
// confident nothing is going to call Close on our files.
func (s *Session) cleanupHandler() {
	s.files.Do(func(m map[interface{}]interface{}) {
		for fid, v := range m {
			delete(m, fid)
			file := v.(file)
			if file.rwc != nil {
				file.rwc.Close()
			}
		}
	})
}
