package styx

import (
	"bytes"
	"io"
	"os"
	"path"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/styxproto"
)

// A Session is a 9P session. It begins when a user opens the root of
// a file tree, and ends when all of its files are closed. Sessions
// occur over a single connection and are associated with a single
// user and root directory.  Over a single session, a user may perform
// multiple operations on multiple files.  Sessions may be multiplexed
// over a single connection.
type Session struct {
	// User is the name of the user associated with a session.
	// When establishing a session, the client provides a username,
	// This may or may not be authenticated, depending on the
	// Server in use.
	User string

	// Access is the name of the file tree requested by a client
	// when it establishes a session, in the "aname" field of its
	// "Tattach" request. When the EnableVHost option is used, if
	// a client does not specify one, this is set to the hostname
	// the client used to connect to the server, for non-TLS
	// connections, and the SNI provided by the client, for TLS
	// connections.
	Access string

	// Incoming requests from the client will be sent over the
	// Requests channel. When a new Request is received, the
	// previous request is no longer valid. The Requests channel
	// is closed when a session is over.
	Requests chan Request

	// Underlying connection this session takes place on.
	*conn

	// This tracks the number of fids pointing to this session
	// in conn.sessionFid. We need to know when all references
	// are gone so we can properly close any session channels.
	util.RefCount

	// Open (or unopened) files, indexed by fid.
	files *util.Map
}

// create a new session and register its fid in the conn.
func newSession(c *conn, m styxproto.Tattach) *Session {
	s := &Session{
		User:     string(m.Uname()),
		Access:   string(m.Aname()),
		conn:     c,
		files:    util.NewMap(),
		Requests: make(chan Request),
	}
	c.sessionFid.Put(m.Fid(), s)
	s.IncRef()
	s.files.Put(m.Fid(), file{name: "/", rwc: nil})
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

func (s *Session) handleTwalk(cx context.Context, msg styxproto.Twalk, file file) bool {
	newpath := file.name
	newfid := msg.Newfid()

	// Cannot use "opened" (ready for IO) fids for walking; see
	// walk(5) in 9P manual.
	if file.rwc != nil {
		s.conn.Rerror(msg.Tag(), "Fid %q is open for IO; cannot use for Twalk", file.name)
		return false
	}

	// newfid must be unused or equal to fid
	if newfid != msg.Fid() {
		if _, ok := s.conn.sessionFid.Get(newfid); ok {
			s.conn.Rerror(msg.Tag(), "Twalk: fid %x already in use", newfid)
			return false
		}
	}

	// NOTE(droyo) The clone usage of Twalk is hidden from the user
	// of the "styx" library; we assume that all clients who have procured
	// a fid for a file are permitted to clone that fid, and may do so without
	// side effects.
	if msg.Nwname() == 0 {
		if newfid != msg.Fid() {
			s.files.Put(newfid, file)
			s.conn.sessionFid.Put(newfid, s)
			s.IncRef()
		}
		s.conn.Rwalk(msg.Tag())
		return true
	}

	// TODO(droyo) think about how we're handling '..' here;
	// the "path" package should cover us but we should be
	// sure about what happens with bad/evil paths like
	// ../../../etc/shadow , etc
	for i := 0; i < msg.Nwname(); i++ {
		newpath = path.Join(newpath, string(msg.Wname(i)))
	}

	s.Requests <- Twalk{
		newfid:  newfid,
		newpath: newpath,
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTopen(cx context.Context, msg styxproto.Topen, file file) bool {
	flag := openFlag(msg.Mode())
	s.Requests <- Topen{
		Flag:    flag,
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTcreate(cx context.Context, msg styxproto.Tcreate, file file) bool {
	qid := s.conn.qid(file.name, 0)
	if qid.Type()&styxproto.QTDIR == 0 {
		s.conn.Rerror(msg.Tag(), "not a directory: %q", file.name)
		return false
	}
	s.Requests <- Tcreate{
		Name:    string(msg.Name()),
		Perm:    fileMode(msg.Perm()),
		Flag:    openFlag(msg.Mode()),
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTremove(cx context.Context, msg styxproto.Tremove, file file) bool {
	s.Requests <- Tremove{
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTstat(cx context.Context, msg styxproto.Tstat, file file) bool {
	s.Requests <- Tstat{
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTwstat(cx context.Context, msg styxproto.Twstat, file file) bool {
	s.Requests <- Twstat{
		Stat:    nil,
		reqInfo: newReqInfo(cx, s, msg, file),
	}
	return true
}

func (s *Session) handleTread(cx context.Context, msg styxproto.Tread, file file) bool {
	if file.rwc == nil {
		s.conn.Rerror(msg.Tag(), "file %q is not open for reading", file.name)
		return false
	}

	// TODO(droyo) allocations could hurt here, come up with a better
	// way to do this (after measuring the impact, of course). The tricky bit
	// here is inherent to the 9P protocol; rather than using sentinel values,
	// each message is prefixed with its length. While this is generally a Good
	// Thing, this means we can't write directly to the connection, because
	// we don't know how much we are going to write until it's too late.
	var buf bytes.Buffer

	// TODO(droyo) handle offset
	// TODO(droyo) handle cancellation
	_, err := io.CopyN(&buf, file.rwc, msg.Count())
	if err != nil {
		s.conn.Rerror(msg.Tag(), "%v", err)
	}
	s.conn.Rread(msg.Tag(), buf.Bytes())
	return true
}

func (s *Session) handleTwrite(cx context.Context, msg styxproto.Twrite, file file) bool {
	if file.rwc == nil {
		s.conn.Rerror(msg.Tag(), "file %q is not opened for writing", file.name)
		return false
	}
	// TODO(droyo): handle offset
	// TODO(droyo): handle cancellation
	n, err := io.Copy(file.rwc, msg)
	if err != nil {
		s.conn.Rerror(msg.Tag(), "%v", err)
	}
	s.conn.Rwrite(msg.Tag(), n)
	return true
}

func (s *Session) handleTclunk(cx context.Context, msg styxproto.Tclunk, file file) bool {
	s.conn.sessionFid.Del(msg.Fid())
	if file.rwc != nil {
		if err := file.rwc.Close(); err != nil {
			s.conn.Rerror(msg.Tag(), "close %s: %v", file.name, err)
		}
	}
	s.files.Del(msg.Fid())
	s.conn.Rclunk(msg.Tag())
	return s.DecRef()
}

// Called when there are no more fids associated with this
// session. The handler is still running and we must notify
// it.
func (s *Session) endSession() {
	if s.Requests != nil {
		close(s.Requests)
		s.Requests = nil
	}
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
