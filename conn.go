package styx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/styxproto"

	"golang.org/x/net/context"
)

var (
	errFidInUse     = errors.New("fid already in use")
	errTagInUse     = errors.New("tag in use")
	errNoFid        = errors.New("no such fid")
	errNotSupported = errors.New("not supported")
)

type fcall interface {
	styxproto.Msg
	Fid() uint32
}

// A note on identifiers (fids & tags)
//
// identifiers are chosen by the client, not by the server.  Therefore,
// it is important that the performance and behavior of a server does
// *not* change based on the fid or tag a client chooses. This is why
// a map is used; its performance is good, and doesn't change based
// on the input a client chooses (rather, it does not change in a way
// a client can predict).

// A conn receives and sends 9P messages across a single network connection.
// Multiple "sessions" may take place over a single connection. The conn
// struct contains the necessary information to route 9P messages to their
// established sessions.
type conn struct {
	// These wrap the network connection to read and write messages.
	*styxproto.Decoder
	*styxproto.Encoder

	// The Server a connection was spawned from. Contains configuration
	// settings and the authentication function, if any.
	srv *Server

	// The network connection itself. We expose it in the struct so that
	// it is available for transport-based auth and any timeouts we need
	// to implement.
	rwc io.ReadWriteCloser

	// This serves as the parent context for the context attached to all
	// requests.
	cx context.Context

	// While srv.MaxSize holds the *desired* 9P protocol message
	// size, msize will contain the actual maximum negotiated with
	// the client, through a Tversion/Rversion exchange.
	msize int64

	// There is no "session id" in 9P. However, because all fids
	// for a connection must be derived from the fid established
	// in a Tattach call, any message that contains a fid can be
	// traced back to the original Tattach message.
	sessionFid *util.Map

	// Qids for the file tree, added on-demand.
	qids    *util.Map
	qidPath uint64

	// used to implement request cancellation when a Tflush
	// message is received.
	pendingReq map[uint16]context.CancelFunc
}

func (c *conn) remoteAddr() net.Addr {
	type hasRemote interface {
		RemoteAddr() net.Addr
	}
	if nc, ok := c.rwc.(hasRemote); ok {
		return nc.RemoteAddr()
	}
	return nil
}

func (c *conn) sessionByFid(fid uint32) (*Session, bool) {
	if v, ok := c.sessionFid.Get(fid); ok {
		return v.(*Session), true
	}
	return nil, false
}

// Close the connection
func (c *conn) close() error {
	// Cancel all pending requests
	for tag, cancel := range c.pendingReq {
		cancel()
		delete(c.pendingReq, tag)
	}

	// Close all open files and sessions
	c.sessionFid.Do(func(m map[interface{}]interface{}) {
		seen := make(map[*Session]struct{}, len(m))
		for k, v := range m {
			session := v.(*Session)
			if _, ok := seen[session]; !ok {
				seen[session] = struct{}{}
				session.endSession()
			}
			// Should probably let the GC take care of this
			delete(m, k)
		}
	})

	return c.rwc.Close()
}

func newConn(srv *Server, rwc io.ReadWriteCloser) *conn {
	var msize int64 = styxproto.DefaultMaxSize
	if srv.MaxSize > 0 {
		if srv.MaxSize > styxproto.MinBufSize {
			msize = srv.MaxSize
		} else {
			msize = styxproto.MinBufSize
		}
	}
	return &conn{
		Decoder:    styxproto.NewDecoder(rwc),
		Encoder:    styxproto.NewEncoder(rwc),
		srv:        srv,
		rwc:        rwc,
		cx:         context.TODO(),
		msize:      msize,
		sessionFid: util.NewMap(),
		pendingReq: make(map[uint16]context.CancelFunc),
		qids:       util.NewMap(),
	}
}

func (c *conn) qid(name string, qtype uint8) styxproto.Qid {
	buf := make([]byte, styxproto.QidLen)
	qpath := atomic.AddUint64(&c.qidPath, 1)
	qid, _, err := styxproto.NewQid(buf, qtype, 0, qpath)
	if err != nil {
		// This should *never* happen
		panic(err)
	}
	return qid
}

// All request contexts must have their cancel functions
// called, to free up resources in the context.
func (c *conn) clearTag(tag uint16) {
	if cancel, ok := c.pendingReq[tag]; ok {
		cancel()
		delete(c.pendingReq, tag)
	}
}

// runs in its own goroutine, one per connection.
func (c *conn) serve() {
	defer c.close()

	if !c.acceptTversion() {
		return
	}

Loop:
	for c.Next() {
		for _, m := range c.Messages() {
			c.srv.debugf("%d %s", m.Tag(), m)
			if !c.handleMessage(m) {
				break Loop
			}
		}
	}
}

func (c *conn) handleMessage(m styxproto.Msg) bool {
	if _, ok := c.pendingReq[m.Tag()]; ok {
		c.Rerror(m.Tag(), "%s", errTagInUse)
		return false
	}
	cx, cancel := context.WithCancel(c.cx)
	c.pendingReq[m.Tag()] = cancel
	defer c.clearTag(m.Tag())

	switch m := m.(type) {
	case styxproto.Tauth:
		return c.handleTauth(cx, m)
	case styxproto.Tattach:
		return c.handleTattach(cx, m)
	case styxproto.Tflush:
		return c.handleTflush(cx, m)
	case fcall:
		return c.handleFcall(cx, m)
	case styxproto.BadMessage:
		c.srv.logf("got bad message from %s: %s", c.remoteAddr(), m.Err)
		c.Rerror(m.Tag(), "bad message: %s", m.Err)
		return false
	default:
		c.Rerror(m.Tag(), "unexpected %T message", m)
		return false
	}
	return true
}

// This is the first thing we do on a new connection. The first
// message a client sends *must* be a Tversion message.
func (c *conn) acceptTversion() bool {
	c.Encoder.MaxSize = c.msize
	c.Decoder.MaxSize = c.msize

Loop:
	for c.Next() {
		for _, m := range c.Messages() {
			c.srv.debugf("%d %s", m.Tag(), m)
			tver, ok := m.(styxproto.Tversion)
			if !ok {
				c.Rerror(m.Tag(), "need Tversion")
				break Loop
			}
			msize := tver.Msize()
			if msize < styxproto.MinBufSize {
				c.Rerror(m.Tag(), "buffer too small")
				break Loop
			}
			if msize < c.msize {
				c.msize = msize
				c.Encoder.MaxSize = msize
				c.Decoder.MaxSize = msize
			}
			if !bytes.HasPrefix(tver.Version(), []byte("9P2000")) {
				c.Rversion(uint32(c.msize), "unknown")
			}
			c.Rversion(uint32(c.msize), "9P2000")
			return true
		}
	}
	return false
}

// NOTE(droyo) consider a scenario where a malicious actor connects
// to the server that repeatedly spams Tauth requests. It can quickly
// use up resources on the server. Consider the following measures:
//
// - rate-limiting Tauth requests
// - Setting a per-connection session limit
// - close connections that have not established a session in N seconds
func (c *conn) handleTauth(cx context.Context, m styxproto.Tauth) bool {
	if c.srv.Auth == nil {
		c.Rerror(m.Tag(), "%s", errNotSupported)
		return true
	}
	if _, ok := c.sessionFid.Get(m.Afid()); ok {
		c.Rerror(m.Tag(), "fid %x in use", m.Afid())
		return false
	}
	client, server := net.Pipe()
	ch := &Channel{
		Context:         c.cx,
		ReadWriteCloser: server,
	}
	rwc, err := styxfile.New(client)
	if err != nil {
		// This should never happen
		panic(err)
	}
	s := newSession(c, m)
	go func() {
		s.authC <- c.srv.Auth(ch, s.User, s.Access)
		close(s.authC)
	}()

	c.sessionFid.Put(m.Afid(), s)
	s.files.Put(m.Afid(), file{rwc: rwc, auth: true})
	s.IncRef()
	return true
}

func (c *conn) handleTattach(cx context.Context, m styxproto.Tattach) bool {
	var handler Handler = DefaultServeMux
	if c.srv.Handler != nil {
		handler = c.srv.Handler
	}
	var s *Session
	if c.srv.Auth == nil {
		s = newSession(c, m)
	} else {
		// TODO(droyo) when a transport-based authentication scheme
		// is in use, the client should not have to do a Tauth request.
		// We should call the Auth handler if Afid is NOFID, passing it
		// a util.BlackHole.
		if !c.sessionFid.Fetch(s, m.Afid()) {
			c.Rerror(m.Tag(), "invalid afid %x", m.Afid())
			return false
		}
		// From attach(5): The same validated afid may be used for
		// multiple attach messages with the same uname and aname.
		if s.User != string(m.Uname()) || s.Access != string(m.Aname()) {
			c.Rerror(m.Tag(), "afid mismatch for %s on %s", m.Uname(), m.Aname())
			return false
		}
		if err := <-s.authC; err != nil {
			c.Rerror(m.Tag(), "auth failed: %s", err)
			return false
		}
	}
	go func() {
		handler.Serve9P(s)
		s.cleanupHandler()
	}()
	c.sessionFid.Put(m.Fid(), s)
	s.IncRef()
	s.files.Put(m.Fid(), file{name: "/", rwc: nil})
	c.Rattach(m.Tag(), c.qid("/", styxproto.QTDIR))
	return true
}

func (c *conn) handleTflush(cx context.Context, m styxproto.Tflush) bool {
	oldtag := m.Oldtag()
	c.clearTag(oldtag)

	defer c.clearTag(m.Tag())
	c.Rflush(m.Tag())
	return true
}

func (c *conn) handleFcall(cx context.Context, msg fcall) bool {
	s, ok := c.sessionByFid(msg.Fid())
	if !ok {
		c.Rerror(msg.Tag(), "%s", errNoFid)
		return false
	}

	file, ok := s.fetchFile(msg.Fid())
	if !ok {
		panic("bug: fid in session map, but no file associated")
		return false
	}

	// NOTE(droyo) on security and anonymous users: On a server with
	// authentication enabled, a client can only ever establish a handle
	// to the auth file.  At this point, we have checked that the fid
	// is valid, so *file can only be an auth file if the user has not
	// completed a Tattach.
	if file.auth {
		// Limit the number of request handlers we have to
		// audit.
		switch msg := msg.(type) {
		case styxproto.Twrite:
		case styxproto.Tread:
		case styxproto.Tstat:
		case styxproto.Tclunk:
		default:
			c.Rerror(msg.Tag(), "%T not allowed on afid", msg)
			return false
		}
	}

	switch msg := msg.(type) {
	case styxproto.Twalk:
		return s.handleTwalk(cx, msg, file)
	case styxproto.Topen:
		return s.handleTopen(cx, msg, file)
	case styxproto.Tcreate:
		return s.handleTcreate(cx, msg, file)
	case styxproto.Tread:
		return s.handleTread(cx, msg, file)
	case styxproto.Twrite:
		return s.handleTwrite(cx, msg, file)
	case styxproto.Tremove:
		return s.handleTremove(cx, msg, file)
	case styxproto.Tstat:
		return s.handleTstat(cx, msg, file)
	case styxproto.Twstat:
		return s.handleTwstat(cx, msg, file)
	case styxproto.Tclunk:
		return s.handleTclunk(cx, msg, file)
	}
	// invalid messages should have been caught
	// in the conn.serve loop, so we should never
	// reach this point.
	panic(fmt.Errorf("unhandled message type %T", msg))
}
