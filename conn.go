package styx

import (
	"bufio"
	"io"
	"sync"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/styxproto"
)

// A Conn represents the server-side of a 9P connection.
// Multiple sessions may be multiplexed over a single
// connection.
type Conn struct {
	*styxproto.Decoder
	bw         *bufio.Writer
	rwc        io.ReadWriteCloser
	srv        *Server
	state      connState
	remoteAddr string

	qidbuf, statbuf []byte

	sessionLock sync.RWMutex // protects the following map
	session     map[uint32]*session

	pendingLock sync.RWMutex // protects the following map
	pending     map[uint16]context.CancelFunc
}

// Conn returns the underlying connection used by a Conn.
// It can be accessed to implement transport-based authentication
// methods. The return value of Conn must never be read from,
// written to, or closed.
func (c *Conn) Conn() interface{} {
	return c.rwc
}

// getPending retrieves a CancelFunc for a pending operation.
// ok is true only if the cancelFunc could be retrieved.
func (c *Conn) getPending(tag uint16) (cancel context.CancelFunc, ok bool) {
	c.pendingLock.RLock()
	cancel, ok = c.pending[tag]
	c.pendingLock.RUnlock()
	return cancel, ok
}

// getSession retrieves the session associated with fid. The returned
// session is non-nil only if the second return parameter is true.
func (c *Conn) getSession(fid uint32) (*session, bool) {
	c.sessionLock.RLock()
	s, ok := c.session[fid]
	c.sessionLock.RUnlock()
	return s, ok
}

type attach interface {
	styxproto.Msg
	Uname() []byte
	Aname() []byte
	Fid() uint32
}

func (c *Conn) newSession(msg attach) *session {
	s := &session{
		uname: string(msg.Uname()),
		aname: string(msg.Aname()),
		conn:  c,
	}
	fid := msg.Fid()
	c.sessionLock.Lock()
	c.session[fid] = s
	c.sessionLock.Unlock()
	return s
}

type connState int

const (
	stateNew    connState = iota // Tversion not received yet
	stateActive                  // Version negotiated, ready to serve requests
)

func newConn(rwc io.ReadWriteCloser, srv *Server) *Conn {
	return &Conn{
		rwc:     rwc,
		srv:     srv,
		session: make(map[uint32]*session),
		bw:      newBufioWriter(rwc),
		Decoder: newDecoder(rwc),
		qidbuf:  make([]byte, styxproto.QidLen*styxproto.MaxWElem),
		statbuf: make([]byte, 512),
	}
}

func (c *Conn) close() error {
	putDecoder(c.Decoder)
	putBufioWriter(c.bw)
	return c.rwc.Close()
}
