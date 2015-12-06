package styx

import (
	"bufio"
	"errors"
	"io"
	"sync"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/styxproto"
)

// A Conn represents the server-side of a 9P connection.
// Multiple sessions may be multiplexed over a single
// connection.
type conn struct {
	*styxproto.Decoder
	*styxproto.Encoder
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

func (c *conn) channel() channel {
	return channel{c: c}
}

// A Channel is a bidirectional communication channel between
// the server and client, that is implemented using read/write
// operations.
type channel struct {
	rw io.ReadWriter
	c  *conn
}

// Read reads any Twrite messages incoming from the client.
func (ch channel) Read(p []byte) (int, error) {
	return 0, errors.New("todo")
}

// Write sends Rread responses to the client.
func (ch channel) Write(p []byte) (int, error) {
	return 0, errors.New("todo")
}

// Transport returns the underlying connection.
func (ch channel) Transport() interface{} {
	return ch.c.rwc
}

// Conn returns the underlying connection used by a Conn.
// It can be accessed to implement transport-based authentication
// methods. The return value of Conn must never be read from,
// written to, or closed.
func (c *conn) conn() interface{} {
	return c.rwc
}

// getPending retrieves a CancelFunc for a pending operation.
// ok is true only if the cancelFunc could be retrieved.
func (c *conn) getPending(tag uint16) (cancel context.CancelFunc, ok bool) {
	c.pendingLock.RLock()
	cancel, ok = c.pending[tag]
	c.pendingLock.RUnlock()
	return cancel, ok
}

// getSession retrieves the session associated with fid. The returned
// session is non-nil only if the second return parameter is true.
func (c *conn) getSession(fid uint32) (*session, bool) {
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
	Afid() uint32
}

func (c *conn) newSession(msg attach) *session {
	s := &session{
		uname: string(msg.Uname()),
		aname: string(msg.Aname()),
		conn:  c,
	}
	fid := msg.Fid()

	c.sessionLock.Lock()
	c.session[fid] = s
	c.sessionLock.Unlock()

	if afid := msg.Afid(); afid != styxproto.NoFid {
		c.sessionLock.Lock()
		c.session[afid] = s
		c.sessionLock.Unlock()
	}

	return s
}

type connState int

const (
	stateNew    connState = iota // Tversion not received yet
	stateActive                  // Version negotiated, ready to serve requests
)

func newConn(rwc io.ReadWriteCloser, srv *Server) *conn {
	bw := newBufioWriter(rwc)
	return &conn{
		rwc:     rwc,
		srv:     srv,
		session: make(map[uint32]*session),
		bw:      bw,
		Decoder: newDecoder(rwc),
		Encoder: styxproto.NewEncoder(bw),
		qidbuf:  make([]byte, styxproto.QidLen*styxproto.MaxWElem),
		statbuf: make([]byte, 512),
	}
}

func (c *conn) close() error {
	putDecoder(c.Decoder)
	putBufioWriter(c.bw)
	return c.rwc.Close()
}
