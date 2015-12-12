package styxproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"sync"

	"golang.org/x/net/context"
)

var errTagInUse = errors.New("tag already in use")

// A Conn is a bidirectional connection that is capable of sending and
// receiving 9P messages.
type Conn struct {
	*Encoder
	*Decoder

	// The maximum 9P message size. During protocol negotiation,
	// the client sets the max size, and a server may set a lower
	// (but not higher) size that both sides must honor thereafter.
	MaxSize uint32

	// empty if version has not been negotiated yet
	version string

	bw  *bufio.Writer
	rwc io.ReadWriteCloser

	// transactions that have not completed yet
	mu          sync.RWMutex
	transaction map[uint16]context.CancelFunc
}

func (c *Conn) close() {
	c.bw.Flush()
	c.rwc.Close()
}

// A ResponseWriter is used to send responses for a single request.
// The embedded Context can be used to receive cancellation signals,
// either due to a Tflush request by a Client, or some other deadline.
type ResponseWriter struct {
	*Encoder
	tag     uint16
	conn    *Conn
	pending bool
	context.Context
}

// A ResponseWriter must be closed to signify that a transaction
// is completed.
func (w *ResponseWriter) Close() {
	w.conn.mu.Lock()
	delete(w.conn.transaction, w.tag)
	w.conn.mu.Unlock()
}

func (c *Conn) pending(tag uint16) (context.CancelFunc, bool) {
	c.mu.RLock()
	cancel, ok := c.transaction[tag]
	c.mu.RUnlock()
	return cancel, ok
}

// returns an error if the tag is already in use for another
// transaction.
func (c *Conn) newResponseWriter(m Msg, cx context.Context) (*ResponseWriter, error) {
	tag := m.Tag()
	cx, cancel := context.WithCancel(cx)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.transaction[tag]; ok {
		return nil, errTagInUse
	} else {
		c.transaction[tag] = cancel
	}
	return &ResponseWriter{
		Encoder: c.Encoder,
		Context: cx,
		conn:    c,
		tag:     tag,
	}, nil
}

// NewConn creates a new Conn from the given io.ReadWriteCloser. A
// Conn performs its own buffering for reads and writes. If msize is
// negative, the maximum 9P message size is set to DefaultMaxSize.
func NewConn(rwc io.ReadWriteCloser, msize int64) *Conn {
	if msize > math.MaxUint32 {
		msize = math.MaxUint32
	}
	if msize < MinBufSize {
		msize = MinBufSize
	}
	if msize < 0 {
		msize = DefaultMaxSize
	}

	bw := bufio.NewWriter(rwc)
	return &Conn{
		Encoder:     NewEncoder(bw),
		Decoder:     NewDecoderSize(rwc, MinBufSize),
		MaxSize:     uint32(msize),
		transaction: make(map[uint16]context.CancelFunc),
		bw:          bw,
		rwc:         rwc,
	}
}

// The Server interface is used by a Conn to service 9P requests. Each
// method in the Srv interface corresponds with a 9P transaction.  Each
// transaction is considered pending until the provided ResponseWriter
// is closed. Each method is called within the same goroutine as the
// Serve function; parsing of further messages will be blocked until the
// method returns. For long-running requests, a method should spawn
// a goroutine to complete the transaction. All requests are subject to
// cancellation by a subsequent Tflush request, or any other deadlines
// set by the Context passed to the Serve function.
type Server interface {
	Attach(*ResponseWriter, Tattach)
	Auth(*ResponseWriter, Tauth)
	Clunk(*ResponseWriter, Tclunk)
	Create(*ResponseWriter, Tcreate)
	Open(*ResponseWriter, Topen)
	Read(*ResponseWriter, Tread)
	Remove(*ResponseWriter, Tremove)
	Stat(*ResponseWriter, Tstat)
	Walk(*ResponseWriter, Twalk)
	Write(*ResponseWriter, Twrite)
	Wstat(*ResponseWriter, Twstat)
}

func (c *Conn) serveMsg(m Msg, cx context.Context, srv Server) {
	if m, ok := m.(Tversion); ok && c.version == "" {
		msize := c.MaxSize
		if n := m.Msize(); n < int64(msize) {
			if n < MinBufSize {
				c.Rerror(m.Tag(), "msize %d too small", n)
				c.close()
				return
			}
			c.MaxSize = uint32(n)
		}
		if ver := m.Version(); bytes.HasPrefix(ver, []byte("9P2000")) {
			c.Rversion(c.MaxSize, "9P2000")
			c.version = "9P2000"
		} else {
			c.Rversion(c.MaxSize, "unknown")
		}
	} else if !ok && c.version == "" {
		c.Rerror(m.Tag(), "need Tversion")
		return
	}
	if m.Len() > int64(c.MaxSize) {
		c.Rerror(m.Tag(), "message exceeds msize")
		c.close()
		return
	}

	w, err := c.newResponseWriter(m, cx)
	if err != nil {
		c.Rerror(m.Tag(), "%s", err)
		return
	}
	switch m := m.(type) {
	case Tauth:
		srv.Auth(w, m)
	case Tattach:
		srv.Attach(w, m)
	case Twalk:
		srv.Walk(w, m)
	case Topen:
		srv.Open(w, m)
	case Tcreate:
		srv.Create(w, m)
	case Tread:
		srv.Read(w, m)
	case Twrite:
		srv.Write(w, m)
	case Tclunk:
		srv.Clunk(w, m)
	case Tremove:
		srv.Remove(w, m)
	case Tstat:
		srv.Stat(w, m)
	case Twstat:
		srv.Wstat(w, m)
	case Tflush:
		tag := m.Tag()
		if cancel, ok := c.pending(tag); ok {
			cancel()
		}
		c.Rflush(tag)
		w.Close()
	case BadMessage:
		c.Rerror(m.Tag(), "bad message: %s", m.Err)
		w.Close()
	default:
		c.Rerror(m.Tag(), "unexpected message type %T", m)
		w.Close()
	}
}

// Serve receives requests on c and serves them by calling the
// methods of srv. When calling methods on srv, the provided
// ResponseWriter will use a Context derived from cx.
func Serve(c *Conn, cx context.Context, srv Server) error {
	for c.Encoder.Err() == nil && c.Decoder.Next() {
		for _, m := range c.Messages() {
			c.serveMsg(m, cx, srv)
		}
		if err := c.bw.Flush(); err != nil {
			return err
		}
	}
	if c.Decoder.Err() != nil {
		return c.Decoder.Err()
	}
	if c.Encoder.Err() != nil {
		return c.Encoder.Err()
	}
	return nil
}
