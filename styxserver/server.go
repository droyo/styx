/*
Package styxserver implements a main loop for running a 9P server.

The styxserver.Serve function takes as an argument a type that
implements a callback for each type of 9P message available. It is
the value's responsibility to respond to each message appropriately,
and the Serve function will handle parsing of incoming messages,
flushing of outgoing messages, and other bookkeeping such as handling
cancellations via Tflush requests.
*/
package styxserver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"sync"

	"aqwari.net/net/styx/styxproto"

	"golang.org/x/net/context"
)

var errTagInUse = errors.New("tag already in use")

// A Conn is a bidirectional connection that is capable of sending and
// receiving 9P messages.
type Conn struct {
	*styxproto.Encoder
	*styxproto.Decoder

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
	*styxproto.Encoder
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

// Flush writes any pending data to the underlying io.Writer
func (w *ResponseWriter) Flush() error {
	return w.conn.bw.Flush()
}

func (c *Conn) pending(tag uint16) (context.CancelFunc, bool) {
	c.mu.RLock()
	cancel, ok := c.transaction[tag]
	c.mu.RUnlock()
	return cancel, ok
}

// returns an error if the tag is already in use for another
// transaction.
func (c *Conn) newResponseWriter(m styxproto.Msg, cx context.Context) (*ResponseWriter, error) {
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
	if msize < styxproto.MinBufSize {
		msize = styxproto.MinBufSize
	}
	if msize <= 0 {
		msize = styxproto.DefaultMaxSize
	}

	bw := bufio.NewWriter(rwc)
	return &Conn{
		Encoder:     styxproto.NewEncoder(bw),
		Decoder:     styxproto.NewDecoderSize(rwc, styxproto.MinBufSize),
		MaxSize:     uint32(msize),
		transaction: make(map[uint16]context.CancelFunc),
		bw:          bw,
		rwc:         rwc,
	}
}

// Types implementing Interface can be used by a Conn to service 9P
// requests. Each method corresponds with a 9P transaction.  Each
// transaction is considered pending until the provided ResponseWriter
// is closed. Each method is called within the same goroutine as the
// Serve function; parsing of further messages will be blocked until
// the method returns. For long-running requests, a method should spawn
// a goroutine to complete the transaction. All requests are subject
// to cancellation by a subsequent Tflush request, or any other deadlines
// set by the Context passed to the Serve function.
type Interface interface {
	Attach(*ResponseWriter, styxproto.Tattach)
	Auth(*ResponseWriter, styxproto.Tauth)
	Clunk(*ResponseWriter, styxproto.Tclunk)
	Create(*ResponseWriter, styxproto.Tcreate)
	Open(*ResponseWriter, styxproto.Topen)
	Read(*ResponseWriter, styxproto.Tread)
	Remove(*ResponseWriter, styxproto.Tremove)
	Stat(*ResponseWriter, styxproto.Tstat)
	Walk(*ResponseWriter, styxproto.Twalk)
	Write(*ResponseWriter, styxproto.Twrite)
	Wstat(*ResponseWriter, styxproto.Twstat)
}

func (c *Conn) serveMsg(m styxproto.Msg, cx context.Context, srv Interface) {
	if m, ok := m.(styxproto.Tversion); ok && c.version == "" {
		msize := c.MaxSize
		if n := m.Msize(); n < int64(msize) {
			if n < styxproto.MinBufSize {
				c.Rerror(m.Tag(), "msize %d too small", n)
				c.close()
				return
			}
			c.MaxSize = uint32(n)
		}
		if ver := m.Version(); bytes.HasPrefix(ver, []byte("9P2000")) {
			c.Rversion(c.MaxSize, "9P2000")
			c.version = "9P2000"
			return
		} else {
			c.Rversion(c.MaxSize, "unknown")
			return
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
	case styxproto.Tauth:
		srv.Auth(w, m)
	case styxproto.Tattach:
		srv.Attach(w, m)
	case styxproto.Twalk:
		srv.Walk(w, m)
	case styxproto.Topen:
		srv.Open(w, m)
	case styxproto.Tcreate:
		srv.Create(w, m)
	case styxproto.Tread:
		srv.Read(w, m)
	case styxproto.Twrite:
		srv.Write(w, m)
	case styxproto.Tclunk:
		srv.Clunk(w, m)
	case styxproto.Tremove:
		srv.Remove(w, m)
	case styxproto.Tstat:
		srv.Stat(w, m)
	case styxproto.Twstat:
		srv.Wstat(w, m)
	case styxproto.Tflush:
		tag := m.Tag()
		if cancel, ok := c.pending(m.Oldtag()); ok {
			cancel()
		}
		c.Rflush(tag)
		w.Close()
	case styxproto.BadMessage:
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
func Serve(c *Conn, cx context.Context, srv Interface) error {
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
