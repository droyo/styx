package styx

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"aqwari.net/net/styx/styxproto"
	"aqwari.net/retry"
)

// Types implementing the Logger interface can receive
// diagnostic information during a server's operation.
// The Logger interface is implemented by *log.Logger.
type Logger interface {
	Printf(format string, v ...interface{})
}

type server struct {
	logger Logger
}

func (s *server) Logf(format string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(format, v...)
	}
}

type connState int

const (
	stateNew connState = iota
	stateActive
)

type conn struct {
	*styxproto.Decoder
	rwc      net.Conn
	srv      *server
	sessions map[uint32]*session
	fids     map[uint32]interface{}
	bw       *bufio.Writer
}

type session struct {
	user, group string
	conn        *conn
}

type file interface{}

func newConn(rwc net.Conn, srv *server) *conn {
	return &conn{
		rwc:      rwc,
		srv:      srv,
		sessions: make(map[uint32]*session),
		files:    make(map[uint32]file),
		bw:       newBufioWriter(rwc),
		Decoder:  newDecoder(rwc),
	}
}

func (c *conn) close() error {
	putDecoder(c.Decoder)
	return c.rwc.Close()
}

func (s *server) serve(l net.Listener) error {
	type tempErr interface {
		Temporary() bool
	}
	backoff := retry.Exponential(time.Millisecond).Max(time.Second)
	try := 0

	for {
		rwc, err := l.Accept()
		if err != nil {
			if err, ok := err.(tempErr); ok && err.Temporary() {
				try++
				s.logf("9p: Accept error: %v; retrying in %v", err, backoff(try))
				time.Sleep(backoff(try))
				continue
			}
			return err
		} else {
			try = 0
		}
		c := newConn(s, rwc)
		go c.serve()
	}
}

func (c *conn) serve() {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.srv.logf("9p: panic serving %v: %v\n%s", c.rwc.RemoteAddr(), err, buf)
		}
		c.close()
	}()
	var (
		Rerror   styxproto.WriteRerror
		Rversion styxproto.WriteRversion

		werr error
		w    = errWriter(c.bwc, &werr)
	)

Loop:
	for c.Next() {
		for _, msg := range c.Messages() {
			switch msg := msg.(type) {
			case styxproto.Tversion:
				if c.connState != stateNew {
					Rerror(w, msg.Tag(), "late Tversion message")
				}
				if !bytes.HasPrefix(msg.Version(), []byte("9P2000")) {
					Rerror(w, msg.Tag(), "invalid version %s", msg.Version())
				}
				Rversion(w, c.srv.Msize, "9P2000")
				c.connState = stateActive
			case styxproto.Tauth:
			case styxproto.Tattach:
			case styxproto.Tflush:
			case styxproto.Twalk:
			case styxproto.Topen:
			case styxproto.Tcreate:
			case styxproto.Tread:
			case styxproto.Twrite:
			case styxproto.Tclunk:
			case styxproto.Tremove:
			case styxproto.Tstat:
			case styxproto.Twstat:
			case styxproto.BadMessage:
				Rerror(w, msg.Tag(), "malformed message")
			default:
				name := fmt.Printf("%T", msg)
				name = name[strings.IndexByte(name, '.')+1:]
				Rerror(w, msg.Tag(), "unexpected message type %s", name)
			}
			if werr != nil {
				c.srv.logf("9p: error writing message: %v", err)
				break Loop
			}
		}
		if err := c.bw.Flush(); err != nil {
			c.srv.logf("9p: error flushing message buffer: %v", err)
			break
		}
	}
	if c.Err() != nil {
		c.srv.logf("9p: error parsing messages: %v", err)
	}
}
