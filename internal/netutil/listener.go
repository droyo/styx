// Package netutil contains useful types for testing network
// services.
package netutil

import (
	"errors"
	"net"
	"sync"
)

var (
	errClosed = errors.New("listener closed")
)

// PipeListener is a net.Listener that does not need permission to
// bind to a port or create a socket file. Useful for testing in heavily
// sandboxed environments or intra-process communication.
type PipeListener struct {
	once     sync.Once
	incoming chan net.Conn
	shutdown chan struct{}
}

func (l *PipeListener) init() {
	l.once.Do(func() {
		l.incoming = make(chan net.Conn)
		l.shutdown = make(chan struct{})
	})
}

// Accept accepts a new connection on a PipeListener.
// Accept blocks until a new connection is made or the
// PipeListener is closed.
func (l *PipeListener) Accept() (net.Conn, error) {
	l.init()
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.shutdown:
		return nil, errClosed
	}
}

func (l *PipeListener) Dial() (net.Conn, error) {
	l.init()
	x, y := net.Pipe()
	select {
	case <-l.shutdown:
		x.Close()
		y.Close()
		return nil, errClosed
	case l.incoming <- x:
		return y, nil
	}
}

// Close closes a PipeListener. The returned error will always
// be nil.
func (l *PipeListener) Close() error {
	l.init()
	select {
	case <-l.shutdown:
		// avoiding a panic on double close here
	default:
		close(l.shutdown)
	}
	return nil
}

type dummyAddress struct{}

func (dummyAddress) String() string  { return "" }
func (dummyAddress) Network() string { return "" }

func (l *PipeListener) Addr() net.Addr {
	l.init()
	return dummyAddress{}
}
