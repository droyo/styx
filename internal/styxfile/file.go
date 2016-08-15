package styxfile

import (
	"errors"
	"fmt"
	"io"
)

// 9P read/write requests contain an offset. This makes them
// well-suited to the io.ReaderAt and io.WriterAt interfaces.
// However to keep our APIs flexible, we do the heavy lifting,
// accepting broader interfaces and forcing them into what we
// need.

// ErrNotSupported is returned when a given type does not
// implement the necessary functionality to complete a given
// read/write operation.
var ErrNotSupported = errors.New("not supported")

// Interface describes the methods a type must implement to
// be used as a file by a 9P file server. The New function converts
// types that implement some, but not all of these methods into
// types that do.
type Interface interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
}

type interfaceWithoutClose interface {
	io.ReaderAt
	io.WriterAt
}

type nopCloser struct {
	interfaceWithoutClose
}

func (nopCloser) Close() error { return nil }

// New creates a new Interface that reads and writes to and from
// rwc. The type of rwc determines the implementation selected
// by New; if rwc already implements Interface, it is used as-is. If
// some methods are missing, wrapper types are used to implement
// missing functionality. If the provided type cannot be adapted into
// an Interface, New returns a non-nil error.
func New(rwc interface{}) (Interface, error) {
	switch rwc := rwc.(type) {
	case Interface:
		return rwc, nil
	case interfaceWithoutClose:
		return nopCloser{rwc}, nil
	case io.Seeker:
		return &seekerAt{rwc: rwc}, nil
	case io.ReadWriter:
		return &dumbPipe{rwc: rwc}, nil
	case io.Reader:
		return &dumbPipe{rwc: rwc}, nil
	case io.Writer:
		return &dumbPipe{rwc: rwc}, nil
	}
	return nil, fmt.Errorf("Cannot convert type %T into a styxfile.Interface")
}
