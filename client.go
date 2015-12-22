package styx

import (
	"errors"
	"io"
)

type File interface {
	io.Writer
	io.Reader
	io.Closer
}

// Open readies a file on a remote 9P server for reading.  Open uses
// the default Client to attach to the remote 9P server specified by
// url, walks to the file specified by the path section of the url,
// and opens it for reading. The connection to the remote server
// is kept open until the file is fully read or closed.
func Open(url string) (File, error) {
	return nil, errors.New("todo")
}

// ReadFile reads all data from the file on the remote 9P server
// specified by url. ReadFile is convenient if a single small file
// needs to be accessed infrequently.
func ReadFile(url string) ([]byte, error) {
	return nil, errors.New("todo")
}

type Mode uint32

// OpenFile opens a file on a remote 9P server with the specified
// mode.
func OpenFile(url string, mode Mode) (File, error) {
	return nil, errors.New("todo")
}
