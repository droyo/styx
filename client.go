package styx

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/styxproto"
)

// DefaultClient is the Client used by top-level functions such
// as Open.
var DefaultClient = &Client{}

// A Client is a 9P client, used to make remote requests to
// a 9P server. The zero value of a Client is a usable 9P client
// that uses default settings chosen by the styx package.
type Client struct {
	// The maximum size of a single 9P message. When working with
	// very large files, a larger MessageSize can reduce protocol
	// overhead. Because a remote server may choose to set a smaller
	// maximum size, increasing MessageSize may have no effect
	// with certain servers.
	MaxSize uint32
	// Timeout specifies the amount of time to wait for a response
	// from the server. Note that Timeout does not apply to Read
	// requests, to avoid interfering with long-poll or message
	// queue-like interfaces, where a client issues a Read request
	// for data that has not arrived yet. If zero, defaults to infinity.
	Timeout time.Duration
}

// Types that implement the Node interface can be returned by a Handler
// when a client performs an operation on a file.
type Node interface {
	io.ReadWriteCloser

	// Stat returns metadata information about a file. The Sys() method
	// returns the styxproto.Stat structure sent by the 9P server. It
	// should not be modified or used after the file is closed. Calling
	// Stat on a file requires that the connected user has permissions to
	// read the directory.
	Stat() (os.FileInfo, error)

	// Readdir reads the contents of the directory associated with node
	// and returns a slice of up to n (if n > 0) os.FileInfo values, in
	// the order returned by the remote server. If there are >n entries
	// in a directory, subsequent calls to Readdir will pick up where
	// previous call left off.
	//
	// If n <= 0, Readdir will return an os.FileInfo value for all entries
	// in the directory. If an error is encountered before reading the
	// entire directory, it is returned, along with the entries read
	// so far. If n > 0 and there are no entries in the directory, the
	// error is io.EOF.
	Readdir(n int) ([]os.FileInfo, error)
}

type FileSystem interface {
	// Open readies a file relative to the directory represented by
	// the Node for I/O.
	Open9P(req *Request, name string, flag int) (Node, error)

	// Create creates a new file relative to this node, with type
	// and permissions specified by mode, and opens it with the
	// mode specified by flag.
	Create9P(req *Request, name string, flag int, mode Mode) (Node, error)
}

// A Request contains contextual information about a
// 9P request.
type Request struct {
	context.Context
}

// A Mode contains permission and type information for a file.
type Mode uint32

// IsDir returns true if m describes a directory.
func (m Mode) IsDir() bool {
	return m&styxproto.DMDIR != 0
}

// IsRegular reports whether m describes a regular file.
func (m Mode) IsRegular() bool {
	return m&styxproto.DMTYPE == 0
}

type File struct {
	node Node
}

// ReadFile reads all data from the file on the remote 9P server
// specified by url. ReadFile is convenient if a single small file
// needs to be accessed infrequently.
func ReadFile(url string) ([]byte, error) {
	return nil, errors.New("todo")
}

// OpenFile opens a file on a remote 9P server with the specified
// mode.
func OpenFile(url string, flag int, mode uint32) (*File, error) {
	return nil, errors.New("todo")
}
