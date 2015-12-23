package styx

import (
	"errors"
	"io"
	"os"
	"time"
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

// A File is an open file in a file tree served by a 9P server.
type File struct{}

// Name returns the name of a file. The name does not include
// the containing directory.
func (f *File) Name() string {
	return "TODO"
}

// Stat returns metadata information about a file. The Sys() method
// returns the styxproto.Stat structure sent by the 9P server. It
// should not be modified or used after the file is closed. Calling
// Stat on a file requires that the connected user has permissions to
// read the directory.
func (f *File) Stat() (os.FileInfo, error) {
	return nil, errors.New("TODO")
}

// OpenFile opens a file under a directory, creating it if it does not
// exist, with permissions and mode bits set according to mode. The
// returned file will be opened with the mode flags set in the flag
// parameter.  OpenFile is a generalized open call; most users will
// use Open, Create, or Mkdir instead.
func (f *File) OpenFile(name string, flag int, mode uint32) (*File, error) {
	return nil, errors.New("TODO")
}

// CreateFile can be used to avoid the race condition present in
// the Create method regarding existing files. If mode has the
// DMEXCL bit set, CreateFile will return an error immediately if
// the file cannot be created due to another file existing with the
// same name.
func (f *File) CreateFile(name string, flag int, mode uint32) (*File, error) {
	return nil, errors.New("TODO")
}

// Create creates a new regular file with permissions 0666 in the
// directory represented by the File, and opens it with the mode
// specified by flag. If the create fails because the file already
// exists, the existing file is opened and truncated, and no error
// is returned.
func (f *File) Create(name string) (*File, error) {
	return nil, errors.New("TODO")
}

// Readdir reads the contents of the directory associated with file
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
func (f *File) Readdir(n int) ([]os.FileInfo, error) {
	return nil, errors.New("TODO")
}

// Read reads up to len(p) bytes from the File. It returns the number
// of bytes read and an error, if any. If less than len(p) bytes are
// read due to the end-of-file being reached, the next call to Read
// will return 0, io.EOF.
func (f *File) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// Read reads len(p) bytes from the file starting at offset bytes.
// It returns the number of bytes read, and an error, if any. If
// n < len(p), error will be non-nil.
func (f *File) ReadAt(p []byte, offset int64) (n int, err error) {
	return 0, io.EOF
}

// Write writes len(b) bytes to the File. It returns the number of
// bytes written and an error, if any. If less than len(b) bytes are
// written, err will be non-nil.
func (f *File) Write(b []byte) (int, error) {
	return 0, io.EOF
}

// WriteAt writes len(b) bytes to the File, starting at offset. It returns
// the number of bytes written and an error, if any. The error will
// always be non-nil when less than len(b) bytes are written.
func (f *File) WriteAt(b []byte, offset int64) (int, error) {
	return 0, io.EOF
}

// Close closes the file. After Close returns, the file can no longer
// be used. It returns any errors encountered communicating with
// the remote server.
func (f *File) Close() error {
	return errors.New("TODO")
}

// Open readies a file on a remote 9P server for reading.  Open uses
// the default Client to attach to the remote 9P server specified by
// url, walks to the file specified by the path section of the url,
// and opens it for reading. The connection to the remote server
// is kept open until the file is fully read or closed.
func Open(url string) (*File, error) {
	return nil, errors.New("todo")
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
