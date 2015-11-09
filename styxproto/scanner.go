package styxproto

import (
	"bufio"
	"io"
	"strconv"
)

// Design goals of the parser:
//   - minimize allocations
//   - resilient to malicious input (invalid/overlarge sizes)
//   - streaming: a 4GB (max uint32) Twrite should not take 4G of memory

// NewScanner returns a Scanner that reads from the provided io.Reader.
// If non-nil, the provided buffer is used for storage of the parsed
// messages between calls to Next. If buf is nil, a new buffer is
// allocated of size DefaultBufSize. Passing a buffer with a length
// of less than MinBufSize bytes will cause a run-time panic.
func NewScanner(r *bufio.Reader, buf []byte) *Scanner {
	if buf == nil {
		buf = make([]byte, DefaultBufSize)
	} else if len(buf) < MinBufSize {
		panic("Non-nil buffer passed to NewScanner must be more than " +
			strconv.Itoa(MinBufSize) + " bytes long")
	}
	// We must be able to peek at the first 7 bytes of each message,
	// to know what type of message it is.
	const minPeekSize = minMsgSize
	return &Scanner{
		r:   bufio.NewReaderSize(r, minPeekSize),
		buf: buf,
	}
}

// A Scanner provides an interface for reading a stream of 9P
// messages from an io.Reader. Successive calls to the Next
// method of a Scanner will fetch and validate 9P messages
// from the input stream, until EOF is encountered, or another
// error is encountered.
//
// A Scanner is not safe for concurrent use. Usage of any Scanner
// method should be delegated to a single thread of execution or
// protected by a mutex.
type Scanner struct {
	// Input source
	r *bufio.Reader

	// Buffer for incoming messages
	buf []byte

	// Last fetched messages.
	msg []Msg

	// Last error encountered when reading from r
	// or during parsing
	err error
}

// Err returns the first error encountered during parsing.
// If the underyling io.Reader was closed in the middle of
// a message, Err will return io.ErrUnexpectedEOF. Otherwise,
// io.EOF is not considered to be an error, and is not relayed
// by Err.
func (s *Scanner) Err() error {
	if s.err == io.EOF {
		return nil
	}
	return s.err
}

// Msgs returns the 9P messages fetched from the last
// call to Next. The returned messages are only valid until
// the next call to the Scanner's Next method. All Twrite
// and Rread messages must be closed before the next
// call to Next.
func (s *Scanner) Msgs() []Msg {
	return s.msg
}

// Next fetches the next 9P messages from the Scanner's underlying
// io.Reader. If an error is encountered, either with the underlying
// IO, Next will return false, and the Scanner's Err method will return
// the first error encountered.
//
// If Next returns true, at least one 9P message will be returned from
// the next call to the Msgs method of the Scanner.
func (s *Scanner) Next() bool {
	if s.err != nil {
		return false
	}

	s.msg, s.err = ReadMsg(s.r, s.buf, s.msg)
	if s.err != nil {
		return false
	}

	return true
}
