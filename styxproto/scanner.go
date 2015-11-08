package styxproto

import (
	"io"
	"strconv"

	"aqwari.net/net/styx/styxproto/sliding"
)

// Design goals of the parser:
//   - minimize allocations
//   - resilient to malicious input (invalid/overlarge sizes)
//   - streaming: a 4GB (max uint32) Twrite should not take 4G of memory

// NewScanner returns a Scanner that reads from the provided
// io.Reader. If non-nil, the provided buffer is used for temporary
// storage during the parsing process. If buf is nil, a new buffer is
// allocated of size DefaultBufSize. Passing a buffer with a length of
// less than MinBufSize bytes will cause a run-time panic.
func NewScanner(r io.Reader, buf []byte) *Scanner {
	if buf == nil {
		buf = make([]byte, DefaultBufSize)
	} else if len(buf) < MinBufSize {
		panic("Non-nil buffer passed to NewScanner must be more than " +
			strconv.Itoa(MinBufSize) + " bytes long")
	}
	return &Scanner{
		input: &sliding.Window{B: buf, R: r},
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
	// Buffer for incoming messages
	input *sliding.Window

	// Last fetched message.
	msg Msg

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

// Msg returns the 9P message fetched from the last
// call to Next. The returned Msg is only valid until
// the next call to the Scanner's Next method.
//
// For Twrite and Rread messages, callers must read
// the entirety of the message body before calling
// Next.
func (s *Scanner) Msg() Msg {
	return s.msg
}

// Next fetches the next 9P message from the Scanner's
// underlying io.Reader. If an error is encountered, either
// with the underlying IO device or the 9P message itself,
// Next will return false, and the Scanner's Err method will
// return the first error encountered.
//
// If Next returns true, the fetched 9P message will be
// returned from the next call to the Msg method of the
// Scanner.
func (s *Scanner) Next() bool {
	if s.err != nil {
		return false
	}

	msg, err := parse(s.input)
	if err != nil {
		s.err = err
		return false
	}

	s.msg = msg
	return true
}
