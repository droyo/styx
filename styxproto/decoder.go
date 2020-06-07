package styxproto

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
)

var (
	errFillOverflow = errors.New("cannot fill buffer past maxInt")
)

// Design goals of the parser:
//   - minimize allocations
//   - resilient to malicious input (invalid/overlarge sizes)
//   - streaming: a 4GB (max uint32) Twrite should not take 4G of memory

// NewDecoder returns a Decoder with an internal buffer of size
// DefaultBufSize.
func NewDecoder(r io.Reader) *Decoder {
	return NewDecoderSize(r, DefaultBufSize)
}

// NewDecoderSize returns a Decoder with an internal buffer of size
// max(MinBufSize, bufsize) bytes. A Decoder with a larger buffer can
// provide more 9P messages at once, if they are available. This may
// improve performance on connections that are heavily multiplexed,
// where there messages from independent sessions that can be handled
// in any order.
func NewDecoderSize(r io.Reader, bufsize int) *Decoder {
	if bufsize < MinBufSize {
		bufsize = MinBufSize
	}
	return &Decoder{r: r, br: bufio.NewReaderSize(r, bufsize), MaxSize: -1}
}

// A Decoder provides an interface for reading a stream of 9P
// messages from an io.Reader. Successive calls to the Next
// method of a Decoder will fetch and validate 9P messages
// from the input stream, until EOF is encountered, or another
// error is encountered.
//
// A Decoder is not safe for concurrent use. Usage of any Decoder
// method should be delegated to a single thread of execution or
// protected by a mutex.
type Decoder struct {
	// MaxSize is the maximum size message that a Decoder will accept. If
	// MaxSize is -1, a Decoder will accept any size message.
	MaxSize int64

	// input source. we need to expose this so we can stitch together
	// an io.Reader for large Twrite/Rread messages.
	r io.Reader

	// internal buffer is used to store messages
	br *bufio.Reader

	// current selection in the buffered data
	start, pos int

	// Last fetched message. slices on br's internal buffer, so
	// only valid until next call to br.Read
	msg Msg

	// Last error encountered when reading from r
	// or during parsing
	err error
}

// Reset resets a Decoder with a new io.Reader.
func (s *Decoder) Reset(r io.Reader) {
	s.MaxSize = -1
	s.r = r
	s.br.Reset(s.r)
	s.start = 0
	s.pos = 0
	s.msg = nil
	s.err = nil
}

// Err returns the first error encountered during parsing.
// If the underyling io.Reader was closed in the middle of
// a message, Err will return io.ErrUnexpectedEOF. Otherwise,
// io.EOF is not considered to be an error, and is not relayed
// by Err.
//
// Invalid messages are not considered errors, and are
// represented in the Messages slice as values of type BadMessage.
// Only problems with the underlying io.Reader are
// considered errors.
func (s *Decoder) Err() error {
	if s.err == io.EOF {
		return nil
	}
	return s.err
}

// Msg returns the last 9P message decoded in the stream. It
// returns a non-nil message if and only if the last call to the
// Decoder's Next method returned true. The return value of
// Msg is only valid until the next call to a decoder's Next method.
func (s *Decoder) Msg() Msg {
	return s.msg
}

// Next fetches the next 9P message from the Decoder's underlying
// io.Reader. If an error is encountered reading from the underlying
// stream, Next will return false, and the Decoder's Err method will return
// the first error encountered.
//
// If Next returns true, the Msg method of the Decoder will return the
// decoded 9P message.
func (s *Decoder) Next() bool {
	if s.msg != nil {
		// Exhaust any Rread/Twrite messages to move the stream to the
		// next message boundary.
		if r, ok := s.msg.(io.Reader); ok {
			_, s.err = io.Copy(ioutil.Discard, r)
		}
		s.err = discard(s.br, s.msg.nbytes())
		s.msg = nil
	}
	if s.err != nil {
		s.msg = nil
		return false
	}
	s.resetdot()
	s.msg, s.err = s.fetchMessage()
	return s.msg != nil
}

// A bufio.Reader is not just a way to smooth out I/O performance;
// it can also be used as a "sliding window" over a byte stream.
// If the terminology below seems odd, it is inspired by the sam
// text editor, where "dot" refers to the current text selection.
func (s *Decoder) dot() []byte {
	if s.pos > s.br.Buffered() {
		panic("decoder position out of bounds")
	}
	buf, err := s.br.Peek(s.pos)
	if err != nil {
		panic(err) // this should never happen, it's buffered
	}
	return buf[s.start:]
}

func (s *Decoder) resetdot() {
	s.start, s.pos = 0, 0
}

func (s *Decoder) advance(n int) {
	if s.buflen() < n {
		panic("advance decoder out of bounds")
	}
	s.pos += n
}

func (s *Decoder) shrinkdot(n int) {
	if s.dotlen() < n {
		panic("shrink dot out of bounds")
	}
	s.pos -= n
}

// advance start of dot to end of dot
func (s *Decoder) mark() {
	s.start = s.pos
}

// number of bytes buffered after dot
func (s *Decoder) buflen() int {
	return s.br.Buffered() - s.pos
}

func (s *Decoder) dotlen() int {
	return s.pos - s.start
}

// extends dot to be n bytes long, performing
// IO if necessary. returns dot
func (s *Decoder) growdot(n int) ([]byte, error) {
	if err := s.fill(n - s.dotlen()); err != nil {
		return nil, err
	}
	s.advance(n - s.dotlen())
	return s.dot(), nil
}

// guarantees that s.buflen() >= n if error is nil
func (s *Decoder) fill(n int) error {
	if maxInt-n < s.pos {
		return errFillOverflow
	}
	_, err := s.br.Peek(s.pos + n)
	return err
}

func discard(r *bufio.Reader, n int64) error {
	_, err := io.CopyN(ioutil.Discard, r, n)
	return err
}
