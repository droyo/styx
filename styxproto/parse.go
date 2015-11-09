package styxproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"unicode/utf8"

	"aqwari.net/net/styx"
)

var (
	errShortRead = errors.New("not enough data in buffer to complete message")
)

// Shorthand for parsing numbers
var (
	guint16 = binary.LittleEndian.Uint16
	guint32 = binary.LittleEndian.Uint32
	guint64 = binary.LittleEndian.Uint64
)

type closer struct {
	io.Reader
}

func (r closer) Close() error {
	_, err := io.Copy(ioutil.Discard, r)
	return err
}

var msgParseLUT = [...]func(msg, *bufio.Reader) (Msg, error){
	msgTversion: parseTversion,
	msgRversion: parseRversion,
	msgTauth:    parseTauth,
	msgRauth:    parseRauth,
	msgTattach:  parseTattach,
	msgRattach:  parseRattach,
	msgRerror:   parseRerror,
	msgTflush:   parseTflush,
	msgRflush:   parseRflush,
	msgTwalk:    parseTwalk,
	msgRwalk:    parseRwalk,
	msgTopen:    parseTopen,
	msgRopen:    parseRopen,
	msgTcreate:  parseTcreate,
	msgRcreate:  parseRcreate,
	msgTread:    parseTread,
	msgRread:    parseRread,
	msgTwrite:   parseTwrite,
	msgRwrite:   parseRwrite,
	msgTclunk:   parseTclunk,
	msgRclunk:   parseRclunk,
	msgTremove:  parseTremove,
	msgRremove:  parseRremove,
	msgTstat:    parseTstat,
	msgRstat:    parseRstat,
	msgTwstat:   parseTwstat,
	msgRwstat:   parseRwstat,
}

func validMsgType(m uint8) bool {
	return int(m) < len(msgParseLUT) && msgParseLUT[m] != nil
}

func fixedSize(m uint8) bool {
	switch m {
	case msgTversion, msgRversion, msgTauth, msgTattach:
		fallthrough
	case msgRerror, msgTwalk, msgRwalk, msgTcreate:
		fallthrough
	case msgRread, msgTwrite, msgRstat, msgTwstat:
		return false
	}
	return true
}

func verifyQid(qid []byte) error {
	switch styx.QidType(qid[0]) {
	case styx.QTDIR, styx.QTAPPEND, styx.QTEXCL, styx.QTMOUNT, styx.QTAUTH, styx.QTTMP, styx.QTFILE:
		return nil
	}
	return errInvalidQidType
}

// check that a message is as big or as small as
// it needs to be, given what we know about its
// type.
func verifySize(m msg) error {
	t, n := m.Type(), m.Len()
	if !validMsgType(t) {
		return errInvalidMsgType
	}
	if min := int64(minSizeLUT[t]); n < min {
		return errTooBig
	} else if fixedSize(t) && n > min {
		return errTooSmall
	}
	return nil
}

// Verify a string. Strings must be valid UTF8 sequences.
func verifyString(data []byte) error {
	if !utf8.Valid(data) {
		return errInvalidUTF8
	}
	return nil
}

// Verify the first variable-length field. If succesful, returns
// a nil error and the remaining data after the field.
// If fill is true, the field is expected to fill data, minus padding.
func verifyField(data []byte, fill bool, padding int) ([]byte, []byte, error) {
	size := int(guint16(data[:2]))
	if len(data) < size {
		return nil, nil, errOverSize
	} else if fill && size < len(data)-padding {
		return nil, nil, errUnderSize
	}
	return data[:size], data[size:], nil
}

// ReadMsg returns all valid 9P messages that can be retrieved in a
// single Read call on input. Callers must read all data in Twrite and
// Rread messages before the next call to Parse with the same bufio.Reader.
//
// The byte slice buf is used to store incoming messages, and must
// be greater than length MinBufSize. If buf is not large enough to
// store a message, Parse will return io.ErrShortBuffer. If not enough
// data is returned from a single read call, the error will be io.ErrShortRead.
//
// ReadMsg will return a non-nil error if a fatal error was encountered
// during parsing, such as encountering io.EOF on input. For every
// invalid message read, an item is added to bad. If no fatal error is
// encountered, msg will contain the messages parsed, in the order
// encountered. If an invalid message is encountered, the item added
// to msg will be of type BadMessage.
func ReadMsg(input *bufio.Reader, buf []byte, msgbuf []Msg) ([]Msg, error) {
	var (
		err  error
		stop bool
	)

	result := msgbuf[:0]
	bufp := buf[:]

	for !stop {
		result, stop, bufp, err = readOneMsg(input, bufp, result)
	}
	if err == io.ErrShortBuffer && len(result) > 0 {
		err = nil
	} else if err == errShortRead && len(result) > 0 {
		err = nil
	}
	return result, err
}

// Read a single message and append it to result. Second return value is
// true if reading must stop due to a message that extends past the buffer,
// or a fatal error with the underlying Reader. Does not read additional data
// from r's internal reader unless necessary.
//
// If the error is nil, readOneMsg guarantees that a message has been added
// to result. Returns any remaining space in the buffer.
func readOneMsg(r *bufio.Reader, buf []byte, result []Msg) ([]Msg, bool, []byte, error) {
	// ReadMsg guarantees it will return at least one message.
	first := (len(result) == 0)

	if len(buf) < minMsgSize {
		return result, true, buf, io.ErrShortBuffer
	}

	if r.Buffered() < minMsgSize && !first {
		return result, true, buf, errShortRead
	}

	// Fill the buffer without emptying it
	for r.Buffered() < minMsgSize {
		if n, err := r.Read(buf[:1]); err != nil {
			return result, true, buf[n:], err
		}
		if err := r.UnreadByte(); err != nil {
			// This cannot occur if the Read error was nil
			panic("bufio.Reader.UnreadByte after succesful Read returned error")
		}
	}

	var (
		dot msg
		err error
	)
	dot, err = r.Peek(minMsgSize)
	if err != nil {
		panic("bufio.Reader.Peek() returned error but Buffered() >= minMsgSize")
	}

	if err := verifySize(dot); err != nil {
		return skipMessage(result, err, buf, r, dot, first)
	}

	var (
		final = false
		size  = dot.Len() + 4 // +4 for the 4 bytes of the size uint32
		t     = dot.Type()
	)

	if t == msgTwrite || t == msgRread {
		// These messages are a special case, because they
		// can very frequently be larger than our buffer. Rather
		// than load the up to 4GB (max allowed by 9P), the io.Reader
		// is passed to the client.
		if int64(r.Buffered()) < dot.Len() {
			// Stop parsing when we find a Twrite/Rread
			// that extends past the buffer. This guarantees
			// that at most one message will Read directly
			// from the underlying Reader, letting us tell
			// users that all Twrite/Tread messages returned
			// by ReadMsg can be read and closed in any
			// order, as long as they are all closed before the
			// next call to ReadMsg.
			final = true
			if t == msgTwrite {
				size = 23
			} else {
				size = 11
			}
		}
	}

	if int64(len(buf)) < size {
		return result, true, buf, io.ErrShortBuffer
	}
	data := buf[:size]

	if int64(r.Buffered()) < size {
		if first {
			if n, err := io.ReadFull(r, data); err != nil {
				return result, true, buf[n:], err
			}
		} else {
			return result, true, buf, errShortRead
		}
	} else if n, err := r.Read(data); int64(n) != size {
		panic("short read of Buffered data")
	} else if err != nil {
		panic(err)
	}

	msg, err := msgParseLUT[t](data, r)

	// Nothing left to read, all that's possible are parsing errors
	if err != nil {
		return skipMessage(result, err, buf, r, data, first)
	} else {
		result = append(result, msg)
	}

	return result, final, buf[len(data):], nil
}

// Skip an invalid message. If wait is true, or r wholly contains the message in
// its buffer, a BadMessage is appended to result, and r is fast forwarded
// past the end of the message. Otherwise, no action is taken.
func skipMessage(result []Msg, err error, buf []byte, r *bufio.Reader, dot msg, wait bool) ([]Msg, bool, []byte, error) {
	// Discard only takes an int, we've got an int64 (converted from a uint32)
	const maxInt32 = 1<<31 - 1

	msgInBuffer := int64(r.Buffered()) >= dot.Len()+4
	if wait || msgInBuffer {
		result = append(result, BadMessage{Err: err, tag: dot.Tag()})
		for x := dot.Len() + 4; x > 0; x -= maxInt32 {
			n := maxInt32
			if x < maxInt32 {
				n = int(x)
			}
			if _, err := r.Discard(n); err != nil {
				return result, true, buf, err
			}
		}
		return result, !msgInBuffer, buf, nil
	}
	return result, true, buf, nil
}

func parseTversion(dot msg, _ *bufio.Reader) (Msg, error) {
	if ver, _, err := verifyField(dot.Body()[4:], true, 0); err != nil {
		return nil, err
	} else if err := verifyString(ver); err != nil {
		return nil, err
	} else if len(ver) > MaxVersionLen {
		return nil, errLongVersion
	}
	return Tversion(dot), nil
}

func parseRversion(dot msg, _ *bufio.Reader) (Msg, error) {
	_, err := parseTversion(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rversion(dot), nil
}

func parseTauth(dot msg, _ *bufio.Reader) (Msg, error) {
	if err := parseTauthBody(dot.Body()); err != nil {
		return nil, err
	}
	return Tauth(dot), nil
}

func parseTauthBody(body []byte) error {
	if uname, _, err := verifyField(body[4:], false, 2); err != nil {
		return err
	} else if err := verifyString(uname); err != nil {
		return err
	} else if len(uname) > MaxUidLen {
		return errLongUsername
	} else if aname, _, err := verifyField(uname, true, 0); err != nil {
		return err
	} else if err := verifyString(aname); err != nil {
		return err
	} else if len(aname) > MaxAttachLen {
		return errLongAname
	}
	return nil
}

func parseRauth(dot msg, _ *bufio.Reader) (Msg, error) {
	if err := verifyQid(dot.Body()); err != nil {
		return nil, err
	}
	return Rauth(dot), nil
}

func parseTattach(dot msg, _ *bufio.Reader) (Msg, error) {
	if err := parseTauthBody(dot.Body()[4:]); err != nil {
		return nil, err
	}
	return Tattach(dot), nil
}

func parseRattach(dot msg, _ *bufio.Reader) (Msg, error) {
	_, err := parseRauth(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rattach(dot), nil
}

func parseRerror(dot msg, _ *bufio.Reader) (Msg, error) {
	if str, _, err := verifyField(dot.Body(), true, 0); err != nil {
		return nil, err
	} else if err := verifyString(str); err != nil {
		return nil, err
	} else if len(str) > MaxErrorLen {
		return nil, errLongError
	}
	return Rerror(dot), nil
}

func parseTflush(dot msg, _ *bufio.Reader) (Msg, error) {
	return Tflush(dot), nil
}

func parseRflush(dot msg, _ *bufio.Reader) (Msg, error) {
	return Rflush(dot), nil
}

func parseTwalk(dot msg, _ *bufio.Reader) (Msg, error) {
	// size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
	var (
		err       error
		el, elems []byte // first, rest in *wname
	)
	nwelem := guint16(dot.Body()[8:])
	if nwelem > MaxWElem {
		return nil, errMaxWElem
	}
	if dot.Len() < int64(nwelem)*2 {
		return nil, errOverSize
	}
	elems = dot.Body()[10:]
	for i := uint16(0); i < nwelem; i++ {
		last := (i == nwelem-1)
		el, elems, err = verifyField(elems, last, (int(nwelem)*2)-(int(i)*2))
		if err != nil {
			return nil, err
		} else if err := verifyString(el); err != nil {
			return nil, err
		} else if len(el) > MaxFilenameLen {
			return nil, errLongFilename
		}
	}
	return Twalk(dot), nil
}

func parseRwalk(dot msg, _ *bufio.Reader) (Msg, error) {
	nwqid := guint16(dot.Body()[:2])
	if nwqid > MaxWElem {
		return nil, errMaxWElem
	}

	if sz, real := dot.Len(), int64(nwqid)*13; real < sz {
		return nil, errUnderSize
	} else if real > sz {
		return nil, errOverSize
	}

	for i := uint16(0); i < nwqid; i++ {
		if err := verifyQid(dot.Body()[i*13 : (i+1)*13]); err != nil {
			return nil, err
		}
	}
	return Rwalk(dot), nil
}

func parseTopen(dot msg, _ *bufio.Reader) (Msg, error) {
	return Topen(dot), nil
}

func parseRopen(dot msg, _ *bufio.Reader) (Msg, error) {
	if err := verifyQid(dot.Body()[:13]); err != nil {
		return nil, err
	}
	return Ropen(dot), nil
}

func parseTcreate(dot msg, _ *bufio.Reader) (Msg, error) {
	if name, _, err := verifyField(dot.Body()[4:], true, 5); err != nil {
		return nil, err
	} else if err := verifyString(name); err != nil {
		return nil, err
	} else if len(name) > MaxFilenameLen {
		return nil, errLongFilename
	}
	return Tcreate(dot), nil
}

func parseRcreate(dot msg, _ *bufio.Reader) (Msg, error) {
	_, err := parseRopen(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rcreate(dot), nil
}

func parseTread(dot msg, _ *bufio.Reader) (Msg, error) {
	// size[4] Tread tag[2] fid[4] offset[8] count[4]
	return Tread(dot), nil
}

func parseRread(dot msg, r *bufio.Reader) (Msg, error) {
	// size[4] Rread tag[2] count[4] data[count]
	count := int64(guint32(dot.Body()[:4]))
	msgSize := dot.Len() + 4

	realSize := count + 11
	if realSize < msgSize {
		return nil, errUnderSize
	} else if realSize > msgSize {
		return nil, errOverSize
	}

	if int64(len(dot)) == msgSize {
		return Rread{
			ReadCloser: closer{bytes.NewReader(dot[11:])},
			msg:        dot,
		}, nil
	}
	return Rread{
		ReadCloser: closer{io.LimitReader(r, count)},
		msg:        dot,
	}, nil
}

func parseTwrite(dot msg, input *bufio.Reader) (Msg, error) {
	// size[4] Twrite tag[2] fid[4] offset[8] count[4]  data[count]
	offset := guint64(dot.Body()[4:12])
	if offset > MaxOffset {
		return nil, errMaxOffset
	}

	count := int64(guint32(dot.Body()[12:16]))
	msgSize := dot.Len()

	realSize := count + 23
	if realSize < msgSize {
		return nil, errUnderSize
	}
	if realSize > msgSize {
		return nil, errOverSize
	}

	if int64(len(dot)) == msgSize {
		return Twrite{
			ReadCloser: closer{bytes.NewReader(dot[11:])},
			msg:        dot,
		}, nil
	}
	return Twrite{
		ReadCloser: closer{io.LimitReader(input, count)},
		msg:        dot,
	}, nil
}

func parseRwrite(dot msg, _ *bufio.Reader) (Msg, error) {
	return Rwrite(dot), nil
}

func parseTclunk(dot msg, _ *bufio.Reader) (Msg, error) {
	return Tclunk(dot), nil
}

func parseRclunk(dot msg, _ *bufio.Reader) (Msg, error) {
	return Rclunk(dot), nil
}

func parseTremove(dot msg, _ *bufio.Reader) (Msg, error) {
	return Tremove(dot), nil
}

func parseRremove(dot msg, _ *bufio.Reader) (Msg, error) {
	return Rremove(dot), nil
}

func parseTstat(dot msg, _ *bufio.Reader) (Msg, error) {
	return Tstat(dot), nil
}

func parseRstat(dot msg, _ *bufio.Reader) (Msg, error) {
	stat, _, err := verifyField(dot.Body(), true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Rstat(dot), nil
}

func parseTwstat(dot msg, _ *bufio.Reader) (Msg, error) {
	stat, _, err := verifyField(dot.Body(), true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Twstat(dot), nil
}

func parseRwstat(dot msg, _ *bufio.Reader) (Msg, error) {
	return Rwstat(dot), nil
}
