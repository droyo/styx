package styxproto

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"unicode/utf8"

	"aqwari.net/net/styx"
	"aqwari.net/net/styx/styxproto/sliding"
)

type parseError string

func (p parseError) Error() string { return string(p) }

var (
	errInvalidMsgType = parseError("invalid message type")
	errInvalidQidType = parseError("invalid type field in qid")
	errInvalidUTF8    = parseError("string is not valid utf8")
	errLongAname      = parseError("aname field too long")
	errLongError      = parseError("error message too long")
	errLongFilename   = parseError("file name too long")
	errLongSize       = parseError("size field is longer than actual message size")
	errLongStat       = parseError("stat structure too long")
	errLongUsername   = parseError("uid or gid name is too long")
	errLongVersion    = parseError("protocol version string too long")
	errMaxOffset      = parseError("Maximum offset exceeded")
	errMaxWElem       = parseError("maximum walk elements exceeded")
	errNullString     = parseError("NUL in string field")
	errOverSize       = parseError("size of field exceeds size of message")
	errShortSize      = parseError("size field is shorter than actual message size")
	errShortStat      = parseError("stat structure too short")
	errTooBig         = parseError("message is too long")
	errTooSmall       = parseError("message is too small")
	errUnderSize      = parseError("size of fields is less than size header value")
)

// Shorthand for parsing numbers
var (
	guint16 = binary.LittleEndian.Uint16
	guint32 = binary.LittleEndian.Uint32
	guint64 = binary.LittleEndian.Uint64
)

type parseFn func(*sliding.Window, msg) (Msg, error)

var msgParseLUT = [...]parseFn{
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

// Skip a bad message, so that we can continue to parse
// good messages.
func skipMessage(input *sliding.Window, dot msg, err error) error {
	length := dot.Len() - int64(len(dot))
	remaining := input.Reader(length)
	if _, err := io.CopyN(ioutil.Discard, remaining, length); err != nil {
		return err
	}
	input.Reset()
	return err
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

func verifyStat(data []byte) error {
	var field []byte

	// type[2] dev[4] qid[13] mod[4] atime[4] mtime[4] length[8] name[s] uid[s] gid[s] muid[s]
	if len(data) < minStatLen {
		return errShortStat
	} else if len(data) > maxStatLen {
		return errLongStat
	}
	if err := verifyQid(data[6:19]); err != nil {
		return err
	}
	name, rest, err := verifyField(data[39:], false, 6)
	if err != nil {
		return err
	} else if err := verifyString(name); err != nil {
		return err
	} else if len(name) > MaxFilenameLen {
		return errLongFilename
	}

	for i := 0; i < 3; i++ {
		field, rest, err = verifyField(rest, i == 2, 4-i*2)
		if err != nil {
			return err
		} else if err := verifyString(field); err != nil {
			return err
		} else if len(field) > MaxUidLen {
			return errLongUsername
		}
	}
	return nil
}

func verifyQid(qid []byte) error {
	switch styx.QidType(qid[0]) {
	case styx.QTDIR, styx.QTAPPEND, styx.QTEXCL, styx.QTMOUNT, styx.QTAUTH, styx.QTTMP, styx.QTFILE:
		return nil
	}
	return errInvalidQidType
}

func verifySize(mtype uint8, n int64) error {
	if !validMsgType(mtype) {
		return errInvalidMsgType
	}
	if min := int64(minSizeLUT[mtype]); n < min {
		return errTooBig
	} else if fixedSize(mtype) && n > min {
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
// a nil error and the remainder data with the field removed.
// If fill is true, the field is expected to fill data, minus padding.
func verifyField(data []byte, fill bool, padding int) ([]byte, []byte, error) {
	size := int(guint16(data[:2]))
	if len(data) < size {
		return nil, nil, errOverSized
	} else if fill && size < len(data)-padding {
		return nil, nil, errUnderSized
	}
	return data[:size], data[size:], nil
}

// parse reads the first 9P message from input, along with any errors
// encountered. parse expects the length of the input window to be
// 0. Repeated calls to parse on the same input window will return
// new messages, even if a non-fatal parse error is encountered due
// to an improperly-formed message.
func parse(input *sliding.Window) (Msg, error) {
	var (
		dot msg
		err error
	)

	if input.Len() != 0 {
		panic("Unknown state; previous parse did not complete")
	}

	dot, err = input.Fetch(minMsgSize)
	if err != nil {
		return nil, err
	}

	if err := verifySize(dot.Type(), dot.Len()); err != nil {
		return nil, skipMessage(input, dot, err)
	}

	// Except for Twrite and Rread requests, read the
	// whole message into memory.
	switch dot.Type() {
	case msgTwrite:
		dot, err = input.Fetch(16)
	case msgRread:
		dot, err = input.Fetch(4)
	default:
		dot, err = input.Fetch(int(dot.Len()) - minMsgSize)
	}
	if err != nil {
		return nil, err
	}
	return msgParseLUT[dot.Type()](input, dot)
}

func parseTversion(input *sliding.Window, dot msg) (Msg, error) {
	if ver, _, err := verifyField(dot.Body()[4:], true, 0); err != nil {
		return nil, err
	} else if err := verifyString(ver); err != nil {
		return nil, err
	} else if len(ver) > MaxVersionLen {
		return nil, errLongVersion
	}
	return Tversion(dot), nil
}

func parseRversion(input *sliding.Window, dot msg) (Msg, error) {
	_, err := parseTversion(input, dot)
	if err != nil {
		return nil, err
	}
	return Rversion(dot), nil
}

func parseTauth(input *sliding.Window, dot msg) (Msg, error) {
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

func parseRauth(input *sliding.Window, dot msg) (Msg, error) {
	if err := verifyQid(dot.Body()); err != nil {
		return nil, err
	}
	return Rauth(dot), nil
}

func parseTattach(input *sliding.Window, dot msg) (Msg, error) {
	if err := parseTauthBody(dot.Body()[4:]); err != nil {
		return nil, err
	}
	return Tattach(dot), nil
}

func parseRattach(input *sliding.Window, dot msg) (Msg, error) {
	_, err := parseRauth(input, dot)
	if err != nil {
		return nil, err
	}
	return Rattach(dot), nil
}

func parseRerror(input *sliding.Window, dot msg) (Msg, error) {
	if str, _, err := verifyField(dot.Body(), true, 0); err != nil {
		return nil, err
	} else if err := verifyString(str); err != nil {
		return nil, err
	} else if len(str) > MaxErrorLen {
		return nil, errLongError
	}
	return Rerror(dot), nil
}

func parseTflush(input *sliding.Window, dot msg) (Msg, error) {
	return Tflush(dot), nil
}

func parseRflush(input *sliding.Window, dot msg) (Msg, error) {
	return Rflush(dot), nil
}

func parseTwalk(input *sliding.Window, dot msg) (Msg, error) {
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
		return nil, errOverSized
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

func parseRwalk(input *sliding.Window, dot msg) (Msg, error) {
	nwqid := guint16(dot.Body()[:2])
	if nwqid > MaxWElem {
		return nil, errMaxWElem
	}

	if sz, real := dot.Len(), int64(nwqid)*13; real < sz {
		return nil, errUnderSized
	} else if real > sz {
		return nil, errOverSized
	}

	for i := uint16(0); i < nwqid; i++ {
		if err := verifyQid(dot.Body()[i*13 : (i+1)*13]); err != nil {
			return nil, err
		}
	}
	return Rwalk(dot), nil
}

func parseTopen(input *sliding.Window, dot msg) (Msg, error) {
	return Topen(dot), nil
}

func parseRopen(input *sliding.Window, dot msg) (Msg, error) {
	if err := verifyQid(dot.Body()[:13]); err != nil {
		return nil, err
	}
	return Ropen(dot), nil
}

func parseTcreate(input *sliding.Window, dot msg) (Msg, error) {
	if name, _, err := verifyField(dot.Body()[4:], true, 5); err != nil {
		return nil, err
	} else if err := verifyString(name); err != nil {
		return nil, err
	} else if len(name) > MaxFilenameLen {
		return nil, errLongFilename
	}
	return Tcreate(dot), nil
}

func parseRcreate(input *sliding.Window, dot msg) (Msg, error) {
	_, err := parseRopen(input, dot)
	if err != nil {
		return nil, err
	}
	return Rcreate(dot), nil
}

func parseTread(input *sliding.Window, dot msg) (Msg, error) {
	// size[4] Tread tag[2] fid[4] offset[8] count[4]
	return Tread(dot), nil
}

func parseRread(input *sliding.Window, dot msg) (Msg, error) {
	// size[4] Rread tag[2] count[4] data[count]
	count := int64(guint32(dot.Body()[:4]))
	msgSize := dot.Len()
	realSize := count + 7
	if realSize < msgSize {
		return nil, errUnderSized
	} else if realSize > msgSize {
		return nil, errOverSized
	}
	return Rread{Reader: input.Reader(count), msg: dot}, nil
}

func parseTwrite(input *sliding.Window, dot msg) (Msg, error) {
	// size[4] Twrite tag[2] fid[4] offset[8] count[4]  data[count]
	offset := guint64(dot.Body()[4:12])
	if offset > MaxOffset {
		return nil, errMaxOffset
	}
	count := int64(guint32(dot.Body()[12:16]))
	msgSize := dot.Len()
	realSize := count + 15
	if realSize < msgSize {
		return nil, errUnderSized
	}
	if realSize > msgSize {
		return nil, errOverSized
	}
	return Twrite{Reader: input.Reader(count), msg: dot}, nil
}

func parseRwrite(input *sliding.Window, dot msg) (Msg, error) {
	return Rwrite(dot), nil
}

func parseTclunk(input *sliding.Window, dot msg) (Msg, error) {
	return Tclunk(dot), nil
}

func parseRclunk(input *sliding.Window, dot msg) (Msg, error) {
	return Rclunk(dot), nil
}

func parseTremove(input *sliding.Window, dot msg) (Msg, error) {
	return Tremove(dot), nil
}

func parseRremove(input *sliding.Window, dot msg) (Msg, error) {
	return Rremove(dot), nil
}

func parseTstat(input *sliding.Window, dot msg) (Msg, error) {
	return Tstat(dot), nil
}

func parseRstat(input *sliding.Window, dot msg) (Msg, error) {
	stat, _, err := verifyField(dot.Body(), true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Rstat(dot), nil
}

func parseTwstat(input *sliding.Window, dot msg) (Msg, error) {
	stat, _, err := verifyField(dot.Body(), true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Twstat(dot), nil
}

func parseRwstat(input *sliding.Window, dot msg) (Msg, error) {
	return Rwstat(dot), nil
}
