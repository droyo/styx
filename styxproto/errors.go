package styxproto

import "errors"

type parseError string

func (p parseError) Error() string { return string(p) }

var (
	errContainsSlash  = parseError("slash in path element")
	errInvalidMsgType = parseError("invalid message type")
	errInvalidQidType = parseError("invalid type field in qid")
	errInvalidUTF8    = parseError("string is not valid utf8")
	errLongAname      = parseError("aname field too long")
	errLongError      = parseError("error message too long")
	errLongFilename   = parseError("file name too long")
	errLongSize       = parseError("size field is longer than actual message size")
	errLongLength     = parseError("long length field in stat structure")
	errLongStat       = parseError("stat structure too long")
	errLongUsername   = parseError("uid or gid name is too long")
	errLongVersion    = parseError("protocol version string too long")
	errMaxOffset      = parseError("Maximum offset exceeded")
	errMaxWElem       = parseError("maximum walk elements exceeded")
	errNullString     = parseError("NUL in string field")
	errOverSize       = parseError("size of field exceeds size of message")
	errShortStat      = parseError("stat structure too short")
	errTooBig         = parseError("message is too long")
	errTooSmall       = parseError("message is too small")
	errUnderSize      = parseError("empty space in message")
	errZeroLen        = parseError("zero-length message")
)

// ErrMaxSize is returned during the parsing process if a message
// exceeds the maximum size negotiated during the Tversion/Rversion
// transaction.
var ErrMaxSize = errors.New("message exceeds msize")
