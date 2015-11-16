package styxproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

var (
	errMaxSize    = errors.New("message size larger than max uint32")
	errLongString = errors.New("string longer than max uint16")
	errMaxCount   = errors.New("count larger than max uint32")
)

// This package does not unmarshal messages into structures.
// Instead, they are kept as-is and fields are parsed on-demand
// via methods. The msg helper type is used to access fields
// common to all 9P messages.
type msg []byte

func (m msg) Type() uint8   { return m[4] }
func (m msg) Tag() uint16   { return guint16(m[5:7]) }
func (m msg) Body() []byte  { return m[7:] }
func (m msg) nbytes() int64 { return int64(len(m)) }

// Each 9P message begins with a four-byte size field specifying the
// length in bytes of the complete message including the four bytes
// of the size field itself.
func (m msg) Len() int64 { return int64(guint32(m[:4])) }

// Calling nthField on a message that has not been verified
// can result in a run-time panic if the size headers are
// incorrect.
func (m msg) nthField(offset, n int) []byte {
	size := int(guint16(m[offset : offset+2]))
	for i := 0; i < n; i++ {
		offset += size + 2
		size = int(guint16(m[offset : offset+2]))
	}
	return m[offset+2 : offset+2+size]
}

// A Msg is a 9P message. 9P messages are sent by clients (T-messages)
// and servers (R-messages).
type Msg interface {
	// Tag is a transaction identifier. No two pending T-messages may
	// use the same tag. All R-messages must reference the T-message
	// being answered by using the same tag.
	Tag() uint16

	// Len returns the total length of the message in bytes.
	Len() int64

	// The actual number of bytes that the message takes up in
	// memory. For large Twrite/Rread messages, this is just the headers,
	// and not the payload.
	nbytes() int64
}

// The version request negotiates the protocol version and message
// size to be used on the connection and initializes the connection
// for I/O.  Tversion must be the first message sent on the 9P connection,
// and the client cannot issue any further requests until it has
// received the Rversion reply.
type Tversion []byte

// For version messages, Tag should be styx.NOTAG
func (m Tversion) Tag() uint16 { return msg(m).Tag() }

// Len returns the length of a Tversion request in bytes.
func (m Tversion) Len() int64    { return msg(m).Len() }
func (m Tversion) nbytes() int64 { return msg(m).nbytes() }

// Msize returns the maximum length, in bytes, that the client will
// ever generate or expect to receive in a single 9P message. This
// count includes all 9P protocol data, starting from the size field
// and extending through the message, but excludes enveloping transport
// protocols.
func (m Tversion) Msize() int64 { return int64(guint32(m[7:11])) }

// Version identifies the level of the protocol that the client supports.
// The string must always begin with the two characters "9P".
func (m Tversion) Version() []byte { return msg(m).nthField(11, 0) }

// NewTversion creates a new Tversion message. The
// Tversion's tag is set to NoTag. Any space left over
// in buf is returned.
func NewTversion(buf []byte, msize uint32, version string) (Tversion, []byte, error) {
	if len(version) > MaxVersionLen {
		return nil, buf, errLongVersion
	}
	if len(buf) < minSizeLUT[msgTversion]+len(version) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTversion, NoTag, msize)
	b = pstring(b, version)
	writelen(b)

	return Tversion(b), buf[len(b):], nil
}

func (m Tversion) String() string {
	return fmt.Sprintf("Tversion msize=%d version=%q", m.Msize(), m.Version())
}

// An Rversion reply is sent in response to a Tversion request.
// It contains the version of the protocol that the server has
// chosen, and the maximum size of all successive messages.
type Rversion []byte

// Tag must return the tag of the corresponding Tversion message,
// NOTAG.
func (m Rversion) Tag() uint16 { return msg(m).Tag() }

// Len returns the length of the Rversion message in bytes.
func (m Rversion) Len() int64    { return msg(m).Len() }
func (m Rversion) nbytes() int64 { return msg(m).nbytes() }

// Msize returns the maximum size (in bytes) of any 9P message that
// it will send or accept, and must be equal to or less than the maximum
// suggested in the preceding Tversion message. After the Rversion
// message is received, both sides of the connection must honor this
// limit.
func (m Rversion) Msize() int64 { return Tversion(m).Msize() }

// Version identifies the level of the protocol that the server supports. If a server
// does not understand the protocol version sent in a Tversion message, Version
// will return the string "unknown". A server may choose to specify a version that
// is less than or equal to that supported by the client.
func (m Rversion) Version() []byte { return Tversion(m).Version() }

// NewRversion creates a new Rversion message. The
// Rversion's tag is set to NoTag. Any space left over
// in buf is returned.
func NewRversion(buf []byte, msize uint32, version string) (Rversion, []byte, error) {
	m, rest, err := NewTversion(buf, msize, version)
	if len(m) > 4 {
		m[4] = msgRversion
	}
	return Rversion(m), rest, err
}

func (m Rversion) String() string {
	return fmt.Sprintf("Rversion msize=%d version=%q", m.Msize(), m.Version())
}

// The Tauth message is used to authenticate users on a connection.
type Tauth []byte

func (m Tauth) Tag() uint16   { return msg(m).Tag() }
func (m Tauth) Len() int64    { return msg(m).Len() }
func (m Tauth) nbytes() int64 { return msg(m).nbytes() }

// The afid of a Tversion message establishes an 'authentication file';
// after a Tauth message is accepted by the server, a client must carry
// out the authentication protocol by performing I/O operations on
// afid. Any protocol may be used and authentication is outside the
// scope of the 9P protocol.
func (m Tauth) Afid() uint32 { return guint32(m[7:11]) }

// The uname field contains the name of the user to authenticate.
func (m Tauth) Uname() []byte { return msg(m).nthField(11, 0) }

// The aname field contains the name of the file tree to access. It
// may be empty.
func (m Tauth) Aname() []byte { return msg(m).nthField(11, 1) }

// NewTauth writes a new Tauth message to buf. If buf is not long
// enough to hold the Tauth message, io.ErrShortBuffer is returned.
// An error is returned if uname or aname are longer than MaxUidLen
// and MaxAttachLen, respectively. Any additional space in buf is
// returned from NewTauth.
func NewTauth(buf []byte, tag uint16, afid uint32, uname, aname string) (Tauth, []byte, error) {
	if len(uname) > MaxUidLen {
		return nil, buf, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return nil, buf, errLongAname
	}
	sz := minSizeLUT[msgTauth] + len(uname) + len(aname)
	if len(buf) < sz {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTauth, tag, afid)
	b = pstring(b, uname, aname)
	writelen(b)

	return Tauth(b), buf[len(b):], nil
}

func (m Tauth) String() string {
	return fmt.Sprintf("Tauth afid=%x uname=%q aname=%q", m.Afid(), m.Uname(), m.Aname())
}

// Servers that require authentication will reply to Tauth requests
// with an Rauth message. If a server does not require authentication,
// it can reply to a Tauth message with an Rerror message.
type Rauth []byte

func (m Rauth) Tag() uint16   { return msg(m).Tag() }
func (m Rauth) Len() int64    { return msg(m).Len() }
func (m Rauth) nbytes() int64 { return msg(m).nbytes() }

// The aqid of an Rauth message must be of type QTAUTH.
func (m Rauth) Aqid() Qid      { return Qid(m[7:20]) }
func (m Rauth) String() string { return fmt.Sprintf("Rauth aqid=%q", m.Aqid()) }

// NewRauth creates a new Rauth message. If buf is not long enough
// to hold the Rauth message, io.ErrShortBuffer is returned. NewRauth
// returns any additional space left in buf.
func NewRauth(buf []byte, tag uint16, qid Qid) (Rauth, []byte, error) {
	if len(buf) < maxSizeLUT[msgRauth] {
		return nil, nil, io.ErrShortBuffer
	}
	b := pheader(buf, msgRauth, tag)
	b = pqid(b, qid)
	writelen(b)

	return Rauth(b), buf[len(b):], nil
}

// The attach message serves as a fresh introduction from a  user on
// the client machine to the server.
type Tattach []byte

func (m Tattach) Tag() uint16   { return msg(m).Tag() }
func (m Tattach) Len() int64    { return msg(m).Len() }
func (m Tattach) nbytes() int64 { return msg(m).nbytes() }

// Fid establishes a fid to be used as the root of the file tree, should
// the client's Tattach request be accepted.
func (m Tattach) Fid() uint32 { return guint32(m[7:11]) }

// On servers that require authentication, afid serves to authenticate a user,
// and must have been established in a previous Tauth request. If a client
// does not wish to authenticate, afid should be set to styx.NOFID.
func (m Tattach) Afid() uint32 { return guint32(m[11:15]) }

// Uname is the user name of the attaching user.
func (m Tattach) Uname() []byte { return msg(m).nthField(15, 0) }

// Aname is the name of the file tree that the client wants to access.
func (m Tattach) Aname() []byte { return msg(m).nthField(15, 1) }

// NewTattach writes a new Tattach message to buf. If the client does not want
// to authenticate, afid should be NoFid. If buf is not long enough to hold the
// Tattach message, io.ErrShortBuffer is returned. An error is returned if uname
// or aname are longer than MaxUidLen or MaxAttachLen, respectively. NewTattach
// returns any remaining space left in buf.
func NewTattach(buf []byte, tag uint16, fid, afid uint32, uname, aname string) (Tattach, []byte, error) {
	if len(uname) > MaxUidLen {
		return nil, buf, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return nil, buf, errLongAname
	}
	sz := minSizeLUT[msgTattach] + len(uname) + len(aname)
	if len(buf) < sz {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTattach, tag, fid, afid)
	b = pstring(b, uname, aname)
	writelen(b)

	return Tattach(b), buf[len(b):], nil
}

func (m Tattach) String() string {
	return fmt.Sprintf("Tattach fid=%x afid=%x uname=%q aname=%q",
		m.Fid(), m.Afid(), m.Uname(), m.Aname())
}

// The Rattach message contains a server's reply to a Tattach request.
// As a result of the attach transaction, the client will have a
// connection to the root directory of the desired file tree, represented
// by the returned qid.
type Rattach []byte

func (m Rattach) Tag() uint16   { return msg(m).Tag() }
func (m Rattach) Len() int64    { return msg(m).Len() }
func (m Rattach) nbytes() int64 { return msg(m).nbytes() }

// Qid is the qid of the root of the file tree. Qid is associated
// with the fid of the corresponding Tattach request.
func (m Rattach) Qid() Qid { return Qid(m[7:20]) }

// NewRattach writes a new Rattach message to buf. If buf is not
// long enough to hold an Rattach message, io.ErrShortBuffer is
// returned. NewRattach will return any remaining space left in
// buf.
func NewRattach(buf []byte, tag uint16, qid Qid) (Rattach, []byte, error) {
	m, rest, err := NewRauth(buf, tag, qid)
	if len(m) > 4 {
		m[5] = msgRattach
	}
	return Rattach(m), rest, err
}

func (m Rattach) String() string { return fmt.Sprintf("Rattach qid=%q", m.Qid()) }

// The Rerror message (there is no Terror) is used to return an
// error string describing the failure of a transaction.
type Rerror []byte

// An Rerror message replaces the corresponding reply message that
// would accom- pany a successful call; its tag is that of the failing
// request.
func (m Rerror) Tag() uint16   { return msg(m).Tag() }
func (m Rerror) Len() int64    { return msg(m).Len() }
func (m Rerror) nbytes() int64 { return msg(m).nbytes() }

// Ename is a UTF-8 string describing the error that occured.
func (m Rerror) Ename() []byte { return msg(m).nthField(7, 0) }

// NewRerror writes a new Rerror message to buf. If buf is not
// long enough to hold the Rerror message, io.ErrShortBuffer is
// returned. If ename is longer than MaxErrorLen bytes, it is
// silently truncated to MaxErrorLen bytes.
func NewRerror(buf []byte, tag uint16, ename string) (Rerror, []byte, error) {
	if len(ename) > MaxErrorLen {
		ename = ename[:MaxErrorLen]
	}
	if len(buf) < minSizeLUT[msgRerror]+len(ename) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRerror, tag)
	b = pstring(b, ename)
	writelen(b)

	return Rerror(b), buf[len(b):], nil
}

func (m Rerror) String() string { return fmt.Sprintf("Rerror ename=%q", m.Ename()) }

// When the response to a request is no longer needed, such as
// when a user interrupts a process doing a read(2), a Tflush
// request is sent to the server to purge the pending response.
type Tflush []byte

func (m Tflush) Tag() uint16   { return msg(m).Tag() }
func (m Tflush) Len() int64    { return msg(m).Len() }
func (m Tflush) nbytes() int64 { return msg(m).nbytes() }

// The message being flushed is identified by oldtag.
func (m Tflush) Oldtag() uint16 { return guint16(m[7:9]) }

// NewTflush writes a new Tflush message to buf. If buf is not long
// enough to hold a Tflush message, io.ErrShortBuffer returns.
// NewTflush returns any remaining space left in buf.
func NewTflush(buf []byte, tag, oldtag uint16) (Tflush, []byte, error) {
	if len(buf) < maxSizeLUT[msgTflush] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTflush, tag)
	b = puint16(b, oldtag)
	writelen(b)

	return Tflush(b), buf[len(b):], nil
}

func (m Tflush) String() string { return fmt.Sprintf("Tflush oldtag=%x", m.Oldtag()) }

// A server should answer a Tflush message immediately with
// an Rflush message that echoes the tag (not oldtag) of the
// Tflush message. If it recognizes oldtag as the tag of a pending
// transaction, it should abort any pending response and discard
// that tag. A Tflush can never be responded to with an Rerror
// message.
type Rflush []byte

func (m Rflush) Tag() uint16   { return msg(m).Tag() }
func (m Rflush) Len() int64    { return msg(m).Len() }
func (m Rflush) nbytes() int64 { return msg(m).nbytes() }

// NewRflush writes a new Rflush message to buf. io.ErrShortBuffer is
// returned if buf is not long enough to hold an Rflush message. Any
// remaining space in buf is returned from NewRflush.
func NewRflush(buf []byte, tag uint16) (Rflush, []byte, error) {
	if len(buf) < maxSizeLUT[msgRflush] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRflush, tag)
	writelen(b)

	return Rflush(b), buf[len(b):], nil
}

func (m Rflush) String() string { return "Rflush" }

// A Twalk message is used to descend a directory hierarchy.
type Twalk []byte

func (m Twalk) Tag() uint16   { return msg(m).Tag() }
func (m Twalk) Len() int64    { return msg(m).Len() }
func (m Twalk) nbytes() int64 { return msg(m).nbytes() }

// The Twalk message contains the fid of the directory it intends
// to descend into. The Fid must have been established by a previous
// transaction, such as an attach.
func (m Twalk) Fid() uint32 { return guint32(m[7:11]) }

// Newfid contains the proposed fid that the client wishes to associate
// with the result of traversing the directory hierarchy.
func (m Twalk) Newfid() uint32 { return guint32(m[11:15]) }

// To simplify the implementation of servers, a maximum of sixteen
// name elements may be packed in a single message, as captured
// by the constant MaxWElem.
//
// It is legal for Nwname to be zero, in which case Newfid will
// represent the same file as Fid.
func (m Twalk) Nwname() int { return int(guint16(m[15:17])) }

// The Twalk message contains an ordered list of path name elements
// that the client wishes to descend into in succession.
func (m Twalk) Wname(n int) []byte { return msg(m).nthField(17, n) }

// NewTwalk writes a new Twalk message to buf. io.ErrShortBuffer is returned
// if buf is not long enough to hold the Twalk message.  An error is returned
// if wname is longer than MaxWElem elements, or if any single element in
// wname is longer than MaxFilenameLen bytes long.
func NewTwalk(buf []byte, tag uint16, fid, newfid uint32, wname ...string) (Twalk, []byte, error) {
	if len(wname) > MaxWElem {
		return nil, buf, errMaxWElem
	}
	space := len(buf) - minSizeLUT[msgTwalk]
	for _, v := range wname {
		if len(v) > MaxFilenameLen {
			return nil, buf, errLongFilename
		}
		if space < 0 {
			break
		}
	}
	if space < 0 {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTwalk, tag, fid, newfid)
	b = puint16(b, uint16(len(wname)))
	b = pstring(b, wname...)
	writelen(b)

	return Twalk(b), buf[len(b):], nil
}

func (m Twalk) String() string {
	var buf [MaxWElem][]byte
	wname := buf[:0]

	for i := 0; i < m.Nwname(); i++ {
		wname = append(wname, m.Wname(i))
	}
	path := bytes.Join(wname, []byte("/"))
	return fmt.Sprintf("Twalk fid=%x newfid=%x %q", m.Fid(), m.Newfid(), path)
}

// An Rwalk message contains a server's reply to a successful
// Twalk request. If the first path in the corresponding Twalk request
// cannot be walked, an Rerror message is returned instead.
type Rwalk []byte

func (m Rwalk) Tag() uint16   { return msg(m).Tag() }
func (m Rwalk) Len() int64    { return msg(m).Len() }
func (m Rwalk) nbytes() int64 { return msg(m).nbytes() }

// Nwqid must always be equal to or lesser than Nwname of the corresponding
// Twalk request. Only if Nwqid is equal to Nwname is the Newfid of
// the Twalk request established. Nwqid must always be greater than
// zero.
func (m Rwalk) Nwqid() int { return int(guint16(m[7:9])) }

// Wqid contains the Qid values of each path in the walk
// requested by the client, up to the first failure.
func (m Rwalk) Wqid(n int) Qid { return Qid(m[9+n*13 : 9+(n+1)*13]) }

// NewRwalk writes a new Rwalk message to buf. An error is returned if wqid
// has more than MaxWElem elements. io.ErrShortBuffer is returned if buf
// is not long enough to hold the Rwalk message.
func NewRwalk(buf []byte, tag uint16, wqid ...Qid) (Rwalk, []byte, error) {
	if len(wqid) > MaxWElem {
		return nil, buf, errMaxWElem
	}
	if len(buf) < minSizeLUT[msgRwalk]+13*len(wqid) {
		return nil, buf, io.ErrShortBuffer
	}

	b := pheader(buf, msgRwalk, tag)
	b = puint16(b, uint16(len(wqid)))
	b = pqid(b, wqid...)
	writelen(b)

	return Rwalk(b), buf[len(b):], nil
}

func (m Rwalk) String() string {
	var buf [MaxWElem]string
	wqid := buf[:0]

	for i := 0; i < m.Nwqid(); i++ {
		wqid = append(wqid, m.Wqid(i).String())
	}
	return fmt.Sprintf("Rwalk wqid=%q", strings.Join(wqid, ","))
}

// The open request asks the file server to check permissions
// and prepare a fid for I/O with subsequent read and write
// messages.
type Topen []byte

func (m Topen) Tag() uint16   { return msg(m).Tag() }
func (m Topen) Len() int64    { return msg(m).Len() }
func (m Topen) nbytes() int64 { return msg(m).nbytes() }

// Fid is the fid of the file to open, as established by a previous
// transaction (such as a succesful Twalk).
func (m Topen) Fid() uint32 { return guint32(m[7:11]) }

// The mode field determines the type of I/O, and is checked against the
// permissions for the file:
//
// 	0 (OREAD)    read access
// 	1 (OWRITE)   write access
// 	2 (ORDWR)    read and write access
// 	3 (OEXEC)    execute access
//
// If mode has the OTRUNC (0x10) bit set, the file is to be
// truncated, which requires write permission (if the file is append-only,
// and permission is granted, the open succeeds but the file will not be
// truncated)
//
// If the mode has the ORCLOSE (0x40) bit set, the file is to
// be removed when the fid is clunked, which requires permission to remove
// the file from its directory. All other bits in mode should be zero.
//
// It is illegal to write a directory, truncate it, or attempt to remove
// it on close.
func (m Topen) Mode() uint8 { return uint8(m[11]) }

// NewTopen writes a new Topen message to buf. io.ErrShortBuffer is returned if
// buf is not long enough to contain a Topen message. NewTopen returns any
// remaining space in buf.
func NewTopen(buf []byte, tag uint16, fid uint32, mode uint8) (Topen, []byte, error) {
	if len(buf) < maxSizeLUT[msgTopen] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTopen, tag, fid)
	b = puint8(b, mode)
	writelen(b)

	return Topen(b), buf[len(b):], nil
}

func (m Topen) String() string {
	return fmt.Sprintf("Topen fid=%x mode=%#o", m.Fid(), m.Mode())
}

// An Ropen message contains a servers response to a Topen
// request. An Ropen message is only sent if the server determined
// that the requesting user had the proper permissions required
// for the Topen to succeed, otherwise Rerror is returned.
type Ropen []byte

func (m Ropen) Tag() uint16   { return msg(m).Tag() }
func (m Ropen) Len() int64    { return msg(m).Len() }
func (m Ropen) nbytes() int64 { return msg(m).nbytes() }

// Qid contains the unique identifier of the opened file.
func (m Ropen) Qid() Qid { return Qid(m[7:20]) }

// The iounit field returned by open and create may be zero.  If it
// is not, it is the maximum number of bytes that are guaranteed to
// be read from or written to the file without breaking the I/O transfer
// into multiple 9P messages
func (m Ropen) IOunit() int64 { return int64(guint32(m[20:24])) }

// NewRopen writes a new Ropen message to buf. io.ErrShortBuffer is returned if
// buf is not long enough to hold an Ropen message. Any additional space left
// in buf is returned.
func NewRopen(buf []byte, tag uint16, qid Qid, iounit uint32) (Ropen, []byte, error) {
	if len(buf) < maxSizeLUT[msgRopen] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRopen, tag)
	b = pqid(b, qid)
	b = puint32(b, iounit)
	writelen(b)

	return Ropen(b), buf[len(b):], nil
}

func (m Ropen) String() string {
	return fmt.Sprintf("Ropen qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tcreate []byte

func (m Tcreate) Tag() uint16   { return msg(m).Tag() }
func (m Tcreate) Len() int64    { return msg(m).Len() }
func (m Tcreate) nbytes() int64 { return msg(m).nbytes() }
func (m Tcreate) Fid() uint32   { return guint32(m[7:11]) }
func (m Tcreate) Name() []byte  { return msg(m).nthField(11, 0) }
func (m Tcreate) Perm() uint32 {
	// Would have been nice if Name came at the end
	offset := 11 + 2 + guint16(m[11:13])
	return guint32(m[offset : offset+4])
}
func (m Tcreate) Mode() uint8 { return m[len(m.Name())+17] }

func NewTcreate(buf []byte, tag uint16, fid uint32, name string, perm uint32, mode uint8) (Tcreate, []byte, error) {
	if len(name) > MaxFilenameLen {
		return nil, buf, errLongFilename
	}
	if len(buf) < minSizeLUT[msgTcreate]+len(name) {
		return nil, buf, io.ErrShortBuffer
	}

	b := pheader(buf, msgTcreate, tag, fid)
	b = pstring(b, name)
	b = puint32(b, perm)
	b = puint8(b, mode)
	writelen(b)

	return Tcreate(b), buf[len(b):], nil
}

func (m Tcreate) String() string {
	return fmt.Sprintf("Tcreate fid=%x name=%q perm=%o mode=%#o",
		m.Fid(), m.Name(), m.Perm(), m.Mode())
}

type Rcreate []byte

func (m Rcreate) Tag() uint16   { return msg(m).Tag() }
func (m Rcreate) Len() int64    { return msg(m).Len() }
func (m Rcreate) nbytes() int64 { return msg(m).nbytes() }
func (m Rcreate) Qid() Qid      { return Qid(m[7:20]) }
func (m Rcreate) IOunit() int64 { return int64(guint32(m[20:24])) }

func NewRcreate(buf []byte, tag uint16, qid Qid, iounit uint32) (Rcreate, []byte, error) {
	if len(buf) < maxSizeLUT[msgRcreate] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRcreate, tag)
	b = pqid(b, qid)
	b = puint32(b, iounit)
	writelen(b)

	return Rcreate(b), buf[len(b):], nil
}

func (m Rcreate) String() string {
	return fmt.Sprintf("Rcreate qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tread []byte

func (m Tread) Tag() uint16   { return msg(m).Tag() }
func (m Tread) Len() int64    { return msg(m).Len() }
func (m Tread) nbytes() int64 { return msg(m).nbytes() }

// Fid is the handle of the file to read from.
func (m Tread) Fid() uint32 { return guint32(m[7:11]) }

// Offset is the starting point in the file from which to begin
// returning data.
func (m Tread) Offset() int64 { return int64(guint64(m[11:19])) }

// Count is the number of bytes to read from the file. Count
// cannot be more than the maximum value of a 32-bit unsigned
// integer.
func (m Tread) Count() int64 { return int64(guint32(m[19:23])) }

// NewTread creates a New Tread message The offset must be smaller
// than MaxOffset.
func NewTread(buf []byte, tag uint16, fid uint32, offset, count int64) (Tread, []byte, error) {
	if len(buf) < maxSizeLUT[msgTread] {
		return nil, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return nil, buf, errMaxCount
	}
	b := pheader(buf, msgTread, tag, fid)
	b = puint64(b, uint64(offset))
	b = puint32(b, uint32(count))
	writelen(b)

	return Tread(b), buf[len(b):], nil
}

func (m Tread) String() string {
	return fmt.Sprintf("Tread fid=%d offset=%d count=%d", m.Fid(), m.Offset(), m.Count())
}

// The Rread message returns the bytes requested by a Tread message.
// The data portion of an Rread message can be consumed using the io.Reader
// interface.
type Rread struct {
	io.Reader
	msg msg // headers plus any extra buffered data
}

// If a Tread requests asks for more data than can fit within a single 9P
// message, multiple Rread messages will be generated that cite the tag
// of a single Tread request.
func (m Rread) Tag() uint16   { return m.msg.Tag() }
func (m Rread) Len() int64    { return m.msg.Len() }
func (m Rread) nbytes() int64 { return m.msg.nbytes() }
func (m Rread) Count() int64  { return int64(guint32(m.msg[7:11])) }

// NewRread writes a new Rread message to buf.  An error is returned if
// count exceeds the maximum size of a 9P message.  If buf is not large
// enough to contain the header of the Rread request, io.ErrShortBuffer is
// returned. The data parameter is used as-is and is not copied.
func NewRread(buf []byte, tag uint16, count int64, data io.Reader) (Rread, []byte, error) {
	if len(buf) < minSizeLUT[msgRread] {
		return Rread{}, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return Rread{}, buf, errTooBig
	}
	b := pheader(buf, msgRread, tag, uint32(count))
	if math.MaxUint32-int64(count) < int64(len(b)) {
		return Rread{}, buf, errTooBig
	}
	puint32(b[:0], uint32(len(b))+uint32(count))

	return Rread{Reader: io.LimitReader(data, int64(count)), msg: b}, buf[len(b):], nil
}

func (m Rread) String() string { return fmt.Sprintf("Rread count=%d", m.Count()) }

// The Twrite message is sent by a client to write data to a file.
// The data portion of a Twrite request can be accessed via the
// io.Reader interface.
type Twrite struct {
	io.Reader
	msg msg // headers plus any extra buffered data
}

func (m Twrite) Tag() uint16   { return m.msg.Tag() }
func (m Twrite) Len() int64    { return m.msg.Len() }
func (m Twrite) nbytes() int64 { return m.msg.nbytes() }
func (m Twrite) Fid() uint32   { return Tread(m.msg).Fid() }
func (m Twrite) Offset() int64 { return Tread(m.msg).Offset() }
func (m Twrite) Count() int64  { return Tread(m.msg).Count() }

func NewTwrite(buf []byte, tag uint16, fid uint32, offset, count int64, data io.Reader) (Twrite, []byte, error) {
	if len(buf) < minSizeLUT[msgTwrite] {
		return Twrite{}, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return Twrite{}, buf, errTooBig
	}
	b := pheader(buf, msgTwrite, tag, fid)
	b = puint64(b, uint64(offset))
	b = puint32(b, uint32(count))
	if math.MaxUint32-int64(count) < int64(len(b)) {
		return Twrite{}, buf, errTooBig
	}
	puint32(b[:0], uint32(len(b))+uint32(count))

	return Twrite{Reader: io.LimitReader(data, int64(count)), msg: b}, buf[len(b):], nil
}

func (m Twrite) String() string {
	return fmt.Sprintf("Twrite fid=%x offset=%d count=%d",
		m.Fid(), m.Offset(), m.Count())
}

type Rwrite []byte

func (m Rwrite) Tag() uint16   { return msg(m).Tag() }
func (m Rwrite) Len() int64    { return msg(m).Len() }
func (m Rwrite) nbytes() int64 { return msg(m).nbytes() }
func (m Rwrite) Count() uint32 { return guint32(m[7:11]) }

func NewRwrite(buf []byte, tag uint16, count int64) (Rwrite, []byte, error) {
	if len(buf) < maxSizeLUT[msgRwrite] {
		return nil, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return nil, buf, errMaxCount
	}
	b := pheader(buf, msgRwrite, tag, uint32(count))
	writelen(b)

	return Rwrite(b), buf[len(b):], nil
}

func (m Rwrite) String() string { return fmt.Sprintf("Rwrite count=%d", m.Count()) }

// The clunk request informs the file server that the current
// file represented by fid is no longer needed by the client.
// The actual file is not removed on the server unless the fid
// had been opened with ORCLOSE.
type Tclunk []byte

func (m Tclunk) Tag() uint16   { return msg(m).Tag() }
func (m Tclunk) Len() int64    { return msg(m).Len() }
func (m Tclunk) nbytes() int64 { return msg(m).nbytes() }
func (m Tclunk) Fid() uint32   { return guint32(m[7:11]) }

func NewTclunk(buf []byte, tag uint16, fid uint32) (Tclunk, []byte, error) {
	if len(buf) < maxSizeLUT[msgTclunk] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTclunk, tag, fid)
	writelen(b)

	return Tclunk(b), buf[len(b):], nil
}
func (m Tclunk) String() string { return fmt.Sprintf("Tclunk fid=%x", m.Fid()) }

type Rclunk []byte

func (m Rclunk) Tag() uint16   { return msg(m).Tag() }
func (m Rclunk) Len() int64    { return msg(m).Len() }
func (m Rclunk) nbytes() int64 { return msg(m).nbytes() }

func NewRclunk(buf []byte, tag uint16) (Rclunk, []byte, error) {
	if len(buf) < maxSizeLUT[msgRclunk] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRclunk, tag)
	writelen(b)

	return Rclunk(b), buf[len(b):], nil
}
func (m Rclunk) String() string { return "Rclunk" }

type Tremove []byte

func (m Tremove) Tag() uint16   { return msg(m).Tag() }
func (m Tremove) Len() int64    { return msg(m).Len() }
func (m Tremove) nbytes() int64 { return msg(m).nbytes() }
func (m Tremove) Fid() uint32   { return guint32(m[7:11]) }

func NewTremove(buf []byte, tag uint16, fid uint32) (Tremove, []byte, error) {
	if len(buf) < maxSizeLUT[msgTremove] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTremove, tag, fid)
	writelen(b)

	return Tremove(b), buf[len(b):], nil
}
func (m Tremove) String() string { return fmt.Sprintf("Tremove fid=%x", m.Fid()) }

type Rremove []byte

func (m Rremove) Tag() uint16   { return msg(m).Tag() }
func (m Rremove) Len() int64    { return msg(m).Len() }
func (m Rremove) nbytes() int64 { return msg(m).nbytes() }

func NewRremove(buf []byte, tag uint16) (Rremove, []byte, error) {
	if len(buf) < maxSizeLUT[msgRremove] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRremove, tag)
	writelen(b)

	return Rremove(b), buf[len(b):], nil
}
func (m Rremove) String() string { return "Rremove" }

type Tstat []byte

func (m Tstat) Tag() uint16   { return msg(m).Tag() }
func (m Tstat) Len() int64    { return msg(m).Len() }
func (m Tstat) nbytes() int64 { return msg(m).nbytes() }
func (m Tstat) Fid() uint32   { return guint32(m[7:11]) }

func NewTstat(buf []byte, tag uint16, fid uint32) (Tstat, []byte, error) {
	if len(buf) < maxSizeLUT[msgTstat] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTstat, tag, fid)
	writelen(b)

	return Tstat(b), buf[len(b):], nil
}
func (m Tstat) String() string { return fmt.Sprintf("Tstat fid=%x", m.Fid()) }

type Rstat []byte

func (m Rstat) Tag() uint16   { return msg(m).Tag() }
func (m Rstat) Len() int64    { return msg(m).Len() }
func (m Rstat) nbytes() int64 { return msg(m).nbytes() }
func (m Rstat) Stat() Stat    { return msg(m).nthField(7, 0) }

func NewRstat(buf []byte, tag uint16, stat Stat) (Rstat, []byte, error) {
	if len(stat) > maxStatLen {
		return nil, buf, errLongStat
	}
	if len(stat) < minStatLen {
		return nil, buf, errShortStat
	}
	if len(buf) < minSizeLUT[msgRstat]+len(stat) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRstat, tag)
	b = pbyte(b, stat)
	writelen(b)

	return Rstat(b), buf[len(b):], nil
}
func (m Rstat) String() string { return "Rstat " + m.Stat().String() }

type Twstat []byte

func (m Twstat) Tag() uint16   { return msg(m).Tag() }
func (m Twstat) Len() int64    { return msg(m).Len() }
func (m Twstat) nbytes() int64 { return msg(m).nbytes() }
func (m Twstat) Fid() uint32   { return guint32(m[7:11]) }
func (m Twstat) Stat() Stat    { return msg(m).nthField(7, 0) }

func NewTwstat(buf []byte, tag uint16, fid uint32, stat Stat) (Twstat, []byte, error) {
	if len(stat) > maxStatLen {
		return nil, buf, errLongStat
	}
	if len(stat) < minStatLen {
		return nil, buf, errShortStat
	}
	if len(buf) < minSizeLUT[msgTwstat]+len(stat) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTwstat, tag)
	b = pbyte(b, stat)
	writelen(b)

	return Twstat(b), buf[len(b):], nil
}
func (m Twstat) String() string { return fmt.Sprintf("Twstat fid=%x stat=%q", m.Fid(), m.Stat()) }

type Rwstat []byte

func (m Rwstat) Tag() uint16   { return msg(m).Tag() }
func (m Rwstat) Len() int64    { return msg(m).Len() }
func (m Rwstat) nbytes() int64 { return msg(m).nbytes() }

func NewRwstat(buf []byte, tag uint16) (Rwstat, []byte, error) {
	if len(buf) < maxSizeLUT[msgRwstat] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRwstat, tag)
	writelen(b)

	return Rwstat(b), buf[len(b):], nil
}
func (m Rwstat) String() string { return "Rwstat" }

// BadMessage represents an invalid message.
type BadMessage struct {
	Err    error // the reason the message is invalid
	length int64 // the message bytes
	tag    uint16
}

// Tag returns the tag of the errant message. Servers
// should cite the same tag when replying with an Rerror
// message.
func (m BadMessage) Tag() uint16    { return m.tag }
func (m BadMessage) Len() int64     { return m.length }
func (m BadMessage) nbytes() int64  { return m.length }
func (m BadMessage) String() string { return fmt.Sprintf("bad message: %v", m.Err) }
