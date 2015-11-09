package styxproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"aqwari.net/net/styx"
)

// This package does not unmarshal messages into structures.
// Instead, they are kept as-is and fields are parsed on-demand
// via methods. The msg helper type is used to access fields
// common to all 9P messages.
type msg []byte

func (m msg) Type() uint8  { return m[4] }
func (m msg) Tag() uint16  { return guint16(m[5:7]) }
func (m msg) Body() []byte { return m[7:] }

// In the 9P protocol, the first field, size[4], does *not*
// count itself in the size of the 9P message. It should be
// interpreted as "the number of subsequent bytes".
// However, the byte slices we wrap our types around *do*
// contain the size[4] header. So the size[4] field should
// equal len(m) - 4 for non-Rread/Twrite messages.
func (m msg) Len() int64 { return int64(guint32(m[:4])) }

// Calling nthField on a message that has not been verified
// can result in a run-time panic if the size headers are
// incorrect.
func (m msg) nthField(offset, n int) []byte {
	size := int(binary.LittleEndian.Uint16(m[offset : offset+2]))
	for i := 0; i < n; i++ {
		offset += size + 2
		size = int(binary.LittleEndian.Uint16(m[offset : offset+2]))
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
func (m Tversion) Len() int64 { return int64(len(m) - 4) }

// Msize returns the maximum length, in bytes, that the client will
// ever generate or expect to receive in a single 9P message. This
// count includes all 9P protocol data, starting from the size field
// and extending through the message, but excludes enveloping transport
// protocols.
func (m Tversion) Msize() int64 { return int64(binary.LittleEndian.Uint32(m[3:7])) }

// Version identifies the level of the protocol that the client supports.
// The string must always begin with the two characters "9P".
func (m Tversion) Version() string { return string(msg(m).nthField(7, 0)) }
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
func (m Rversion) Len() int64 { return int64(len(m) - 4) }

// Version identifies the level of the protocol that the server supports. If a server
// does not understand the protocol version sent in a Tversion message, Version
// will return the string "unknown". A server may choose to specify a version that
// is less than or equal to that supported by the client.
func (m Rversion) Version() string { return string(msg(m).nthField(7, 0)) }

// Msize returns the maximum size (in bytes) of any 9P message that
// it will send or accept, and must be equal to or less than the maximum
// suggested in the preceding Tversion message. After the Rversion
// message is received, both sides of the connection must honor this
// limit.
func (m Rversion) Msize() int64 { return int64(binary.LittleEndian.Uint32(m[3:7])) }

func (m Rversion) String() string {
	return fmt.Sprintf("Rversion msize=%d version=%q", m.Msize(), m.Version())
}

// The Tauth message is used to authenticate users on a connection.
type Tauth []byte

func (m Tauth) Tag() uint16 { return msg(m).Tag() }
func (m Tauth) Len() int64  { return int64(len(m) - 4) }

// The afid of a Tversion message establishes an 'authentication file';
// after a Tauth message is accepted by the server, a client must carry
// out the authentication protocol by performing I/O operations on
// afid. Any protocol may be used and authentication is outside the
// scope of the 9P protocol.
func (m Tauth) Afid() uint32 { return binary.LittleEndian.Uint32(m[3:7]) }

// The uname field contains the name of the user to authenticate.
func (m Tauth) Uname() []byte { return msg(m).nthField(7, 0) }

// The aname field contains the name of the file tree to access. It
// may be empty.
func (m Tauth) Aname() []byte { return msg(m).nthField(7, 1) }

func (m Tauth) String() string {
	return fmt.Sprintf("Tauth afid=%x uname=%q aname=%q", m.Afid(), m.Uname(), m.Aname())
}

// Servers that require authentication will reply to Tauth requests
// with an Rauth message. If a server does not require authentication,
// it can reply to a Tauth message with an Rerror message.
type Rauth []byte

func (m Rauth) Tag() uint16 { return msg(m).Tag() }
func (m Rauth) Len() int64  { return int64(len(m) - 4) }

// The aqid of an Rauth message must be of type QTAUTH.
func (m Rauth) Aqid() styx.Qid { return styx.Qid(m[3:16]) }
func (m Rauth) String() string { return fmt.Sprintf("Rauth aqid=%q", m.Aqid()) }

// The attach message serves as a fresh introduction from a  user on
// the client machine to the server.
type Tattach []byte

func (m Tattach) Tag() uint16 { return msg(m).Tag() }
func (m Tattach) Len() int64  { return int64(len(m) - 4) }

// Fid establishes a fid to be used as the root of the file tree, should
// the client's Tattach request be accepted.
func (m Tattach) Fid() uint32 { return binary.LittleEndian.Uint32(m[3:7]) }

// On servers that require authentication, afid serves to authenticate a user,
// and must have been established in a previous Tauth request. If a client
// does not wish to authenticate, afid should be set to styx.NOFID.
func (m Tattach) Afid() uint32 { return binary.LittleEndian.Uint32(m[7:11]) }

// Uname is the user name of the attaching user.
func (m Tattach) Uname() []byte { return msg(m).nthField(11, 0) }

// Aname is the name of the file tree that the client wants to access.
func (m Tattach) Aname() []byte { return msg(m).nthField(11, 1) }

func (m Tattach) String() string {
	return fmt.Sprintf("Tattach fid=%x afid=%x uname=%q aname=%q",
		m.Fid(), m.Afid(), m.Uname(), m.Aname())
}

type Rattach []byte

func (m Rattach) Tag() uint16 { return msg(m).Tag() }
func (m Rattach) Len() int64  { return int64(len(m) - 4) }

// Qid is the qid of the root of the file tree. Qid is associated
// with the fid of the corresponding Tattach request.
func (m Rattach) Qid() styx.Qid  { return styx.Qid(m[3:16]) }
func (m Rattach) String() string { return fmt.Sprintf("Rattach qid=%q", m.Qid()) }

type Rerror msg

func (m Rerror) Tag() uint16 { return msg(m).Tag() }
func (m Rerror) Len() int64  { return int64(len(m) - 4) }

// Ename is a UTF-8 string describing the error that occured.
func (m Rerror) Ename() []byte { return msg(m).nthField(3, 0) }

// The Error method implements the error interface, and
// returns the result of the Ename method as a string.
func (m Rerror) Error() string { return string(m.Ename()) }

func (m Rerror) String() string { return fmt.Sprintf("Rerror ename=%q", m.Ename()) }

type Tflush msg

func (m Tflush) Tag() uint16    { return msg(m).Tag() }
func (m Tflush) Len() int64     { return int64(len(m) - 4) }
func (m Tflush) Oldtag() uint16 { return binary.LittleEndian.Uint16(m[3:5]) }
func (m Tflush) String() string { return fmt.Sprintf("Tflush oldtag=%x", m.Oldtag()) }

type Rflush msg

func (m Rflush) Tag() uint16    { return msg(m).Tag() }
func (m Rflush) Len() int64     { return int64(len(m) - 4) }
func (m Rflush) String() string { return "Rflush" }

type Twalk msg

func (m Twalk) Tag() uint16        { return msg(m).Tag() }
func (m Twalk) Len() int64         { return int64(len(m) - 4) }
func (m Twalk) Fid() uint32        { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Twalk) Newfid() uint32     { return binary.LittleEndian.Uint32(m[7:11]) }
func (m Twalk) Nwname() int        { return int(binary.LittleEndian.Uint16(m[11:13])) }
func (m Twalk) Wname(n int) []byte { return msg(m).nthField(13, n) }
func (m Twalk) String() string {
	names := make([][]byte, m.Nwname())
	for i := 0; i < m.Nwname(); i++ {
		names[i] = m.Wname(i)
	}
	path := bytes.Join(names, []byte("/"))
	return fmt.Sprintf("Twalk fid=%x newfid=%x wname=%q",
		m.Fid(), m.Newfid(), path)
}

type Rwalk msg

func (m Rwalk) Tag() uint16         { return msg(m).Tag() }
func (m Rwalk) Len() int64          { return int64(len(m) - 4) }
func (m Rwalk) Nwqid() int          { return int(binary.LittleEndian.Uint16(m[3:5])) }
func (m Rwalk) Wqid(n int) styx.Qid { return styx.Qid(m[n*13 : n*13+13]) }

func (m Rwalk) String() string {
	wqid := make([][]byte, m.Nwqid())
	for i := 0; i < m.Nwqid(); i++ {
		wqid[i] = m.Wqid(i)
	}
	return fmt.Sprintf("Rwalk wqid=%q", bytes.Join(wqid, []byte(",")))
}

type Topen msg

func (m Topen) Tag() uint16 { return msg(m).Tag() }
func (m Topen) Len() int64  { return int64(len(m) - 4) }
func (m Topen) Fid() uint32 { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Topen) Mode() uint8 { return uint8(m[7]) }
func (m Topen) String() string {
	return fmt.Sprintf("Topen fid=%x mode=%#o", m.Fid(), m.Mode())
}

type Ropen msg

func (m Ropen) Tag() uint16   { return msg(m).Tag() }
func (m Ropen) Len() int64    { return int64(len(m) - 4) }
func (m Ropen) Qid() styx.Qid { return styx.Qid(m[3:16]) }
func (m Ropen) IOunit() int64 { return int64(binary.LittleEndian.Uint32(m[16:20])) }
func (m Ropen) String() string {
	return fmt.Sprintf("Ropen qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tcreate msg

func (m Tcreate) Tag() uint16  { return msg(m).Tag() }
func (m Tcreate) Len() int64   { return int64(len(m) - 4) }
func (m Tcreate) Fid() uint32  { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Tcreate) Name() []byte { return msg(m).nthField(7, 0) }
func (m Tcreate) Perm() uint32 {
	// Would have been nice if Name came at the end
	offset := 7 + 2 + len(m.Name())
	return binary.LittleEndian.Uint32(m[offset : offset+4])
}
func (m Tcreate) Mode() uint8 { return m[len(m.Name())+13] }
func (m Tcreate) String() string {
	return fmt.Sprintf("Tcreate fid=%x name=%q perm=%o mode=%#o",
		m.Fid(), m.Name(), m.Perm(), m.Mode())
}

type Rcreate msg

func (m Rcreate) Tag() uint16   { return msg(m).Tag() }
func (m Rcreate) Len() int64    { return int64(len(m) - 4) }
func (m Rcreate) Qid() styx.Qid { return styx.Qid(m[3:16]) }
func (m Rcreate) IOunit() int64 { return int64(binary.LittleEndian.Uint32(m[16:20])) }
func (m Rcreate) String() string {
	return fmt.Sprintf("Rcreate qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tread msg

func (m Tread) Tag() uint16    { return msg(m).Tag() }
func (m Tread) Len() int64     { return int64(len(m) - 4) }
func (m Tread) Fid() uint32    { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Tread) Offset() uint64 { return binary.LittleEndian.Uint64(m[7:15]) }
func (m Tread) Count() uint32  { return binary.LittleEndian.Uint32(m[15:19]) }
func (m Tread) String() string {
	return fmt.Sprintf("Tread offset=%d count=%d", m.Offset(), m.Count())
}

type Rwrite msg

func (m Rwrite) Tag() uint16   { return msg(m).Tag() }
func (m Rwrite) Len() int64    { return int64(len(m) - 4) }
func (m Rwrite) Count() uint32 { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Rwrite) String() string {
	return fmt.Sprintf("Rwrite count=%d", m.Count())
}

type Tclunk msg

func (m Tclunk) Tag() uint16    { return msg(m).Tag() }
func (m Tclunk) Len() int64     { return int64(len(m) - 4) }
func (m Tclunk) Fid() uint32    { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Tclunk) String() string { return fmt.Sprintf("Tclunk fid=%x", m.Fid()) }

type Rclunk msg

func (m Rclunk) Tag() uint16    { return msg(m).Tag() }
func (m Rclunk) Len() int64     { return int64(len(m) - 4) }
func (m Rclunk) String() string { return "Rclunk" }

type Tremove msg

func (m Tremove) Tag() uint16    { return msg(m).Tag() }
func (m Tremove) Len() int64     { return int64(len(m) - 4) }
func (m Tremove) Fid() uint32    { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Tremove) String() string { return fmt.Sprintf("Tremove fid=%x", m.Fid()) }

type Rremove msg

func (m Rremove) Tag() uint16    { return msg(m).Tag() }
func (m Rremove) Len() int64     { return int64(len(m) - 4) }
func (m Rremove) String() string { return "Rremove" }

type Tstat msg

func (m Tstat) Tag() uint16    { return msg(m).Tag() }
func (m Tstat) Len() int64     { return int64(len(m) - 4) }
func (m Tstat) Fid() uint32    { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Tstat) String() string { return fmt.Sprintf("Tstat fid=%x", m.Fid()) }

type Rstat msg

func (m Rstat) Tag() uint16    { return msg(m).Tag() }
func (m Rstat) Len() int64     { return int64(len(m) - 4) }
func (m Rstat) Stat() Stat     { return msg(m).nthField(3, 0) }
func (m Rstat) String() string { return "Rstat " + m.Stat().String() }

type Twstat msg

func (m Twstat) Tag() uint16    { return msg(m).Tag() }
func (m Twstat) Len() int64     { return int64(len(m) - 4) }
func (m Twstat) Fid() uint32    { return binary.LittleEndian.Uint32(m[3:7]) }
func (m Twstat) Stat() Stat     { return msg(m).nthField(3, 0) }
func (m Twstat) String() string { return fmt.Sprintf("Twstat fid=%x stat=%q", m.Fid(), m.Stat()) }

type Rwstat msg

func (m Rwstat) Tag() uint16    { return msg(m).Tag() }
func (m Rwstat) Len() int64     { return int64(len(m) - 4) }
func (m Rwstat) String() string { return "Rwstat" }

// The Rread message returns the bytes requested by a Tread message.
// To present the data portion of the message, Rread messages implement
// the io.ReadCloser interface.
type Rread struct {
	io.ReadCloser
	msg msg
}

// If a Tread requests asks for more data than can fit within a single 9P
// message, multiple Rread messages will be generated that cite the tag
// of a single Tread request.
func (m Rread) Tag() uint16   { return m.msg.Tag() }
func (m Rread) Len() int64    { return m.msg.Len() }
func (m Rread) Count() uint32 { return guint32(m.msg[3:7]) }

func (m Rread) String() string {
	return fmt.Sprintf("Rread count=%d", m.Count())
}

// The Twrite message is sent by a client to write data to a file. Twrite
// messages implement the io.ReadCloser interface for accessing
// the data portion of the message.
type Twrite struct {
	io.ReadCloser
	msg msg
}

func (m Twrite) Tag() uint16   { return m.msg.Tag() }
func (m Twrite) Len() int64    { return m.msg.Len() }
func (m Twrite) Fid() uint32   { return guint32(m.msg[3:7]) }
func (m Twrite) Offset() int64 { return int64(guint64(m.msg[7:15])) }
func (m Twrite) Count() uint32 { return guint32(m.msg[15:19]) }

func (m Twrite) String() string {
	return fmt.Sprintf("Twrite fid=%x offset=%d count=%d",
		m.Fid(), m.Offset(), m.Count())
}

// BadMessage represents an invalid message.
type BadMessage struct {
	Err error  // the reason the message is invalid
	tag uint16 // the tag of the errant message
	msg msg
}

// Tag returns the tag of the errant message. Servers
// should cite the same tag when replying with an Rerror
// message.
func (m BadMessage) Tag() uint16 { return m.tag }
func (m BadMessage) Len() int64  { return m.msg.Len() }

func (m BadMessage) String() string {
	return fmt.Sprintf("bad message: %v", m.Err)
}