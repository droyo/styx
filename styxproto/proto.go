package styxproto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"aqwari.net/net/styx/internal"
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

	// The underlying bytes
	bytes() []byte
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
func (m Tversion) bytes() []byte { return m }

// Msize returns the maximum length, in bytes, that the client will
// ever generate or expect to receive in a single 9P message. This
// count includes all 9P protocol data, starting from the size field
// and extending through the message, but excludes enveloping transport
// protocols.
func (m Tversion) Msize() int64 { return int64(guint32(m[7:11])) }

// Version identifies the level of the protocol that the client supports.
// The string must always begin with the two characters "9P".
func (m Tversion) Version() []byte { return msg(m).nthField(11, 0) }

// WriteTversion writes a Tversion message to w.
func WriteTversion(w io.Writer, msize uint32, version string) (int, error) {
	if len(version) > MaxVersionLen {
		return 0, errLongVersion
	}
	size := uint32(minSizeLUT[msgTversion] + len(version))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTversion, NoTag, msize)
	pstring(ew, version)
	return ew.N, ew.Err
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
func (m Rversion) bytes() []byte { return m }

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

// WriteRversion writes a Rversion message to w.
func WriteRversion(w io.Writer, msize uint32, version string) (int, error) {
	if len(version) > MaxVersionLen {
		return 0, errLongVersion
	}
	size := uint32(minSizeLUT[msgRversion] + len(version))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRversion, NoTag, msize)
	pstring(ew, version)
	return ew.N, ew.Err
}

func (m Rversion) String() string {
	return fmt.Sprintf("Rversion msize=%d version=%q", m.Msize(), m.Version())
}

// The Tauth message is used to authenticate users on a connection.
type Tauth []byte

func (m Tauth) Tag() uint16   { return msg(m).Tag() }
func (m Tauth) Len() int64    { return msg(m).Len() }
func (m Tauth) nbytes() int64 { return msg(m).nbytes() }
func (m Tauth) bytes() []byte { return m }

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

// WriteTauth writes a Tauth message to w. The uname and aname
// parameters must be shorter than MaxUidLen and MaxAttachLen,
// respectively.
func WriteTauth(w io.Writer, tag uint16, afid uint32, uname, aname string) (int, error) {
	if len(uname) > MaxUidLen {
		return 0, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return 0, errLongAname
	}
	size := uint32(minSizeLUT[msgTauth] + len(uname) + len(aname))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTauth, tag, afid)
	pstring(ew, uname, aname)
	return ew.N, ew.Err
}

func (m Tauth) String() string {
	return fmt.Sprintf("Tauth afid=%d uname=%q aname=%q", m.Afid(), m.Uname(), m.Aname())
}

// Servers that require authentication will reply to Tauth requests
// with an Rauth message. If a server does not require authentication,
// it can reply to a Tauth message with an Rerror message.
type Rauth []byte

func (m Rauth) Tag() uint16   { return msg(m).Tag() }
func (m Rauth) Len() int64    { return msg(m).Len() }
func (m Rauth) nbytes() int64 { return msg(m).nbytes() }
func (m Rauth) bytes() []byte { return m }

// The aqid of an Rauth message must be of type QTAUTH.
func (m Rauth) Aqid() Qid      { return Qid(m[7:20]) }
func (m Rauth) String() string { return fmt.Sprintf("Rauth aqid=%q", m.Aqid()) }

// WriteRauth writes a new Rauth message to w.
func WriteRauth(w io.Writer, tag uint16, qid Qid) (int, error) {
	size := uint32(maxSizeLUT[msgRauth])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRauth, tag)
	pqid(ew, qid)
	return ew.N, ew.Err
}

// The attach message serves as a fresh introduction from a  user on
// the client machine to the server.
type Tattach []byte

func (m Tattach) Tag() uint16   { return msg(m).Tag() }
func (m Tattach) Len() int64    { return msg(m).Len() }
func (m Tattach) nbytes() int64 { return msg(m).nbytes() }
func (m Tattach) bytes() []byte { return m }

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

// WriteTattach writes a new Tattach message to w. If the client does not want
// to authenticate, afid should be NoFid.
func WriteTattach(w io.Writer, tag uint16, fid, afid uint32, uname, aname string) (int, error) {
	if len(uname) > MaxUidLen {
		return 0, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return 0, errLongAname
	}
	size := uint32(minSizeLUT[msgTattach] + len(uname) + len(aname))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTattach, tag, fid, afid)
	pstring(ew, uname, aname)
	return ew.N, ew.Err
}

func (m Tattach) String() string {
	return fmt.Sprintf("Tattach fid=%d afid=%d uname=%q aname=%q",
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
func (m Rattach) bytes() []byte { return m }

// Qid is the qid of the root of the file tree. Qid is associated
// with the fid of the corresponding Tattach request.
func (m Rattach) Qid() Qid { return Qid(m[7:20]) }

// WriteRattach writes a new Rattach message to w.
func WriteRattach(w io.Writer, tag uint16, qid Qid) (int, error) {
	size := uint32(maxSizeLUT[msgRattach])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRattach, tag)
	pqid(ew, qid)
	return ew.N, ew.Err
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
func (m Rerror) bytes() []byte { return m }

// Ename is a UTF-8 string describing the error that occured.
func (m Rerror) Ename() []byte { return msg(m).nthField(7, 0) }

// WriteRerror writes a new Rerror message to w. Errfmt may
// be a printf-style format string, with values filled in from the
// argument list v. If the error string is longer than MaxErrorLen
// bytes, it is truncated.
func WriteRerror(w io.Writer, tag uint16, errfmt string, v ...interface{}) (int, error) {
	ename := errfmt
	if len(v) > 0 {
		ename = fmt.Sprintf(errfmt, v...)
	}
	if len(ename) > MaxErrorLen {
		ename = ename[:MaxErrorLen]
	}
	size := uint32(minSizeLUT[msgRerror] + len(ename))
	ew := &internal.ErrWriter{W: w}

	pheader(ew, size, msgRerror, tag)
	pstring(ew, ename)

	return ew.N, ew.Err
}

func (m Rerror) String() string { return fmt.Sprintf("Rerror ename=%q", m.Ename()) }

// When the response to a request is no longer needed, such as
// when a user interrupts a process doing a read(2), a Tflush
// request is sent to the server to purge the pending response.
type Tflush []byte

func (m Tflush) Tag() uint16   { return msg(m).Tag() }
func (m Tflush) Len() int64    { return msg(m).Len() }
func (m Tflush) nbytes() int64 { return msg(m).nbytes() }
func (m Tflush) bytes() []byte { return m }

// The message being flushed is identified by oldtag.
func (m Tflush) Oldtag() uint16 { return guint16(m[7:9]) }

// WriteTflush writes a new Tflush message to w.
func WriteTflush(w io.Writer, tag, oldtag uint16) (int, error) {
	size := uint32(maxSizeLUT[msgTflush])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTflush, tag)
	puint16(ew, oldtag)
	return ew.N, ew.Err
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
func (m Rflush) bytes() []byte { return m }

// WriteRflush writes a new Rflush message to w.
func WriteRflush(w io.Writer, tag uint16) (int, error) {
	size := uint32(maxSizeLUT[msgRflush])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRflush, tag)
	return ew.N, ew.Err
}

func (m Rflush) String() string { return "Rflush" }

// A Twalk message is used to descend a directory hierarchy.
type Twalk []byte

func (m Twalk) Tag() uint16   { return msg(m).Tag() }
func (m Twalk) Len() int64    { return msg(m).Len() }
func (m Twalk) nbytes() int64 { return msg(m).nbytes() }
func (m Twalk) bytes() []byte { return m }

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

// WriteTwalk writes a new Twalk message to w. An error is returned
// if wname is longer than MaxWElem elements, or if any single element in
// wname is longer than MaxFilenameLen bytes long.
func WriteTwalk(w io.Writer, tag uint16, fid, newfid uint32, wname ...string) (int, error) {
	if len(wname) > MaxWElem {
		return 0, errMaxWElem
	}
	size := uint32(minSizeLUT[msgTwalk])
	for _, v := range wname {
		if len(v) > MaxFilenameLen {
			return 0, errLongFilename
		}
		size += 2
		size += uint32(len(v))
	}
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTwalk, tag, fid, newfid)
	puint16(ew, uint16(len(wname)))
	pstring(ew, wname...)

	return ew.N, ew.Err
}

func (m Twalk) String() string {
	var buf [MaxWElem][]byte
	wname := buf[:0]

	for i := 0; i < m.Nwname(); i++ {
		wname = append(wname, m.Wname(i))
	}
	path := bytes.Join(wname, []byte("/"))
	return fmt.Sprintf("Twalk fid=%d newfid=%d %q", m.Fid(), m.Newfid(), path)
}

// An Rwalk message contains a server's reply to a successful
// Twalk request. If the first path in the corresponding Twalk request
// cannot be walked, an Rerror message is returned instead.
type Rwalk []byte

func (m Rwalk) Tag() uint16   { return msg(m).Tag() }
func (m Rwalk) Len() int64    { return msg(m).Len() }
func (m Rwalk) nbytes() int64 { return msg(m).nbytes() }
func (m Rwalk) bytes() []byte { return m }

// Nwqid must always be equal to or lesser than Nwname of the corresponding
// Twalk request. Only if Nwqid is equal to Nwname is the Newfid of
// the Twalk request established. Nwqid must always be greater than
// zero.
func (m Rwalk) Nwqid() int { return int(guint16(m[7:9])) }

// Wqid contains the Qid values of each path in the walk
// requested by the client, up to the first failure.
func (m Rwalk) Wqid(n int) Qid { return Qid(m[9+n*13 : 9+(n+1)*13]) }

// WriteRwalk writes a new Rwalk message to w. An error is returned if wqid
// has more than MaxWElem elements.
func WriteRwalk(w io.Writer, tag uint16, wqid ...Qid) (int, error) {
	if len(wqid) > MaxWElem {
		return 0, errMaxWElem
	}
	size := uint32(minSizeLUT[msgRwalk] + 13*len(wqid))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRwalk, tag)
	puint16(ew, uint16(len(wqid)))
	pqid(ew, wqid...)

	return ew.N, ew.Err
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
func (m Topen) bytes() []byte { return m }

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

// NewTopen writes a new Topen message to w.
func WriteTopen(w io.Writer, tag uint16, fid uint32, mode uint8) (int, error) {
	size := uint32(maxSizeLUT[msgTopen])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTopen, tag, fid)
	puint8(ew, mode)

	return ew.N, ew.Err
}

func (m Topen) String() string {
	return fmt.Sprintf("Topen fid=%d mode=%#o", m.Fid(), m.Mode())
}

// An Ropen message contains a servers response to a Topen
// request. An Ropen message is only sent if the server determined
// that the requesting user had the proper permissions required
// for the Topen to succeed, otherwise Rerror is returned.
type Ropen []byte

func (m Ropen) Tag() uint16   { return msg(m).Tag() }
func (m Ropen) Len() int64    { return msg(m).Len() }
func (m Ropen) nbytes() int64 { return msg(m).nbytes() }
func (m Ropen) bytes() []byte { return m }

// Qid contains the unique identifier of the opened file.
func (m Ropen) Qid() Qid { return Qid(m[7:20]) }

// The iounit field returned by open and create may be zero.  If it
// is not, it is the maximum number of bytes that are guaranteed to
// be read from or written to the file without breaking the I/O transfer
// into multiple 9P messages
func (m Ropen) IOunit() int64 { return int64(guint32(m[20:24])) }

// WriteRopen writes a new Ropen message to w.
func WriteRopen(w io.Writer, tag uint16, qid Qid, iounit uint32) (int, error) {
	size := uint32(maxSizeLUT[msgRopen])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRopen, tag)
	pqid(ew, qid)
	puint32(ew, iounit)

	return ew.N, ew.Err
}

func (m Ropen) String() string {
	return fmt.Sprintf("Ropen qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tcreate []byte

func (m Tcreate) Tag() uint16   { return msg(m).Tag() }
func (m Tcreate) Len() int64    { return msg(m).Len() }
func (m Tcreate) nbytes() int64 { return msg(m).nbytes() }
func (m Tcreate) bytes() []byte { return m }
func (m Tcreate) Fid() uint32   { return guint32(m[7:11]) }
func (m Tcreate) Name() []byte  { return msg(m).nthField(11, 0) }
func (m Tcreate) Perm() uint32 {
	// Would have been nice if Name came at the end
	offset := 11 + 2 + guint16(m[11:13])
	return guint32(m[offset : offset+4])
}
func (m Tcreate) Mode() uint8 { return m[len(m.Name())+17] }

// WriteTcreate writes a new Tcreate message to w.
func WriteTcreate(w io.Writer, tag uint16, fid uint32, name string, perm uint32, mode uint8) (int, error) {
	if len(name) > MaxFilenameLen {
		return 0, errLongFilename
	}
	size := uint32(minSizeLUT[msgTcreate] + len(name))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTcreate, tag, fid)
	pstring(ew, name)
	puint32(ew, perm)
	puint8(ew, mode)

	return ew.N, ew.Err
}

func (m Tcreate) String() string {
	return fmt.Sprintf("Tcreate fid=%d name=%q perm=%o mode=%#o",
		m.Fid(), m.Name(), m.Perm(), m.Mode())
}

type Rcreate []byte

func (m Rcreate) Tag() uint16   { return msg(m).Tag() }
func (m Rcreate) Len() int64    { return msg(m).Len() }
func (m Rcreate) nbytes() int64 { return msg(m).nbytes() }
func (m Rcreate) bytes() []byte { return m }
func (m Rcreate) Qid() Qid      { return Qid(m[7:20]) }
func (m Rcreate) IOunit() int64 { return int64(guint32(m[20:24])) }

// WriteRcreate writes a new Rcreate message to w.
func WriteRcreate(w io.Writer, tag uint16, qid Qid, iounit uint32) (int, error) {
	size := uint32(maxSizeLUT[msgRcreate])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRcreate, tag)
	pqid(ew, qid)
	puint32(ew, iounit)

	return ew.N, ew.Err
}

func (m Rcreate) String() string {
	return fmt.Sprintf("Rcreate qid=%q iounit=%d", m.Qid(), m.IOunit())
}

type Tread []byte

func (m Tread) Tag() uint16   { return msg(m).Tag() }
func (m Tread) Len() int64    { return msg(m).Len() }
func (m Tread) nbytes() int64 { return msg(m).nbytes() }
func (m Tread) bytes() []byte { return m }

// Fid is the handle of the file to read from.
func (m Tread) Fid() uint32 { return guint32(m[7:11]) }

// Offset is the starting point in the file from which to begin
// returning data.
func (m Tread) Offset() int64 { return int64(guint64(m[11:19])) }

// Count is the number of bytes to read from the file. Count
// cannot be more than the maximum value of a 32-bit unsigned
// integer.
func (m Tread) Count() int64 { return int64(guint32(m[19:23])) }

// WriteTread writes a new Tread message to w. An error is returned
// if count is greater than the maximum value of a 32-bit unsigned integer.
func WriteTread(w io.Writer, tag uint16, fid uint32, offset, count int64) (int, error) {
	if count > math.MaxUint32 {
		return 0, errMaxCount
	}
	size := uint32(maxSizeLUT[msgTread])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTread, tag, fid)
	puint64(ew, uint64(offset))
	puint32(ew, uint32(count))
	return ew.N, ew.Err
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
func (m Rread) bytes() []byte { return m.msg[:11] }
func (m Rread) Count() int64  { return int64(guint32(m.msg[7:11])) }

// WriteRread writes a new Rread message to w.  An error is returned if
// count exceeds the maximum size of a 9P message.
func WriteRread(w io.Writer, tag uint16, count int64, data io.Reader) (int, error) {
	if math.MaxUint32-int64(minSizeLUT[msgRread]) < count {
		return 0, errTooBig
	}
	size := uint32(minSizeLUT[msgRread]) + uint32(count)
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRread, tag, uint32(count))
	io.CopyN(ew, data, count)
	return ew.N, ew.Err
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
func (m Twrite) bytes() []byte { return m.msg[:23] }
func (m Twrite) Fid() uint32   { return Tread(m.msg).Fid() }
func (m Twrite) Offset() int64 { return Tread(m.msg).Offset() }
func (m Twrite) Count() int64  { return Tread(m.msg).Count() }

// WriteTwrite writes a Twrite message to w. An error is returned
// if the message cannot fit inside a single 9P message.
func WriteTwrite(w io.Writer, tag uint16, fid uint32, offset, count int64, data io.Reader) (int, error) {
	if math.MaxUint32-int64(minSizeLUT[msgTwrite]) < count {
		return 0, errTooBig
	}
	size := uint32(minSizeLUT[msgTwrite]) + uint32(count)
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTwrite, tag, fid)
	puint64(ew, uint64(offset))
	puint32(ew, uint32(count))
	io.CopyN(ew, data, count)
	return ew.N, ew.Err
}

func (m Twrite) String() string {
	return fmt.Sprintf("Twrite fid=%d offset=%d count=%d",
		m.Fid(), m.Offset(), m.Count())
}

type Rwrite []byte

func (m Rwrite) Tag() uint16   { return msg(m).Tag() }
func (m Rwrite) Len() int64    { return msg(m).Len() }
func (m Rwrite) nbytes() int64 { return msg(m).nbytes() }
func (m Rwrite) bytes() []byte { return m }
func (m Rwrite) Count() uint32 { return guint32(m[7:11]) }

// WriteRwrite writes an Rwrite message to w. An error is returned
// if count is greater than the maximum value of a 32-bit unsigned
// integer.
func WriteRwrite(w io.Writer, tag uint16, count int64) (int, error) {
	if count > math.MaxUint32 {
		return 0, errMaxCount
	}
	size := uint32(maxSizeLUT[msgRwrite])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRwrite, tag, uint32(count))

	return ew.N, ew.Err
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
func (m Tclunk) bytes() []byte { return m }
func (m Tclunk) Fid() uint32   { return guint32(m[7:11]) }

// WriteTclunk writes a Tclunk message to w.
func WriteTclunk(w io.Writer, tag uint16, fid uint32) (int, error) {
	size := uint32(maxSizeLUT[msgTclunk])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTclunk, tag, fid)
	return ew.N, ew.Err
}
func (m Tclunk) String() string { return fmt.Sprintf("Tclunk fid=%d", m.Fid()) }

type Rclunk []byte

func (m Rclunk) Tag() uint16   { return msg(m).Tag() }
func (m Rclunk) Len() int64    { return msg(m).Len() }
func (m Rclunk) nbytes() int64 { return msg(m).nbytes() }
func (m Rclunk) bytes() []byte { return m }

// WriteRclunk writes an Rclunk message to w.
func WriteRclunk(w io.Writer, tag uint16) (int, error) {
	size := uint32(maxSizeLUT[msgRclunk])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRclunk, tag)
	return ew.N, ew.Err
}
func (m Rclunk) String() string { return "Rclunk" }

type Tremove []byte

func (m Tremove) Tag() uint16   { return msg(m).Tag() }
func (m Tremove) Len() int64    { return msg(m).Len() }
func (m Tremove) nbytes() int64 { return msg(m).nbytes() }
func (m Tremove) bytes() []byte { return m }
func (m Tremove) Fid() uint32   { return guint32(m[7:11]) }

// WriteTremove writes a Tremove message to w.
func WriteTremove(w io.Writer, tag uint16, fid uint32) (int, error) {
	size := uint32(maxSizeLUT[msgTremove])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTremove, tag, fid)
	return ew.N, ew.Err
}
func (m Tremove) String() string { return fmt.Sprintf("Tremove fid=%d", m.Fid()) }

type Rremove []byte

func (m Rremove) Tag() uint16   { return msg(m).Tag() }
func (m Rremove) Len() int64    { return msg(m).Len() }
func (m Rremove) nbytes() int64 { return msg(m).nbytes() }
func (m Rremove) bytes() []byte { return m }

// WriteRremove writes an Rremove message to w.
func WriteRremove(w io.Writer, tag uint16) (int, error) {
	size := uint32(maxSizeLUT[msgRremove])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRremove, tag)
	return ew.N, ew.Err
}
func (m Rremove) String() string { return "Rremove" }

type Tstat []byte

func (m Tstat) Tag() uint16   { return msg(m).Tag() }
func (m Tstat) Len() int64    { return msg(m).Len() }
func (m Tstat) nbytes() int64 { return msg(m).nbytes() }
func (m Tstat) bytes() []byte { return m }
func (m Tstat) Fid() uint32   { return guint32(m[7:11]) }

// WriteTstat writes a Tstat message to w.
func WriteTstat(w io.Writer, tag uint16, fid uint32) (int, error) {
	size := uint32(maxSizeLUT[msgTstat])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTstat, tag, fid)
	return ew.N, ew.Err
}
func (m Tstat) String() string { return fmt.Sprintf("Tstat fid=%d", m.Fid()) }

type Rstat []byte

func (m Rstat) Tag() uint16   { return msg(m).Tag() }
func (m Rstat) Len() int64    { return msg(m).Len() }
func (m Rstat) nbytes() int64 { return msg(m).nbytes() }
func (m Rstat) bytes() []byte { return m }
func (m Rstat) Stat() Stat    { return msg(m).nthField(7, 0) }

// WriteRstat writes an Rstat message to w.
func WriteRstat(w io.Writer, tag uint16, stat Stat) (int, error) {
	if len(stat) > maxStatLen {
		return 0, errLongStat
	}
	if len(stat) < minStatLen {
		return 0, errShortStat
	}
	size := uint32((minSizeLUT[msgRstat] - minStatLen) + len(stat))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRstat, tag)
	pbyte(ew, stat)

	return ew.N, ew.Err
}
func (m Rstat) String() string { return "Rstat " + m.Stat().String() }

type Twstat []byte

func (m Twstat) Tag() uint16   { return msg(m).Tag() }
func (m Twstat) Len() int64    { return msg(m).Len() }
func (m Twstat) nbytes() int64 { return msg(m).nbytes() }
func (m Twstat) bytes() []byte { return m }
func (m Twstat) Fid() uint32   { return guint32(m[7:11]) }
func (m Twstat) Stat() Stat    { return msg(m).nthField(7, 0) }

// WriteTwstat writes a Twstat message to w.
func WriteTwstat(w io.Writer, tag uint16, fid uint32, stat Stat) (int, error) {
	if len(stat) > maxStatLen {
		return 0, errLongStat
	}
	if len(stat) < minStatLen {
		return 0, errShortStat
	}
	size := uint32(minSizeLUT[msgTwstat] + len(stat))
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgTwstat, tag)
	pbyte(ew, stat)
	return ew.N, ew.Err
}
func (m Twstat) String() string { return fmt.Sprintf("Twstat fid=%d stat=%q", m.Fid(), m.Stat()) }

type Rwstat []byte

func (m Rwstat) Tag() uint16   { return msg(m).Tag() }
func (m Rwstat) Len() int64    { return msg(m).Len() }
func (m Rwstat) nbytes() int64 { return msg(m).nbytes() }
func (m Rwstat) bytes() []byte { return m }

// WriteRwstat writes an Rwstat message to w.
func WriteRwstat(w io.Writer, tag uint16) (int, error) {
	size := uint32(maxSizeLUT[msgRwstat])
	ew := &internal.ErrWriter{W: w}
	pheader(ew, size, msgRwstat, tag)
	return ew.N, ew.Err
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
func (m BadMessage) bytes() []byte  { return nil }
func (m BadMessage) String() string { return fmt.Sprintf("bad message: %v", m.Err) }
