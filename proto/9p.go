package proto

import (
	"encoding/binary"
	"time"
)

var (
	guint16 = binary.LittleEndian.Uint16
	guint32 = binary.LittleEndian.Uint32
	guint64 = binary.LittleEndian.Uint64
)

func nthString(p msg, offset, n int) string {
	x := p[offset:]
	size := int(guint16(x[:2]))

	for i := 0; i < n; i++ {
		x = x[size+2:]
		size = int(guint16(x[:2]))
	}
	return string(x[2 : size+2])
}

func msgSize(m msg) int64 {
	return int64(guint32(m[:4]))
}

func msgTag(m msg) uint16 {
	return guint16(m[5:7])
}

// The private `msg` type is used to discourage
// users from declaring the various types in this
// package with arbitrary byte slices.
type msg []byte

// A Qid is a unique identifier chosen by the server
// for a single object in the file system. Multiple
// Fids may refer to the same Qid.
type Qid []byte

func (q Qid) Type() uint8     { return q[0] }
func (q Qid) Version() uint32 { return guint32(q[1:5]) }
func (q Qid) Path() uint64    { return guint64(q[5:13]) }

// A Dir describes a directory entry. A single Stat
// is returned from a Tstat call, and a list of Stats
// is returned when reading a directory. A Stat
// must be created by the ParseStat or NewStat
// function.
type Dir []byte

func (s Dir) Size() int        { return int(guint16(s[0:2])) }
func (s Dir) Type() uint16     { return guint16(s[2:4]) }
func (s Dir) Dev() uint32      { return guint32(s[4:8]) }
func (s Dir) Qid() Qid         { return Qid(s[8:21]) }
func (s Dir) Mode() uint32     { return guint32(s[21:25]) }
func (s Dir) Atime() time.Time { return time.Unix(int64(guint32(s[25:29])), 0) }
func (s Dir) Mtime() time.Time { return time.Unix(int64(guint32(s[29:33])), 0) }
func (s Dir) Length() uint64   { return guint64(s[33:37]) }
func (s Dir) Name() string     { return nthString(msg(s), 37, 0) }
func (s Dir) Uid() string      { return nthString(msg(s), 37, 1) }
func (s Dir) Gid() string      { return nthString(msg(s), 37, 2) }
func (s Dir) Muid() string     { return nthString(msg(s), 37, 3) }

// An Fcall is a 9P protocol message
type Fcall interface {
	// Size returns the size in bytes of the 9P message on
	// the wire.
	Size() int64

	// Tag is an identifier chosen by the client for a request.
	// Tags must be unique among all pending requests.
	// Replies must reference the tag of the request.
	Tag() uint16

	// Returns the underyling byte slice
	bytes() []byte
}

// A Tversion request is sent by the client when a connection
// is created and initializes the connection for I/O. It must be
// the first request sent by the client, and is of the form
//
// 	size[4] Tversion tag[2] msize[4] version[s]
//
// If a Tversion request is sent on an already-initialized
// connection, all outstanding I/O on the connection is aborted,
// and all active fids are freed. The set of messages between
// version requests is called a session.
type Tversion msg

func (t Tversion) Size() int64     { return msgSize(msg(t)) }
func (t Tversion) Tag() uint16     { return msgTag(msg(t)) }
func (t Tversion) MaxSize() int64  { return int64(guint32(t[7:11])) }
func (t Tversion) Version() string { return nthString([]byte(t), 11, 0) }

// A Tauth request is used to authenticate a user on a connection.
// It is of the form
//
// 	size[4] Tauth tag[2] afid[4] uname[s] aname[s]
//
// The client can use IO operations on afid to authenticate itself. The
// authentication protocol used is outside the scope of the 9P protocol.
// After authentication is complete, the client can use afid in a later
// Tattach request, which will give the new user an entry point into the
// file system.
type Tauth msg

func (t Tauth) Size() int64   { return msgSize(msg(t)) }
func (t Tauth) Tag() uint16   { return msgTag(msg(t)) }
func (t Tauth) Afid() uint32  { return guint32(t[7:11]) }
func (t Tauth) Uname() string { return nthString(msg(t), 11, 0) }
func (t Tauth) Aname() string { return nthString(msg(t), 11, 1) }

// A Tattach request is used to grant a user entry into a
// file system. It is of the form
//
// 	size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
//
// The afid must have been previously established
// in a Tauth request, and the authentication protocol must
// be completed before the Tattach request is made.
// If authorized, fid will be associated with the root of the
// requested tree.
type Tattach msg

func (t Tattach) Size() int64   { return msgSize(msg(t)) }
func (t Tattach) Tag() uint16   { return msgTag(msg(t)) }
func (t Tattach) Fid() uint32   { return guint32(t[7:11]) }
func (t Tattach) Afid() uint32  { return guint32(t[11:15]) }
func (t Tattach) Uname() string { return nthString(msg(t), 15, 0) }
func (t Tattach) Aname() string { return nthString(msg(t), 15, 0) }

// A Twalk request descends each directory in the path to a given
// file and associates newfid with the file. The requesting user
// must have permission to read each directory in the path to
// the file. Before performing I/O on the file, the client must
// complete an open request.
type Twalk msg

func (t Twalk) Size() int64    { return msgSize(msg(t)) }
func (t Twalk) Tag() uint16    { return msgTag(msg(t)) }
func (t Twalk) Fid() uint32    { return guint32(t[7:11]) }
func (t Twalk) Newfid() uint32 { return guint32(t[11:15]) }

func (t Twalk) Wname() []string {
	var buf [MAXWELEM]string
	var s = buf[:0]

	count := guint16(t[15:17])
	for i := 0; i < count; i++ {
		s = append(s, nthString(msg(t, 17, i)))
	}
	return s
}

// A Topen requests prepares a file for I/O. It is of the
// form
//
// 	size[4] Topen tag[2] fid[4] mode[1]
//
// Fid must have been obtained by a previous Twalk
// or Tattach request.
type Topen msg

func (t Topen) Size() int64 { return msgSize(msg(t)) }
func (t Topen) Tag() uint16 { return msgTag(msg(t)) }
func (t Topen) Fid() uint32 { return guint32(t[7:11]) }
func (t Topen) Mode() uint8 { return uint8(t[15]) }

// A Tcreate request creates a new file in the directory
// associated with fid. It is of the form
//
// 	size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
//
//
type Tcreate msg

func (t Tcreate) Size() int64  { return msgSize(msg(t)) }
func (t Tcreate) Tag() uint16  { return msgTag(msg(t)) }
func (t Tcreate) Fid() uint32  { return guint32(t[7:11]) }
func (t Tcreate) Name() string { return nthString(msg(t), 11, 0) }

// TODO
func (t Tcreate) Perm() uint32 { return 0 }

// TODO
func (t Tcreate) Mode() uint8 { return 0 }
