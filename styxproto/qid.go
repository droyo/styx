package styxproto

import (
	"fmt"
	"io"
)

// A Qid represents the server's unique identification for the file
// being accessed: two files on the same server hierarchy are the same
// if and only if their qids are the same.
type Qid []byte

// NewQid writes the 9P representation of a Qid to buf. If buf is
// not long enough to hold a Qid (13 bytes), io.ErrShortBuffer is
// returned. NewQid returns any remaining space in buf after
// the Qid has been written.
func NewQid(buf []byte, qtype uint8, version uint32, path uint64) (Qid, []byte, error) {
	if len(buf) < 13 {
		return nil, buf, io.ErrShortBuffer
	}

	buf[0] = qtype
	buint32(buf[1:5], version)
	buint64(buf[5:13], path)

	return Qid(buf[:13]), buf[13:], nil
}

// Type returns the type of a file (directory, etc)
func (q Qid) Type() uint8 { return q[0] }

// Version is a version number for a file; typically, it is incremented
// every time a file is modified. By convention, synthetic files usually
// have a verison number of 0. Traditional files have a version number
// that is a hash of their modification time.
func (q Qid) Version() uint32 { return guint32(q[1:5]) }

// Path is an integer unique among all files in the hierarchy. If a
// file is deleted and recreated with the same name in the same
// directory, the old and new path components of the qids should be
// different.
func (q Qid) Path() uint64 { return guint64(q[5:13]) }

func (q Qid) String() string {
	return fmt.Sprintf("type=%d ver=%d path=%x", q.Type(), q.Version(), q.Path())
}

// A Qid's type field represents the type of a file (directory, etc.), represented
// as a bit vector corresponding to the high 8 bits of the file's mode
// word.
const (
	QTDIR    = 0x80 // directories
	QTAPPEND = 0x40 // append only files
	QTEXCL   = 0x20 // exclusive use files
	QTMOUNT  = 0x10 // mounted channel
	QTAUTH   = 0x08 // authentication file (afid)
	QTTMP    = 0x04 // non-backed-up file
	QTFILE   = 0x00
)
