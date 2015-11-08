package styx

import (
	"encoding/binary"
	"fmt"
)

// A Qid represents the server's unique identification for the file
// being accessed: two files on the same server hierarchy are the same
// if and only if their qids are the same.
type Qid []byte

// Type returns the type of a file (directory, etc)
func (q Qid) Type() QidType { return QidType(q[0]) }

// Version is a version number for a file; typically, it is incremented
// every time a file is modified.
func (q Qid) Version() uint32 { return binary.LittleEndian.Uint32(q[1:5]) }

// Path is an integer unique among all files in the hierarchy. If a
// file is deleted and recreated with the same name in the same
// directory, the old and new path components of the qids should be
// different.
func (q Qid) Path() uint64 { return binary.LittleEndian.Uint64(q[5:13]) }

func (q Qid) String() string {
	return fmt.Sprintf("type=%d ver=%d path=%d", q.Type(), q.Version(), q.Path())
}

// A QidType represents the type of a file (directory, etc.), represented
// as a bit vector corresponding to the high 8 bits of the file's mode
// word.
type QidType uint8

const (
	QTDIR    QidType = 0x80 // directories
	QTAPPEND QidType = 0x40 // append only files
	QTEXCL   QidType = 0x20 // exclusive use files
	QTMOUNT  QidType = 0x10 // mounted channel
	QTAUTH   QidType = 0x08 // authentication file (afid)
	QTTMP    QidType = 0x04 // non-backed-up file
	QTFILE   QidType = 0x00
)
