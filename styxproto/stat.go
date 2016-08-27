package styxproto

import (
	"fmt"
	"io"
)

// The Stat structure describes a directory entry. It is contained in
// Rstat and Twstat messages. Tread requests on directories return
// a Stat structure for each directory entry. A Stat implements the
// os.FileInfo interface.
type Stat []byte

// The 2-byte type field contains implementation-specific data
// that is outside the scope of the 9P protocol.
func (s Stat) Type() uint16     { return guint16(s[2:4]) }
func (s Stat) SetType(t uint16) { buint16(s[2:4], t) }

// The 4-byte dev field contains implementation-specific data
// that is outside the scope of the 9P protocol. In Plan 9, it holds
// an identifier for the block device that stores the file.
func (s Stat) Dev() uint32     { return guint32(s[4:8]) }
func (s Stat) SetDev(d uint32) { buint32(s[4:8], d) }

// Qid returns the unique identifier of the file.
func (s Stat) Qid() Qid     { return Qid(s[8:21]) }
func (s Stat) SetQid(q Qid) { copy(s[8:21], q) }

// Mode contains the permissions and flags set for the file.
// Permissions follow the unix model; the 3 least-significant
// 3-bit triads describe read, write, and execute access for
// owners, group members, and other users, respectively.
func (s Stat) Mode() uint32     { return guint32(s[21:25]) }
func (s Stat) SetMode(m uint32) { buint32(s[21:25], m) }

// Atime returns the last access time for the file, in seconds since the epoch.
func (s Stat) Atime() uint32     { return guint32(s[25:29]) }
func (s Stat) SetAtime(t uint32) { buint32(s[25:29], t) }

// Mtime returns the last time the file was modified, in seconds since the epoch.
func (s Stat) Mtime() uint32     { return guint32(s[29:33]) }
func (s Stat) SetMtime(t uint32) { buint32(s[29:33], t) }

// Length returns the length of the file in bytes.
func (s Stat) Length() int64     { return int64(guint64(s[33:41])) }
func (s Stat) SetLength(n int64) { buint64(s[33:41], uint64(n)) }

// Name returns the name of the file.
func (s Stat) Name() []byte { return nthField(s, statFixedSize, 0) }

// Uid returns the name of the owner of the file.
func (s Stat) Uid() []byte { return nthField(s, statFixedSize, 1) }

// Gid returns the group of the file.
func (s Stat) Gid() []byte { return nthField(s, statFixedSize, 2) }

// Muid returns the name of the user who last modified the file
func (s Stat) Muid() []byte { return nthField(s, statFixedSize, 3) }

func (s Stat) String() string {
	return fmt.Sprintf("type=%x dev=%x qid=%q mode=%o atime=%d "+
		"mtime=%d length=%d name=%q uid=%q gid=%q muid=%q",
		s.Type(), s.Dev(), s.Qid(), s.Mode(), s.Atime(), s.Mtime(),
		s.Length(), s.Name(), s.Uid(), s.Gid(), s.Muid())
}

// NewStat creates a new Stat structure. The name, uid, gid, and muid
// fields affect the size of the stat-structure and should be considered
// read-only once the Stat is created. An error is returned if name is
// more than MaxFilenameLen bytes long or uid, gid, or muid are more
// than MaxUidLen bytes long. Additional fields in the Stat structure
// can be set by using the appropriate Set method on the Stat value.
func NewStat(buf []byte, name, uid, gid, muid string) (Stat, []byte, error) {
	if len(uid) > MaxUidLen || len(gid) > MaxUidLen || len(muid) > MaxUidLen {
		return nil, buf, errLongUsername
	}
	if len(buf) < minStatLen+len(uid)+len(gid)+len(muid) {
		return nil, buf, io.ErrShortBuffer
	}

	b := buf[41:]
	buint16(b, uint16(len(name)))
	b = b[2:]
	b = b[copy(b, name):]

	buint16(b, uint16(len(uid)))
	b = b[2:]
	b = b[copy(b, uid):]

	buint16(b, uint16(len(gid)))
	b = b[2:]
	b = b[copy(b, gid):]

	buint16(b, uint16(len(muid)))
	b = b[2:]
	b = b[copy(b, muid):]

	length := len(buf) - len(b)
	buint16(buf[:2], uint16(length-2))
	return Stat(buf[:length]), b, nil
}

// verifyStat ensures that a Stat structure is valid and safe to use
// as a Stat. This *must* be called on all received Stats, otherwise
// there is no guarantee that a bad actor threw in some illegal sizes
// or strings.
//
// From stat(5):
//
// A wstat request can avoid modifying some properties of the file by
// providing explicit ``don't touch'' values in the stat data that is sent:
// zero-length strings for text values and the maximum unsigned value of
// appropriate size for integral values.
func verifyStat(data []byte) error {
	var field []byte

	// type[2] dev[4] qid[13] mod[4] atime[4]
	// mtime[4] length[8] name[s] uid[s] gid[s] muid[s]
	if len(data) < minStatLen {
		return errShortStat
	} else if len(data) > MaxStatLen {
		return errLongStat
	}

	const sizeHeaders = 2 * 4 // name[s], uid[s], gid[s], muid[s], 2-byte length headers each
	name, rest, err := verifyField(data[statFixedSize:], false, sizeHeaders-2)
	if err != nil {
		return err
	} else if err := verifyPathElem(name); err != nil {
		return err
	} else if len(name) > MaxFilenameLen {
		return errLongFilename
	}

	for i := 0; i < 3; i++ {
		padding := 4 - i*2
		field, rest, err = verifyField(rest, i == 2, padding)
		if err != nil {
			return err
		} else if err := verifyString(field); err != nil {
			return err
		} else if len(field) > MaxUidLen {
			return errLongUsername
		}
		if len(rest) < padding {
			return errOverSize
		}
	}
	return nil
}
