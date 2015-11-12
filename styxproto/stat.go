package styxproto

import (
	"encoding/binary"
	"fmt"

	"aqwari.net/net/styx"
)

// The Stat structure describes a directory entry. It is contained in
// Rstat and Twstat messages. Tread requests on directories return
// a Stat structure for each directory entry.
type Stat []byte

// Size returns the length (in bytes) of the stat structure, minus the
// two-byte size.
func (s Stat) Size() uint16 { return guint16(s[0:2]) }

// The 2-byte type field contains implementation-specific data
// that is outside the scope of the 9P protocol.
func (s Stat) Type() uint16 { return guint16(s[2:4]) }

// The 4-byte dev field contains implementation-specific data
// that is outside the scope of the 9P protocol. In Plan 9, it holds
// an identifier for the block device that stores the file.
func (s Stat) Dev() uint32 { return guint32(s[4:8]) }

// Qid returns the unique identifier of the file.
func (s Stat) Qid() styx.Qid { return styx.Qid(s[8:21]) }

// Mode contains the permissions and flags set for the file.
// Permissions follow the unix model; the 3 least-significant
// 3-bit triads describe read, write, and execute access for
// owners, group members, and other users, respectively.
func (s Stat) Mode() uint32 { return guint32(s[21:25]) }

// Atime returns the last access time for the file, in seconds since the epoch.
func (s Stat) Atime() uint32 { return binary.LittleEndian.Uint32(s[25:29]) }

// Mtime returns the last time the file was modified, in seconds since the epoch.
func (s Stat) Mtime() uint32 { return binary.LittleEndian.Uint32(s[29:33]) }

// Length returns the length of the file in bytes.
func (s Stat) Length() int64 { return int64(binary.LittleEndian.Uint64(s[33:41])) }

// Name returns the name of the file.
func (s Stat) Name() []byte { return msg(s).nthField(41, 0) }

// Uid returns the name of the owner of the file.
func (s Stat) Uid() []byte { return msg(s).nthField(41, 1) }

// Gid returns the group of the file.
func (s Stat) Gid() []byte { return msg(s).nthField(41, 2) }

// Muid returns the name of the user who last modified the file
func (s Stat) Muid() []byte { return msg(s).nthField(41, 3) }

func (s Stat) String() string {
	return fmt.Sprintf("type=%x dev=%x qid=%q mode=%o atime=%d mtime=%d "+
		"length=%d name=%q uid=%q gid=%q muid=%q", s.Type(), s.Dev(), s.Qid(),
		s.Mode(), s.Atime(), s.Mtime(), s.Length(), s.Name(), s.Uid(),
		s.Gid(), s.Muid())
}

// verifyStat ensures that a Stat structure is valid and safe to use
// as a Stat. This *must* be called on all received Stats, otherwise
// there is no guarantee that a bad actor threw in some illegal sizes
// or strings.
func verifyStat(data []byte) error {
	var field []byte

	// type[2] dev[4] qid[13] mod[4] atime[4] mtime[4] length[8] name[s] uid[s] gid[s] muid[s]
	if len(data) < minStatLen {
		return errShortStat
	} else if len(data) > maxStatLen {
		return errLongStat
	}
	if length := guint64(data[31:39]); length > MaxFileLen {
		return errLongLength
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
