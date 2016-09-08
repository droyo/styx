package styxfile

import (
	"os"

	"aqwari.net/net/styx/styxproto"
)

// FileMode converts a 9P mode mask to an os.FileMode.
func ModeOS(perm uint32) os.FileMode {
	var mode os.FileMode
	if perm&styxproto.DMDIR != 0 {
		mode = os.ModeDir
	}
	if perm&styxproto.DMAPPEND != 0 {
		mode |= os.ModeAppend
	}
	if perm&styxproto.DMEXCL != 0 {
		mode |= os.ModeExclusive
	}
	if perm&styxproto.DMTMP != 0 {
		mode |= os.ModeTemporary
	}
	mode |= (os.FileMode(perm) & os.ModePerm)
	return mode
}

// Mode9P converts an os.FileMode to a 9P mode mask
func Mode9P(mode os.FileMode) uint32 {
	var perm uint32
	if mode&os.ModeDir != 0 {
		perm |= styxproto.DMDIR
	}
	if mode&os.ModeAppend != 0 {
		perm |= styxproto.DMAPPEND
	}
	if mode&os.ModeExclusive != 0 {
		perm |= styxproto.DMEXCL
	}
	if mode&os.ModeTemporary != 0 {
		perm |= styxproto.DMTMP
	}
	return perm | uint32(mode&os.ModePerm)
}

// QidType selects the first byte of a 9P mode mask,
// and is suitable for use in a Qid's type field.
func QidType(mode uint32) uint8 {
	return uint8(mode >> 24)
}
