package sys

import (
	"os"

	"aqwari.net/net/styx/styxproto"
)

// DefaultUid and DefaultGid are the default group and owner for a file if
// ownership information cannot be retrieved.
const (
	DefaultUid  = ""
	DefaultGid  = ""
	DefaultMuid = ""
)

type hasUid interface {
	Uid() string
}
type hasGid interface {
	Gid() string
}
type hasMuid interface {
	Muid() string
}

// FileOwner retrieves ownership information for a file.  uid and gid are
// the owner and group of a file, respectively.  muid is the uid of the
// user who last modified the file.
//
// FileOwner will emply multiple strategies to get file ownership
// information. If fi or fi.Sys() implements any methods in the
// styx.OwnerInfo interface, they are used. Otherwise, FileOwner will attempt
// to retrieve ownership information from the host operating sytsem. If such
// information cannot be retrieved, FileOwner will fall back to DefaultUid
// and DefaultGid.
func FileOwner(fi os.FileInfo) (uid, gid, muid string) {
	var ok bool
	if uid, gid, muid, ok = ownerInfo(fi); ok {
		return
	}
	if uid, gid, muid, ok = ownerInfo(fi.Sys()); ok {
		return
	}
	if v, ok := fi.Sys().(styxproto.Stat); ok {
		return string(v.Uid()), string(v.Gid()), string(v.Muid())
	}
	// fall back to OS
	return fileOwner(fi.Sys())
}

func ownerInfo(v interface{}) (uid, gid, muid string, ok bool) {
	meets := false
	if v, ok := v.(hasUid); ok {
		meets = true
		uid = v.Uid()
		muid = v.Uid()
	}
	if v, ok := v.(hasGid); ok {
		gid = v.Gid()
	}
	if v, ok := v.(hasMuid); ok {
		muid = v.Muid()
	}
	return uid, gid, muid, meets
}
