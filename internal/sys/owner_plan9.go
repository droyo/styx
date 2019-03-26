package sys

import (
	"syscall"
)

func fileOwner(v interface{}) (uid, gid, muid string) {
	uid = DefaultUid
	gid = DefaultGid
	muid = DefaultMuid

	stat, ok := v.(*syscall.Dir)
	if !ok {
		return
	}

	// This is pretty easy, it's almost like this OS
	// was made for 9P :D
	return stat.Uid, stat.Gid, stat.Muid
}
