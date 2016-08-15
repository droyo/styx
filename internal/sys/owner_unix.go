// +build android darwin dragonfly freebsd linux nacl netbsd openbsd solaris

package sys

import (
	"os/user"
	"strconv"
	"syscall"
)

func fileOwner(v interface{}) (uid, gid, muid string) {
	uid = DefaultUid
	gid = DefaultGid
	muid = DefaultGid

	stat, ok := v.(*syscall.Stat_t)
	if !ok {
		return
	}

	uid = strconv.Itoa(int(stat.Uid))
	gid = strconv.Itoa(int(stat.Gid))
	muid = uid

	if u, err := user.Lookup(uid); err == nil {
		uid = u.Name
		muid = u.Name
	}

	if g, err := groupLookup(gid); err == nil {
		gid = g
	}
	return uid, gid, muid
}
