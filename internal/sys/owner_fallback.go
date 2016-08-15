//+build !android,!darwin,!dragonfly,!freebsd,!linux,!nacl,!netbsd,!openbsd,!solaris,!plan9

package sys

func fileOwner(v interface{}) (uid, gid, muid string) {
	return DefaultUid, DefaultGid, DefaultUid
}
