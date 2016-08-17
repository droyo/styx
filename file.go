package styx

import (
	"os"

	"aqwari.net/net/styx/internal/styxfile"
)

type file struct {
	rwc  styxfile.Interface
	name string

	// This is an afid, used for authentication
	auth bool
}

// The styx package will attempt to determine the ownership of a file by
// asking the host operating system, if it is a real file. If a given type
// implements the OwnerInfo interface, the styx package will use the methods
// therein to determine file ownership. Uid should return the user name of
// a file's owner. Gid should return the primary group of the file. Muid,
// if implemented, should return the name of the user who last modified the
// file. If Muid is not implemented, the styx package will always return
// the owner of the file for its Muid.
//
// Usage of this interface is opportunistic; a type can implement all or
// some of the methods.
type OwnerInfo interface {
	Uid() string
	Gid() string
	Muid() string
}

// In the 9P protocol, a directory is simply a file that returns zero or more
// styxproto.Stat structures when read. Types that implement the Directory
// interface can avoid marshalling styxproto.Stat methods in the Read methods.
// The Readdir method should return up to n os.FileInfo values, based on the
// contents of the given directory. Further calls to Readdir should pick up where
// the previous call left off.
//
// If n <= 0, Readdir should return os.FileInfo values for all files in the directory.
type Directory interface {
	Readdir(n int) ([]os.FileInfo, error)
}
