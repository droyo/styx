// Package styxmount mounts a 9P filesystem onto a directory.
//
// The styxmount package provides a uniform interface for mounting
// 9P file systems to the local file namespace using the Host operating
// system's support for user-space filesystems. While the usage of the
// styxmount package does not change, its implementation and caveats
// vary with the operating system in use.
//
// For Plan 9, the normal "mount" command is used.
//
// For Linux, FreeBSD, and netBSD FUSE is used.
//
// For Windows and OS X, styxmount translates 9P to WebDAV and
// uses the operating systems' support for mounting WebDAV endpoints.
package styxmount

import (
	"errors"
	"io"
)

// Mount binds the 9P filesystem served on rwc to a directory
// on the local filesystem. After Mount returns succesfully,
// the user will be able to access resources on the 9P file server
// as if they were files on their filesystem. Mount returns any
// errors encountered while trying to setup the bind.
func Mount(rwc io.ReadWriteCloser, dir string, opt ...Option) error {
	var cfg config

	return errors.New("TODO")
}

type config struct {
}

// NOTE(droyo) I don't *need* the Option type to be self-referential,
// as I don't see a use case for changing options back. However,
// Making the function return an Option lets you know it is an Option,
// and also causes godoc to group all of the options together, which
// is definitely worth the extra work.

// An Option is used to change various parameters for the mount.
// Note that the set of options supported by each operating system
// may not be the same.
type Option func(*config) Option
