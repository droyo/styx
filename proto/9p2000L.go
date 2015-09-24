// Linux-specific extensions to the 9P2000 protocol, as
// described in https://github.com/chaos/diod/blob/2d5ac46252e8a3bdf0489530390be5f060c0fa1c/protocol.md
package proto

// 9P2000.L message types
const (
	// lerror replaces the reply message used in a successful call.
	// ecode is a numerical Linux errno.
	Tlerror = 6
	Rlerror = 7

	// statfs is used to request file system information of the file
	// system containing fid. The Rstatfs response corresponds
	// to the fields returned by the statfs(2) system call
	Tstatfs = 8
	Rstatfs = 9

	// lopen prepares fid for file I/O. flags contains Linux
	// open(2) flags bits, e.g. O_RDONLY, O_RDWR,
	// O_WRONLY.
	Tlopen = 12
	Rlopen = 13

	// lcreate creates a regular file name in directory fid and
	// prepares it for I/O. Allows passing flags to the linux
	// kernel that normal create message does not.
	Tlcreate = 14
	Rlcreate = 15

	// symlink creates a symbolic link name in directory dfid.
	// The link will point to symtgt.
	Tsymlink = 16
	Rsymlink = 17

	// mknod creates a device node name in directory dfid
	// with major and minor numbers.
	Tmknod = 18
	Rmknod = 19

	// rename renames a file system object referenced by fid,
	// to name in the directory referenced by dfid. deprecated
	// by renameat
	Trename = 20
	Rrename = 21

	// readlink returns the contents of the symbolic link
	// referenced by fid.
	Treadlink = 22
	Rreadlink = 23

	// getattr gets attributes of a file system object
	// referenced by fid.
	Tgetattr = 24
	Rgetattr = 25

	// setattr sets attributes of a file system object referenced by fid.
	Tsetattr = 26
	Rsetattr = 27

	// xattrwalk - prepare to read/list extended attributes
	Txattrwalk = 30
	Rxattrwalk = 31

	// xattrcreate gets a fid pointing to the xattr name.
	// This fid can later be used to set the xattr value.
	Txattrcreate = 32
	Rxattrcreate = 33

	// readdir requests that the server return directory
	// entries from the directory represented by fid,
	// previously opened with lopen. offset is zero on the
	// first call.
	Treaddir = 40
	Rreaddir = 41

	// fsync tells the server to flush any cached data
	// associated with fid, previously opened with lopen.
	Tfsync = 50
	Rfsync = 51

	// lock is used to acquire or release a POSIX record
	// lock on fid and has semantics similar to Linux
	// fcntl(F_SETLK).
	Tlock = 52
	Rlock = 53

	// getlock tests for the existence of a POSIX record
	// lock and has semantics similar to Linux fcntl(F_GETLK).
	Tgetlock = 54
	Rgetlock = 55

	// link creates a hard link name in directory dfid. The
	// link target is referenced by fid.
	Tlink = 70
	Rlink = 71

	// mkdir creates a new directory name in parent
	// directory dfid.
	Tmkdir = 72
	Rmkdir = 73

	// Change the name of a file from oldname to newname,
	// possible moving it from old directory represented by
	// olddirfid to new directory represented by newdirfid.
	Trenameat = 74
	Rrenameat = 75

	// Unlink name from directory represented by dirfd.
	// If the file is represented by a fid, that fid is not clunked.
	// If the server returns ENOTSUPP, the client should fall
	// back to the remove operation.
	Tunlinkat = 76
	Runlinkat = 77
)
