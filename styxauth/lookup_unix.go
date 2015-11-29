package styxauth

/*
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

// helper function to resolve a group name to gid
func lookupGid(name string) (string, error) {
	var (
		bufSize C.long
		rv      C.int
		grp     C.struct_group
		result  *C.struct_group
	)

	bufSize := C.sysconf(C._SC_GETGR_R_SIZE_MAX)
	if bufSize < 0 {
		// FreeBSD doesn't have _SC_GETPW_R_SIZE_MAX
		// or SC_GETGR_R_SIZE_MAX and just returns -1.
		// So just use the same size that Linux returns
		bufSize = 1024
	}
	buf := C.malloc(C.size_t(bufSize))
	defer C.free(buf)

	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	rv = C.getgrnam_r(nameC, &grp, (*C.char)(buf), C.size_t(bufSize), &result)
	if rv != 0 {
		return "", fmt.Errorf("lookup group %s: %s", name, syscall.Errno(rv))
	}
	if result == nil {
		return "", fmt.Errorf("unknown group %s", name)
	}

	return strconv.Itoa(int(grp.gr_gid)), nil
}
