//+build linux

package styxauth

import (
	"errors"
	"net"
	"os/user"
	"strconv"
	"syscall"

	"aqwari.net/net/styx"
)

// The SocketPeerID authentication method uses the underlying transport
// to authenticate users. The underlying connection must be a unix
// socket. The authentication method will obtain the user of the
// connecting process, and compare it to the user parameter in the
// authentication request.  Authentication fails if the user name does
// not match, or the underlying transport is not a unix socket.
var SocketPeerID authSocket

type authSocket struct{}

var (
	errSocketUser = errors.New("username of connecting process does not match request")
	errSocketConn = errors.New("underlying connection is not a unix socket")
)

func (authSocket) Auth(rw styx.Channel, user, _ string) error {
	connUid, _, err := getpeereid(rw.Transport())
	if err != nil {
		return errAuthFailure
	}
	reqUid, err := lookupUid(user)
	if err != nil {
		return err
	}

	if connUid == reqUid {
		return nil
	}
	return errAuthFailure
}

// Return the uid of a user as a string.
func lookupUid(name string) (string, error) {
	pw, err := user.Lookup(name)
	if err != nil {
		return "", err
	}

	return pw.Uid, nil
}

// Return the uid/gid of the other side of a unix connection.
// This may have to be factored out into OS-specific syscalls.
func getpeereid(conn interface{}) (uid, gid string, err error) {
	sock, ok := conn.(*net.UnixConn)
	if !ok {
		return "", "", errSocketConn
	}
	file, err := sock.File()
	if err != nil {
		return "", "", err
	}

	fd := int(file.Fd())
	acct, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	file.Close()
	if err != nil {
		return "", "", err
	}

	uid = strconv.FormatUint(uint64(acct.Uid), 10)
	gid = strconv.FormatUint(uint64(acct.Gid), 10)
	return uid, gid, nil
}
