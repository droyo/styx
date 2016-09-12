package styx

import (
	"io"

	"context"
)

// A Channel provides authentication methods with a bidirectional
// channel between the client and server, along with any contextual
// information recorded by the server. Of note is the "conn" value,
// which returns the underlying net.Conn value for the network
// connection.
type Channel struct {
	context.Context
	io.ReadWriteCloser
}

// Conn retrieves the underlying io.ReadWriteCloser for a Channel.
func (ch *Channel) Conn() interface{} {
	return ch.Value("conn")
}

// An AuthFunc is used to authenticate a user to a 9P server. The
// authentication protocol itself is tunnelled over 9P via read and
// write operations to a special file, and is outside the scope of the
// 9P protocol.
//
// An AuthFunc must determine that a client is authorized to start a
// 9P session to the file tree specified by the access parameter.  The
// Auth method may receive and send data over rwc. Alternatively,
// additional information can be passed through the Channel's context
// for external authentication. Notably, the Conn method of the Channel
// can be used to access the underlying network connection, in order
// to authenticate based on TLS certificates, unix uid values (on a
// unix socket), etc.
//
// An AuthFunc must return a non-nil error if authentication fails.
// The error may be sent to the client and should not contain any
// sensitive information. If authentication succeeds, an AuthFunc
// must return nil.
//
// Existing AuthFunc implementations can be found in the styxauth package.
type AuthFunc func(rwc *Channel, user, access string) error
