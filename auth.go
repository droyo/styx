package styx

import (
	"io"
	"net"

	"golang.org/x/net/context"
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

// Transport retrieves the underlying net.Conn for a Channel, or nil
// if it is not stored in the channel context.
func (ch *Channel) Transport() net.Conn {
	if c, ok := ch.Value("conn").(net.Conn); ok {
		return c
	}
	return nil
}

// Types that implement the Auth interface can be used to authenticate
// a user to a plan 9 server. The authentication protocol itself is
// tunnelled over 9P via read and write operations to a special file,
// and is outside the scope of the 9P protocol.
//
// The Auth method must determine that a client is authorized to start
// a 9P session to the file tree specified by the access parameter.
// The Auth method may receive and send data over rwc. Alternatively,
// additional information can be passed through the Context value
// to perform "external" authentication.
//
// The Auth method must return a non-nil error if authentication fails.
// The error may be sent to the client and should not contain any
// sensitive information. If authentication succeeds, the Auth method
// must return nil.
//
// Existing Auth implementations can be found in the styxauth package.
type Auth interface {
	Auth(rwc *Channel, user, access string) error
}
