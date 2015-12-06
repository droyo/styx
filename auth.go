package styx

import "io"

// Types implementing the Auth interface receive a Channel
// through which they can communicate with a client to complete
// the authentication protocol of their choosing. For authentication
// methods that use the underlying transport, the Transport method
// returns the net.Conn value used for the connection.
type Channel interface {
	io.ReadWriter
	Transport() interface{}
}

// Types that implement the Auth interface can be used to authenticate
// a user to a plan 9 server. The authentication protocol itself is
// tunnelled over 9P via read and write operations to a special file,
// and is outside the scope of the 9P protocol.
//
// The Auth method must determine that a client is authorized to start
// a 9P session to the file tree specified by the access parameter.
// The Auth method may receive and send data over rw. Alternatively,
// the underlying transport may be used to authenticate a user, using
// the Conn parameter.
//
// The Auth method must return a non-nil error if authentication fails.
// The error may be sent to the client and should not contain any
// sensitive information. If authentication succeeds, the Auth method
// must return nil.
//
// Existing Auth implementations can be found in the styxauth package.
type Auth interface {
	Auth(c Channel, user, access string) error
}
