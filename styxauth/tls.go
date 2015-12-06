package styxauth

import (
	"crypto/tls"
	"errors"

	"aqwari.net/net/styx"
)

var (
	errTLSConn = errors.New("not a TLS connection")
)

// TLSSubjectCN authenticates a client using the underyling tls
// connection. The client must provide a valid certificate with a
// common name that matches the username field in the authentication
// request. For more control over cert-based authentication, use the
// TLSAuth type.
var TLSSubjectCN = TLSAuth(checkSubjectCN)

// TLSAuth returns a styx.Auth value that authenticates a user based
// on the status of the underlying TLS connection.  After validating
// the client certificate, the callback function is called with the
// connection state as a parameter.  The callback must return nil if
// authentication succeeds, and a non-nil error otherwise.
type TLSAuth func(user, access string, state tls.ConnectionState) error

func (fn TLSAuth) Auth(rw styx.Channel, user, access string) error {
	if tlsconn, ok := rw.Transport().(*tls.Conn); ok {
		return fn(user, access, tlsconn.ConnectionState())
	}
	return errTLSConn
}

func checkSubjectCN(user, access string, state tls.ConnectionState) error {
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			if cert.Subject.CommonName == user {
				return nil
			}
			return errAuthFailure
		}
	}
	return errAuthFailure
}
