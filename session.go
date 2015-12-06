package styx

// A session is a set of requests initiated over a 9P connection that
// is associated with a single user. Sessions begin with a Tattach
// message, and end with a Tclunk message of the final fid associated
// with that session. There is no concept of a "session cookie" in 9P;
// because all additional fids must be derived from the initial root
// fid established in a Tattach request, the fid used in a T-message
// is sufficient to identify the session.
type session struct {
	uname, aname string
	conn         *conn
}
