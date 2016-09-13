package styx

import (
	"crypto/tls"
	"net"
	"time"

	"aqwari.net/net/styx/internal/util"
	"aqwari.net/retry"
)

// Types implementing the Logger interface can receive
// diagnostic information during a Server's operation.
// The Logger interface is implemented by *log.Logger.
type Logger interface {
	Printf(string, ...interface{})
}

// A Server defines parameters for running a 9P server. The
// zero value of a Server is usable as a 9P server, and will
// use the defaults set by the styx package.
type Server struct {
	// Address to listen on, ":9pfs" if empty.
	Addr string

	// maximum wait before timing out write of the response.
	WriteTimeout time.Duration

	// maximum wait before closing an idle connection.
	IdleTimeout time.Duration

	// maximum size of a 9P message, DefaultMsize if unset.
	MaxSize int64

	// optional TLS config, used by ListenAndServeTLS
	TLSConfig *tls.Config

	// Handler to invoke for each session
	Handler Handler

	// Auth is used to authenticate user sessions. If nil,
	// authentication is disabled.
	Auth AuthFunc

	// If not nil, ErrorLog will be used to log unexpected
	// errors accepting or handling connections. TraceLog,
	// if not nil, will receive detailed protocol tracing
	// information.
	ErrorLog, TraceLog Logger
}

// Types implementing the Handler interface can receive and respond to 9P
// requests from clients.
//
// When a client connects to the server and starts a session, a new goroutine
// is created running the handler's Serve9P method. Each 9P message can
// be retrieved using the Session's Next and Request methods. Serve9P is
// expected to last for the duration of the 9P session; if the client ends
// the session, the Session's Next method will return false. If the Serve9P
// method exits prematurely, all open files and other resources associated
// with that session are released, and any further requests for that session
// will result in an error.
//
// The Serve9P method is not required to answer every type of 9P message.
// If an existing request is unanswered when Serve9P fetches the next
// request, the styx package will reply to the client with a default
// response. The documentation for each request type notes its default
// response.
//
// In practice, a Handler is usually composed of a for loop and a type switch,
// like so:
//
// 	func (srv *Srv) Serve9P(s *styx.Session) {
// 		for s.Next() {
// 			switch msg := s.Request().(type) {
// 			case styx.Twalk:
// 				if (srv.exists(msg.Path()) {
// 					msg.Rwalk(srv.filemode(msg.Path())
// 				} else {
// 					msg.Rerror("%s does not exist", msg.Path())
// 				}
// 			case styx.Topen:
//				msg.Ropen(srv.getfile(msg.Path()))
// 			case styx.Tcreate:
// 				msg.Rcreate(srv.newfile(msg.Path())
// 			}
// 		}
// 	}
//
// Possible message types are listed in the documentation for the Request type.
//
type Handler interface {
	Serve9P(*Session)
}

// The HandlerFunc provides a convenient adapter type that allows for normal
// functions to handle 9P sessions.
type HandlerFunc func(s *Session)

// Serve9P calls fn(s).
func (fn HandlerFunc) Serve9P(s *Session) {
	fn(s)
}

// Serve accepts connections on the listener l, creating a new service
// goroutine for each. The service goroutines read requests and relays
// them to the appropriate Handler goroutines.
func (srv *Server) Serve(l net.Listener) error {
	backoff := retry.Exponential(time.Millisecond * 10).Max(time.Second)
	try := 0

	srv.logf("listening on %s", l.Addr())
	for {
		rwc, err := l.Accept()
		if err != nil {
			if util.IsTempErr(err) {
				try++
				srv.logf("9p: Accept error: %v; retrying in %v", err, backoff(try))
				time.Sleep(backoff(try))
				continue
			}
			return err
		} else {
			try = 0
		}

		srv.logf("accepted connection from %s", rwc.RemoteAddr())
		conn := newConn(srv, rwc)
		go conn.serve()
	}
}

// ListenAndServe listens on the specified TCP address, and then
// calls Serve with handler to handle requests of incoming
// connections.
func ListenAndServe(addr string, handler Handler) error {
	srv := Server{Handler: handler, Addr: addr}
	return srv.ListenAndServe()
}

// ListenAndServeTLS listens on the specified TCP address for
// incoming TLS connections. certFile must be a valid x509
// certificate in PEM format, concatenated with any intermediate
// and CA certificates.
func ListenAndServeTLS(addr string, certFile, keyFile string, handler Handler) error {
	srv := Server{Handler: handler, Addr: addr}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// ListenAndServe listens on the TCP network address srv.Addr and
// calls Serve to handle requests on incoming connections.
// If srv.Addr is blank, :564 is used.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":9pfs"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ListenAndServeTLS listens on the TCP network address srv.Addr for
// incoming TLS connections.
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":564"
	}
	cfg := srv.TLSConfig
	if cfg == nil {
		cfg = new(tls.Config)
	}
	if len(cfg.Certificates) == 0 || certFile != "" || keyFile != "" {
		var err error
		cfg.Certificates = make([]tls.Certificate, 1)
		cfg.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ln = tls.NewListener(ln, cfg)
	return srv.Serve(ln)
}

func (s *Server) logf(format string, v ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, v...)
	}
}
