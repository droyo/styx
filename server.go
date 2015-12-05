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
	Printf(format string, v ...interface{})
}

// A Server defines parameters for running a 9P server. The
// zero value of a Server is usable as a 9P server, and will
// use the defaults set by the styx package.
type Server struct {
	Addr         string        // Address to listen on, ":9pfs" if empty.
	WriteTimeout time.Duration // maximum wait before timing out write of the response.

	IdleTimeout time.Duration // maximum wait before closing an idle connection.
	MaxSize     int64         // maximum size of a 9P message, DefaultMsize if unset.
	TLSConfig   *tls.Config   // optional TLS config, used by ListenAndServeTLS
	Handler     Handler       // Default handler to invoke, DefaultServeMux if nil

	// Auth is used to authenticate user sessions. If nil,
	// authentication is disabled.
	Auth Auth

	// If not nil, ErrorLog will be used to log unexpected
	// errors accepting or handling connections. TraceLog,
	// if not nil, will receive detailed protocol tracing
	// information.
	ErrorLog, TraceLog Logger
}

func (s *Server) debug() bool {
	return s.TraceLog != nil
}

func (s *Server) debugf(format string, v ...interface{}) {
	if s.TraceLog != nil {
		s.TraceLog.Printf(format, v...)
	}
}

func (s *Server) logf(format string, v ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, v...)
	}
}

type Handler interface {
	Serve9P(ResponseWriter, *Request)
}

type ResponseWriter struct{}
type Request struct{}

// Serve accepts connections on the listener l, creating a new service
// goroutine for each. The service goroutines read requests and then
// call srv.Handler to reply to them.
func (srv *Server) Serve(l net.Listener) error {
	backoff := retry.Exponential(time.Millisecond).Max(time.Second)
	try := 0

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
		c := newConn(rwc, srv)
		c.remoteAddr = rwc.RemoteAddr().String()
		srv.debugf("accepeted connection from %s", rwc.RemoteAddr())
		go c.serve()
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
// If srv.Addr is blank, :9pfs is used.
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
		addr = ":9pfs"
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
