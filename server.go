package styx

import (
	"crypto/tls"
	"net"
	"strings"
	"sync"
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

	// Default handler to invoke, Defaultwwwww if nil
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

// A ServeMux routes requests to specific paths or subtrees to registered
// handlers.
type ServeMux struct {
	m  map[string]Handler
	mu sync.RWMutex
}

// NewServeMux initializes an empty ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{
		m: make(map[string]Handler),
	}
}

// DefaultServeMux is the default Handler for the styx package.
// The package-level Handle and HandleFunc functions register
// new handlers in DefaultServeMux.
var DefaultServeMux = NewServeMux()

// Serve9P reads incoming requests for a Session. If the path of an
// operation matches a pattern registered in the ServeMux, the request
// is forwarded to the handler for that pattern. Otherwise, ServeMux
// responds as if the files did not exist.
func (mux *ServeMux) Serve9P(s *Session) {
	mux.mu.RLock()
	handlers := make(map[string]chan Request, len(mux.m))
	for pattern, handler := range mux.m {
		sc := new(Session)
		*sc = *s
		sc.Requests = make(chan Request)
		handlers[pattern] = sc.Requests
		defer close(sc.Requests)
		go handler.Serve9P(sc)
	}
	mux.mu.RUnlock()
	for msg := range s.Requests {
		if c, ok := matchHandler(handlers, msg.Path()); ok {
			c <- msg
		} else {
			msg.defaultResponse()
		}
	}
	for _, c := range handlers {
		close(c)
	}
}

func matchHandler(m map[string]chan Request, s string) (chan Request, bool) {
	var match string
	for k := range m {
		if pathMatch(k, s) && len(match) < len(k) {
			match = k
		}
	}
	if len(match) > 0 {
		return m[match], true
	}
	return nil, false
}

func pathMatch(pattern, name string) bool {
	if !strings.HasPrefix(name, pattern) {
		return false
	}
	if strings.HasSuffix(pattern, "/") {
		return true
	}
	return pattern == name
}

// Handle registers a Handler to receive requests for files whose
// name matches pattern. Registering a handler for the same
// pattern twice results in a run-time panic.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	if _, ok := mux.m[pattern]; ok {
		panic("Handler for \"" + pattern + "\" defined twice")
	}
	mux.m[pattern] = handler
}

func (mux *ServeMux) HandleFunc(pattern string, fn func(*Session)) {
	mux.Handle(pattern, HandlerFunc(fn))
}

// Types implementing the Handler interface can be registered to receive
// 9P requests to a specific path or subtree in the 9P server.
type Handler interface {
	Serve9P(*Session)
}

type HandlerFunc func(s *Session)

func (fn HandlerFunc) Serve9P(s *Session) {
	fn(s)
}

func HandleFunc(prefix string, fn func(s *Session)) {
	DefaultServeMux.HandleFunc(prefix, fn)
}

func (s *Server) isDebug() bool {
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

// Serve accepts connections on the listener l, creating a new service
// goroutine for each. The service goroutines read requests and then
// call srv.Handler to reply to them.
func (srv *Server) Serve(l net.Listener) error {
	backoff := retry.Exponential(time.Millisecond * 10).Max(time.Second)
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

		srv.debugf("accepted connection from %s", rwc.RemoteAddr())
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
