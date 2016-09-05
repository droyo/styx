package styx

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"aqwari.net/net/styx/internal/pool"
	"aqwari.net/net/styx/styxproto"
)

var (
	errBadResponse = errors.New("remote server sent an invalid R-message")
	errBadMsize    = errors.New("server sent msize value that exceeded client's maximum")
	errBadVersion  = errors.New("server proposed an unsupported protocol version")
	errNoResponse  = errors.New("could not get a response from the server")
	errNoFile      = errors.New("No such file or directory")
)

// DefaultClient is the Client used by top-level functions such
// as Open.
var DefaultClient = &Client{}

// A Client is a 9P client, used to make remote requests to
// a 9P server. The zero value of a Client is a usable 9P client
// that uses default settings chosen by the styx package.
type Client struct {
	// The maximum size of a single 9P message. When working with
	// very large files, a larger MessageSize can reduce protocol
	// overhead. Because a remote server may choose to set a smaller
	// maximum size, increasing MessageSize may have no effect
	// with certain servers.
	MaxSize uint32

	// Timeout specifies the amount of time to wait for a response
	// from the server. Note that Timeout does not apply to Read
	// requests, to avoid interfering with long-poll or message
	// queue-like interfaces, where a client issues a Read request
	// for data that has not arrived yet. If zero, defaults to infinity.
	Timeout time.Duration

	// TLSConfig is referenced when connecting to a remote server using
	// TLS, and can be set to provide non-default CA certificate chains,
	// client certificates, and other options.
	TLSConfig *tls.Config

	// Auth is used to authenticate a user with the remote server.
	// If nil, authentication is disabled.
	Auth AuthFunc

	// Version is the version of the 9P2000 protocol that the Client
	// will attempt to use. The default and only available version
	// is "9P2000"
	Version string
}

func pathElements(filepath string) []string {
	return strings.FieldsFunc(filepath, func(r rune) bool { return r == '/' })
}

func addPortIfMissing(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(host, port)
	}
	return host
}

type clientConn struct {
	rwc io.ReadWriteCloser
	*styxproto.Encoder
	*styxproto.Decoder
	fidpool pool.FidPool
	tagpool pool.TagPool
	msize   int64
	version string

	mu       sync.Mutex // guards the following
	requests map[uint16]func(styxproto.Msg)
}

func newClientConn(config *Client, rwc io.ReadWriteCloser) (*clientConn, error) {
	msize := int64(config.MaxSize)
	if msize == 0 {
		msize = styxproto.DefaultMaxSize
	} else if msize < styxproto.MinBufSize {
		msize = styxproto.MinBufSize
	}
	version := config.Version
	if version == "" {
		version = "9P2000"
	}
	c := &clientConn{
		rwc:      rwc,
		Encoder:  styxproto.NewEncoder(rwc),
		Decoder:  styxproto.NewDecoder(rwc),
		msize:    msize,
		version:  version,
		requests: make(map[uint16]func(styxproto.Msg)),
	}
	if err := c.negotiateVersion(); err != nil {
		return nil, err
	}
	go c.run()
	return c, nil
}

func (c *clientConn) negotiateVersion() error {
	c.Tversion(uint32(c.msize), c.version)
	if c.Encoder.Err() != nil {
		return c.Encoder.Err()
	}

	// NOTE(droyo) here we are assuming that the server will only send
	// a single message in response to our Tversion request. By all
	// readings of the protocol, this is a valid assumption. However,
	// should the server send multiple messages together in response
	// to our Tversion, with the way the code below is written, they
	// may be silently ignored.
	for c.Next() {
		rver, ok := c.Msg().(styxproto.Rversion)
		if !ok {
			return errBadResponse
		}
		if rver.Msize() > c.msize {
			return errBadMsize
		}
		if string(rver.Version()) != c.version {
			return errBadVersion
		}
		c.msize = rver.Msize()
		return nil
	}
	if c.Decoder.Err() != nil {
		return c.Decoder.Err()
	}
	return errNoResponse
}

// runs in its own goroutine
func (c *clientConn) run() {
	for c.Next() {
		tag := c.Msg().Tag()

		c.mu.Lock()
		fn := c.requests[tag]
		delete(c.requests, tag)
		c.mu.Unlock()

		c.tagpool.Free(tag)

		if fn != nil {
			fn(c.Msg())
		}
	}
	c.close()
}

func (c *clientConn) close() error {
	return c.rwc.Close()
}

func (c *clientConn) do(w func(uint16), r func(styxproto.Msg)) uint16 {
	tag := c.tagpool.MustGet()

	c.mu.Lock()
	c.requests[tag] = r
	c.mu.Unlock()

	w(tag)
	return tag
}

func (c *clientConn) cancel(oldtag uint16) uint16 {
	return c.do(
		func(tag uint16) { c.Tflush(tag, oldtag) },
		func(r styxproto.Msg) {
			c.mu.Lock()
			delete(c.requests, oldtag)
			c.mu.Unlock()
			c.tagpool.Free(oldtag)
		})
}

func (c *clientConn) attach(fid, afid uint32, uname, aname string) chan error {
	errC := make(chan error, 1)
	c.do(
		func(tag uint16) { c.Tattach(tag, fid, afid, uname, aname) },
		func(msg styxproto.Msg) {
			if e, ok := msg.(styxproto.Rerror); ok {
				errC <- e.Err()
			} else if _, ok := msg.(styxproto.Rattach); !ok {
				errC <- errBadResponse
			}
			close(errC)
		})
	return errC
}

func (c *clientConn) walk(fid, newfid uint32, qid styxproto.Qid, wname ...string) chan error {
	errC := make(chan error, 1)
	c.do(
		func(tag uint16) { c.Twalk(tag, fid, newfid, wname...) },
		func(msg styxproto.Msg) {
			if e, ok := msg.(styxproto.Rerror); ok {
				errC <- e.Err()
			} else if msg, ok := msg.(styxproto.Rwalk); ok {
				if msg.Nwqid() != len(wname) {
					errC <- errNoFile
				} else if msg.Nwqid() > 0 {
					copy(qid, msg.Wqid(msg.Nwqid()-1))
				}
			} else {
				panic(errBadResponse)
				errC <- errBadResponse
			}
			close(errC)
		})
	return errC
}

// A File represents a file on a remote 9P server. Files may be read
// from or written to like regular files, if the server permits it.
type File struct {
	fid  uint32
	qid  styxproto.Qid
	conn *clientConn
}

// Open opens a file on a remote 9P server at uri.
func (c *Client) Open(uri string) (*File, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	var rwc net.Conn
	host := addPortIfMissing(u.Host, "564")
	if u.Scheme == "tls" {
		rwc, err = tls.Dial("tcp", host, c.TLSConfig)
	} else {
		rwc, err = net.Dial(u.Scheme, host)
	}
	if err != nil {
		return nil, err
	}
	conn, err := newClientConn(c, rwc)
	if err != nil {
		return nil, err
	}
	// TODO: authentication
	var (
		uname = ""
		aname = u.Query().Get("aname")
	)
	if u.User != nil {
		uname = u.User.Username()
	}
	rootfid := conn.fidpool.MustGet()
	newfid := conn.fidpool.MustGet()
	newqid := make(styxproto.Qid, styxproto.QidLen)

	attachErr := conn.attach(rootfid, styxproto.NoFid, uname, aname)
	walkErr := conn.walk(rootfid, newfid, newqid, pathElements(u.Path)...)

	if err := <-attachErr; err != nil {
		conn.close()
		return nil, err
	}

	if err := <-walkErr; err != nil {
		conn.close()
		return nil, err
	}

	return &File{
		fid:  newfid,
		qid:  newqid,
		conn: conn,
	}, nil
}
