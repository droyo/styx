package styx

import "time"

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
}
