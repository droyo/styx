/*
Package styx provides 9P client and server implementations.

The styx package allows for the implementation and usage of distributed
file systems via the 9P filesystem protocol. The 9P filesystem protocol
provides a lightweight, high-performance method of accessing remote
resources as part of a hierarchical file system. The resources may
be real files on a remote server, or they may represent bi-directional
RPC calls. Regardless, the interface for serving or accessing the resources
mimics the APIs for dealing with normal files.

Remote URLs

Many of the functions in the styx package take a URL parameter that
specifieds the remote server to connect to. The URL is of the form

	transport://server[:port]/path

For example,

	tcp://aqwari.net/robots.txt
	tls://blog.aqwari.net/9P/index

The default port is 564. If ellided, the default transport is tcp. The supported
transports are:

	tcp  - tcp/ip connection to a remote server
	tls  - TLS over tcp/ip to a remote server
	unix - unix socket. host section must be empty.

Accessing files

The styx package provides a 9P client implementation, and convenient
wrapper functions for common use cases. To open a single remote file,
use the Open function:

	file, err := styx.Open("tls://blog.aqwari.net/9P/index")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	io.Copy(os.Stdout, file)

The OpenFile function can be used to open a file for writing.

	file, err := styx.OpenFile("tls://blog.aqwari.net/9P/index.comment", styx.O_RDWR)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	io.WriteString(file, "This is a great article but it's completely inaccurate")

To enable authentication, change TLS settings, and other connection parameters,
create a Client.

	client := styx.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Auth: styx.AuthPassword("username", "password"),
	}
	file, err := client.Open("tls://blog.aqwari.net/9P/index", styx.O_APPEND)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	io.WriteString(file, "add a missing file")

Minimizing round-trips

When operating over a high-latency connection, performance can be
improved by pipelining messages, such that each packet sent to the
remote server carries the maximum payload. Convenience functions
that capture a use case consisting of multiple messages will attempt
to send the messages within a single packet, if possible.  For
example, ReadFile("tcp://example.net/path/to/file") will pack the
following messages into a single packet:

	Tversion 0xFF <msize> 9P2000
	Tattach <tag> <fid> 0xFFFF none ""
	Twalk <tag> <fid> <newfid> path/to/file
	Topen <tag> <fid> O_READ
	Tread <fid> 0 0xFFFF

A properly optimized server implementation, such as the one contained
in the styx package, can pipeline its responses to minimize the
number of packets sent in the reply. More generally, the NewClient
function can be used to create a Client that buffers its messages
to minimize round-trips. Note that on low-loss, low-latency transports
(such as a unix socket), excessive buffering can be detrimental for
performance and introduce latency.
*/
package styx
