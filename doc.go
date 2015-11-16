/*
Package styx provides 9P client and server implementations.

The styx package allows for the implementation and usage of distributed
file systems via the 9P filesystem protocol.
*/
package styx

import "aqwari.net/net/styx/styxproto"

type Server interface {
	Attach(styxproto.Tattach) error
	Auth(styxproto.Tauth) error
	Open(styxproto.Topen) error
	Read(styxproto.Tread) error
}

type Filesystem interface {
}
