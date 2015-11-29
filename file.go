package styx

import "aqwari.net/net/styx/styxproto"

type file interface{}

// An fcall is a 9P message that contains a fid, and represents
// an operation on a file.
type fcall interface {
	styxproto.Msg
	Fid() uint32
}
