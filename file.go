package styx

import "aqwari.net/net/styx/internal/styxfile"

type file struct {
	rwc  styxfile.Interface
	name string

	// This is an afid, used for authentication
	auth bool
}

type OwnerInfo interface {
	Uid() string
	Gid() string
	Muid() string
}
