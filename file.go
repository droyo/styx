package styx

import "io"

type file struct {
	rwc    io.ReadWriteCloser
	name   string
	offset int64
}
