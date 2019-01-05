// Package styxfile provides helper routines and interfaces
// for serving 9P files from Go types.
package styxfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"aqwari.net/net/styx/internal/sys"
	"aqwari.net/net/styx/styxproto"
)

// 9P read/write requests contain an offset. This makes them
// well-suited to the io.ReaderAt and io.WriterAt interfaces.
// However to keep our APIs flexible, we do the heavy lifting,
// accepting broader interfaces and forcing them into what we
// need.

// ErrNotSupported is returned when a given type does not
// implement the necessary functionality to complete a given
// read/write operation.
var ErrNotSupported = errors.New("not supported")

// Interface describes the methods a type must implement to
// be used as a file by a 9P file server. The New function converts
// types that implement some, but not all of these methods into
// types that do.
type Interface interface {
	io.ReaderAt
	io.WriterAt
	io.Closer
}

type interfaceWithoutClose interface {
	io.ReaderAt
	io.WriterAt
}

type nopCloser struct {
	interfaceWithoutClose
}

func (nopCloser) Close() error { return nil }

// New creates a new Interface that reads and writes to and from
// rwc. The type of rwc determines the implementation selected
// by New; if rwc already implements Interface, it is used as-is. If
// some methods are missing, wrapper types are used to implement
// missing functionality. If the provided type cannot be adapted into
// an Interface, New returns a non-nil error.
func New(rwc interface{}) (Interface, error) {
	switch rwc := rwc.(type) {
	case Interface:
		return rwc, nil
	case interfaceWithoutClose:
		return nopCloser{rwc}, nil
	case io.Seeker:
		return &seekerAt{rwc: rwc}, nil
	case io.ReadWriter:
		return &dumbPipe{rwc: rwc}, nil
	case io.Reader:
		return &dumbPipe{rwc: rwc}, nil
	case io.Writer:
		return &dumbPipe{rwc: rwc}, nil
	}
	return nil, fmt.Errorf("Cannot convert type %T into a styxfile.Interface", rwc)
}

// SetDeadline sets read/write deadlines for a file, if the type supports it.
func SetDeadline(file Interface, t time.Time) error {
	var real interface{}
	switch v := file.(type) {
	case *seekerAt:
		real = v.rwc
	case *dumbPipe:
		real = v.rwc
	case *dirReader:
		real = v.Directory
	default:
		real = v
	}
	type deadline interface {
		SetDeadline(time.Time) error
	}
	if v, ok := real.(deadline); ok {
		return v.SetDeadline(t)
	}
	return ErrNotSupported
}

// Stat produces a styxproto.Stat from an open file. If the value
// provides a Stat method matching that of os.File, that is used.
// Otherwise, the styxfile package determines the file's attributes
// based on other characteristics.
func Stat(buf []byte, file Interface, name string, qid styxproto.Qid) (styxproto.Stat, error) {
	var (
		fi  os.FileInfo
		err error
	)
	type hasStat interface {
		Stat() (os.FileInfo, error)
	}
	if v, ok := file.(hasStat); ok {
		fi, err = v.Stat()
		if err != nil {
			return nil, err
		}
	} else {
		fi = statGuess{file, name, qid.Type()}
	}
	uid, gid, muid := sys.FileOwner(fi)
	stat, _, err := styxproto.NewStat(buf, fi.Name(), uid, gid, muid)
	if err != nil {
		return nil, err
	}
	stat.SetLength(fi.Size())
	stat.SetMode(Mode9P(fi.Mode()))
	stat.SetAtime(uint32(fi.ModTime().Unix()))
	stat.SetMtime(uint32(fi.ModTime().Unix()))
	stat.SetQid(qid)
	return stat, nil
}

type statGuess struct {
	file  Interface
	name  string
	qtype uint8
}

func (sg statGuess) Name() string {
	type hasName interface {
		Name() string
	}
	if v, ok := sg.file.(hasName); ok {
		return v.Name()
	}
	return sg.name
}

func (sg statGuess) Size() int64 {
	type hasSize interface {
		Size() int64
	}
	if v, ok := sg.file.(hasSize); ok {
		return v.Size()
	}
	return -1
}

func (sg statGuess) Mode() os.FileMode {
	type hasMode interface {
		Mode() os.FileMode
	}
	if v, ok := sg.file.(hasMode); ok {
		return v.Mode()
	}
	return ModeOS(uint32(sg.qtype)<<24) | 0777
}

func (sg statGuess) IsDir() bool {
	type hasDir interface {
		IsDir() bool
	}
	if v, ok := sg.file.(hasDir); ok {
		return v.IsDir()
	}
	return sg.Mode().IsDir()
}

func (sg statGuess) ModTime() time.Time {
	type hasTime interface {
		ModTime() time.Time
	}
	if v, ok := sg.file.(hasTime); ok {
		return v.ModTime()
	}
	return time.Time{}
}

func (sg statGuess) Sys() interface{} {
	return sg.file
}
