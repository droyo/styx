package styxfile

import (
	"errors"
	"io"
	"os"
	"sync"

	"aqwari.net/net/styx/internal/qidpool"
	"aqwari.net/net/styx/internal/sys"
	"aqwari.net/net/styx/styxproto"
)

// ErrSmallRead is returned when a client's Tread request on
// a directory does not request enough bytes to hold at least
// one Stat structure.
var ErrSmallRead = errors.New("Tread count too small for dir stat")

// Types implementing the Directory interface can be made
// into 9P files by the NewDir function. This provides an easy
// way, for example, to provide directory listings from an
// *os.File.
type Directory interface {
	Readdir(n int) ([]os.FileInfo, error)
}

// NewDir creates a new Interface that converts the return
// value of a Directory's Readdir method into 9P Stat structures.
func NewDir(dir Directory, pool *qidpool.Pool) Interface {
	return &dirReader{
		Directory: dir,
		pool:      pool,
	}
}

type dirReader struct {
	Directory
	offset int64
	sync.Mutex
	pool *qidpool.Pool
}

func modePerm(mode os.FileMode) uint32 {
	var perm uint32
	if mode&os.ModeDir != 0 {
		perm |= styxproto.DMDIR
	}
	if mode&os.ModeAppend != 0 {
		perm |= styxproto.DMAPPEND
	}
	if mode&os.ModeExclusive != 0 {
		perm |= styxproto.DMEXCL
	}
	if mode&os.ModeTemporary != 0 {
		perm |= styxproto.DMTMP
	}
	return perm | uint32(mode&os.ModePerm)
}

func (d *dirReader) ReadAt(p []byte, offset int64) (int, error) {
	d.Lock()
	defer d.Unlock()

	if offset != d.offset {
		return 0, ErrNoSeek
	}

	// NOTE(droyo) because we are being pessimistic about the
	// size of filenames/usernames/etc, the below can result
	// in us calling Readdir more times than we have to, especially
	// if file/user names are normal size. This could be addressed
	// by buffering Readdir's results.
	nstats := len(p) / styxproto.MaxStatLen

	if nstats == 0 {
		return 0, ErrSmallRead
	}

	files, err := d.Readdir(nstats)
	n, marshalErr := marshalStats(files, p, d.pool)
	d.offset += int64(n)
	if marshalErr != nil {
		return n, marshalErr
	}
	return n, err
}

func marshalStats(files []os.FileInfo, buf []byte, pool *qidpool.Pool) (int, error) {
	var (
		stat styxproto.Stat
		n    = 0
		err  error
	)
	for _, fi := range files {
		uid, gid, muid := sys.FileOwner(fi)
		stat, buf, err = styxproto.NewStat(buf, fi.Name(), uid, gid, muid)
		if err != nil {
			break
		}
		n += len(stat)
		mode := modePerm(fi.Mode())
		qtype := uint8(mode >> 24)

		stat.SetMtime(uint32(fi.ModTime().Unix()))
		stat.SetAtime(stat.Mtime())
		stat.SetLength(fi.Size())
		stat.SetMode(mode)

		// The []byte-based representation has its perks,
		// sometimes :D
		copy(stat.Qid(), pool.Put(fi.Name(), qtype))
	}
	return n, err
}

func (d *dirReader) WriteAt(p []byte, offset int64) (int, error) {
	return 0, ErrNotSupported
}

func (d *dirReader) Close() error {
	if c, ok := d.Directory.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
