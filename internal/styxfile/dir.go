package styxfile

import (
	"errors"
	"io"
	"os"
	"path"
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
func NewDir(dir Directory, abspath string, pool *qidpool.Pool) Interface {
	return &dirReader{
		Directory: dir,
		pool:      pool,
		path:      abspath,
	}
}

type dirReader struct {
	Directory
	offset    int64 // current offset in the byte stream
	nextlen   int   // if non zero, the length of next stat structure cached in next.
	nextshort bool  // whether a short read occured on next
	next      [styxproto.MaxStatLen]byte
	sync.Mutex
	pool *qidpool.Pool
	path string
}

func (d *dirReader) ReadAt(p []byte, offset int64) (written int, err error) {
	// see Plan 9 man read(5): read must return an integral number
	// of stat structures.
	d.Lock()
	defer d.Unlock()

	if offset != d.offset {
		return 0, ErrNoSeek
	}

	// We accept one short read
	if d.nextlen > 0 {
		if len(p) < d.nextlen {
			if d.nextshort {
				return 0, ErrSmallRead
			} else {
				// User buffer is too short,
				// next read *must* be large enough
				d.nextshort = true
				return 0, nil
			}
		} else {
			copy(p[:], d.next[:d.nextlen])
			p = p[d.nextlen:]
			written += d.nextlen
			d.offset += int64(d.nextlen)
			d.nextlen = 0
			d.nextshort = false
		}
	}

	for len(p) > 0 {
		nstats := len(p) / styxproto.MaxStatLen
		if nstats == 0 {
			nstats = 1
		}
		files, rerr := d.Readdir(nstats)
		for _, fi := range files {
			// Create 9p stat blob
			uid, gid, muid := sys.FileOwner(fi)
			stat, _, err := styxproto.NewStat(d.next[:], fi.Name(), uid, gid, muid)
			if err != nil {
				return written, err
			}
			mode := Mode9P(fi.Mode())
			qtype := QidType(mode)

			stat.SetMtime(uint32(fi.ModTime().Unix()))
			stat.SetAtime(stat.Mtime())
			stat.SetLength(fi.Size())
			stat.SetMode(mode)
			stat.SetQid(d.pool.Put(path.Join(d.path, fi.Name()), qtype))

			if len(stat) > len(p) {
				if nstats != 1 {
					panic("impossible")
				}
				// Last entry overflows
				d.nextlen = len(stat)
				d.nextshort = false
				return written, nil
			}

			n := copy(p, stat)
			p = p[n:]
			written += n
			d.offset += int64(n)
		}

		if rerr != nil {
			err = rerr
			break
		}
	}
	return written, err
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
