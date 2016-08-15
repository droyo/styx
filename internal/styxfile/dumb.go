package styxfile

import (
	"errors"
	"io"
	"sync"
)

// Types implementing only io.Reader or io.Writer will only accept a stream of
// in-order, contiguous reads or writes, and will return errors for anything
// else.

// ErrNoSeek is returned when a given type does not support
// writing to any offset other than its current position after
// previous reads and writes.
var ErrNoSeek = errors.New("file does not support seeking")

type dumbPipe struct {
	rwc    interface{}
	offset int64
	sync.Mutex
}

func (dp *dumbPipe) ReadAt(p []byte, offset int64) (int, error) {
	r, ok := dp.rwc.(io.Reader)
	if !ok {
		return 0, ErrNotSupported
	}
	dp.Lock()
	defer dp.Unlock()

	if dp.offset != offset {
		return 0, ErrNoSeek
	}

	n, err := io.ReadFull(r, p)
	dp.offset += int64(n)
	return n, err
}

func (dp *dumbPipe) WriteAt(p []byte, offset int64) (int, error) {
	w, ok := dp.rwc.(io.Writer)
	if !ok {
		return 0, ErrNotSupported
	}
	dp.Lock()
	defer dp.Unlock()

	if dp.offset != offset {
		return 0, ErrNoSeek
	}

	n, err := w.Write(p)
	dp.offset += int64(n)
	return n, err
}

func (dp *dumbPipe) Close() error {
	if c, ok := dp.rwc.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
