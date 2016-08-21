package styxfile

import (
	"io"
	"sync"
)

// A type that implements io.Seeker can be adapted to implement
// io.ReaderAt/io.WriterAt by seeking to the desired offset before
// performing the read/write operation, so long as we protect the
// seeks with a lock.

type seekerAt struct {
	rwc    io.Seeker
	sync.Mutex
}

func (s *seekerAt) ReadAt(p []byte, offset int64) (int, error) {
	r, ok := s.rwc.(io.Reader)
	if !ok {
		return 0, ErrNotSupported
	}
	s.Lock()
	defer s.Unlock()

	if _, err := s.rwc.Seek(offset, 0); err != nil {
		return 0, err
	}
	return io.ReadFull(r, p)
}

func (s *seekerAt) WriteAt(p []byte, offset int64) (int, error) {
	w, ok := s.rwc.(io.Writer)
	if !ok {
		return 0, ErrNotSupported
	}
	s.Lock()
	defer s.Unlock()

	if _, err := s.rwc.Seek(offset, 0); err != nil {
		return 0, err
	}
	return w.Write(p)
}

func (s *seekerAt) Close() error {
	if c, ok := s.rwc.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
