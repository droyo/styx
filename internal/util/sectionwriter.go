package util

import "io"

// Section writer provides a partial analogue io.SectionReader,
// for writers.
type SectionWriter struct {
	w             io.WriterAt
	offset, limit int64
}

func NewSectionWriter(w io.WriterAt, off, n int64) *SectionWriter {
	return &SectionWriter{w, off, off + n}
}

func (s *SectionWriter) Write(p []byte) (int, error) {
	if s.offset >= s.limit {
		return 0, io.EOF
	}
	if max := s.limit - s.offset; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err := s.w.WriteAt(p, s.offset)
	s.offset += int64(n)
	return n, err
}
