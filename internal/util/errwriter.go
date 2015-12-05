package util

import "io"

// An ErrWriter can be used to defer error checking when
// doing several successive writes to an underlying
// io.Writer.
type ErrWriter struct {
	W   io.Writer
	Err error
	N   int
}

// Write writes len(p) bytes to the underlying io.Writer of the ErrWriter
// value. If an error has already been encountered, no additional
// data is written.
func (w *ErrWriter) Write(p []byte) (int, error) {
	if w.Err != nil {
		return 0, w.Err
	}
	n, err := w.W.Write(p)
	w.Err = err
	w.N += n
	return n, err
}

func (w *ErrWriter) WriteByte(v byte) error {
	var buf [1]byte
	if wb, ok := w.W.(io.ByteWriter); ok {
		w.Err = wb.WriteByte(v)
		w.N++
		return w.Err
	}
	buf[0] = v
	n, err := w.W.Write(buf[:])
	w.N += n
	w.Err = err
	return err
}
