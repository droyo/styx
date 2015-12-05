package internal

import (
	"io"
	"sync"
)

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

// A TxWriter provides allows for isolation of writes or sets of writes
// on an io.Writer.
type TxWriter struct {
	W  io.Writer
	mu sync.Mutex
}

// Write writes data to w's underlying writer. Individual Write
// calls are isolated from any concurrent Writes or sets of
// Writes made within a transaction.
func (w *TxWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.W.Write(p)
	w.mu.Unlock()
	return n, err
}

// A Tx allows for a set of multiple Write calls to be isolated from
// other Writes. The returned io.WriteCloser will begin a transaction
// on its first call to Write, and end the transaction when closed.
func (w *TxWriter) Tx() io.WriteCloser {
	return &tx{TxWriter: w}
}

type tx struct {
	*TxWriter
	once sync.Once
}

func (w *tx) Write(p []byte) (int, error) {
	w.once.Do(func() { w.mu.Lock() })
	return w.TxWriter.W.Write(p)
}

func (w *tx) Close() error {
	w.mu.Unlock()
	return nil
}
