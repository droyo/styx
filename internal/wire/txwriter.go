package wire

import (
	"errors"
	"io"
	"sync"
)

var (
	errDoubleClose = errors.New("Close on closed TxWriter.Tx")
	errClosedWrite = errors.New("Write on closed TxWriter.Tx")
)

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
// other Writes. After Tx returns, all other writes to the TxWriter
// will be blocked until the returned io.WriteCloser is closed.  The
// returned io.WriteCloser can only be used from a single goroutine.
func (w *TxWriter) Tx() io.WriteCloser {
	w.mu.Lock()
	return &tx{w}
}

type tx struct {
	*TxWriter
}

func (w *tx) Write(p []byte) (int, error) {
	if w.TxWriter == nil {
		return 0, errClosedWrite
	}
	return w.TxWriter.W.Write(p)
}

func (w *tx) Close() error {
	w.mu.Unlock()
	w.TxWriter = nil
	return nil
}
