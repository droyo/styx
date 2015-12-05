package wire

import (
	"io"
	"sync"
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
