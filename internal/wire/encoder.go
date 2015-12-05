package wire

import (
	"errors"
	"math"

	"aqwari.net/net/styx/internal/pool"
	"aqwari.net/net/styx/styxproto"
)

// An RreadPipe implements io.Writer. It encodes written data
// to 9P Rread messages and writes them to an underlying writer.
type RreadPipe struct {
	// The underlying Writer.
	W *TxWriter

	// The maximum size of a single 9P message.
	Msize int

	// Tag references the Tread request that the Rread messages
	// are in response to.
	Tag uint16
}

// A TwritePipe implements io.Writer. It encodes written data
// to 9P Twrite messages and writes them to an underlying writer.
type TwritePipe struct {
	// The underlying Writer.
	W *TxWriter

	// The Maximum size of a single 9P message.
	Msize int

	// The fid to write to.
	Fid uint32

	// Tag is used to acquire unique tags for outgoing Twrite
	// messages.
	Tag *pool.TagPool

	// The offset to start writing data at. Do not modify after
	// the first call to Write.
	Offset int64

	n int64
}

// Write writes Rread messages to w's underlying TxWriter. If len(p)
// is greater than the maximum message size, multiple Rread messages
// will be generated.
func (w *RreadPipe) Write(p []byte) (n int, err error) {
	for i := len(p); i > 0; i -= w.Msize {
		upto := w.Msize
		if i < w.Msize {
			upto = i
		}
		tx := w.W.Tx()
		_, err = styxproto.WriteRread(tx, w.Tag, p[:upto])
		tx.Close()

		if err != nil {
			break
		}
		p = p[upto:]
		n += upto
	}
	return n, err
}

var errOffsetOverflow = errors.New("write past max int64 in file")

// Write writes Twrite messages to w's underlying TxWriter. If len(p)
// is greater than the maximum message size, multiple Rread messages
// will be generated.
func (w *TwritePipe) Write(p []byte) (n int, err error) {
	var wr = styxproto.WriteTwrite

	if math.MaxInt64-int64(len(p)) < w.Offset {
		return 0, errOffsetOverflow
	}

	for i := len(p); i > 0; i -= w.Msize {
		upto := w.Msize
		if i < w.Msize {
			upto = i
		}
		tx := w.W.Tx()
		_, err := wr(tx, tag, w.Fid, w.Offset+w.n, p[:upto])
		tx.Close()

		if err != nil {
			break
		}
		p = p[upto:]
		n += upto
	}
	w.n += int64(n)
	return n, err
}
