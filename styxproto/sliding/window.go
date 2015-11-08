// Package sliding provides a fixed-size sliding window on a stream
// of bytes.
//
// The sliding package allows for up to N bytes of a byte stream to
// be addressable as a byte slice between read calls, without performing
// additional allocations. This enables parsers to implement efficient
// I/O without excess garbage or unpredictable memory usage.
package sliding

import "io"

// The ZeroBuffer constant controls the behavior of the sliding package
// at compile time; if set to true, Dropped regions of the window buffer
// will be filled with 0.
const ZeroBuffer = true

// A Window provides a fixed-size view over the last N bytes from
// an io.Reader
type Window struct {
	R                io.Reader // underlying byte stream
	B                []byte    // underlying storage for window
	start, pos, upto int       // our current "window"
}

// The Drop method drops the oldest n bytes from the Window.  It is
// an error to use data that has been dropped from the Window, and
// cause unpredictable behavior. Any slices of a dropped region may
// be invalid after the next call to Fetch. Windows do not drop data
// automatically. A user must call Drop to free up space in a full
// Window.
//
// Drop returns the resulting window after the first n bytes are dropped.
func (w *Window) Drop(n int) []byte {
	if n > w.Len() {
		panic("cannot drop more bytes than available in window")
	}
	if ZeroBuffer {
		for i := 0; i < n; i++ {
			w.B[w.start+i] = 0
		}
	}
	w.start += n
	return w.Bytes()
}

// Fetch fills the window with n bytes from the underlying io.Reader.
// Subsequent calls to the Bytes method will return an n-element byte
// slice. Fetch over-fills the Window if additional data are available,
// such that if >n bytes are available from a previous call to Fetch,
// Read is not called on the underlying io.Reader.
//
// Fetch returns the new window, and any error encountered reading
// from the io.Reader.  If the length of the returned slice does not
// equal w.Len() + n, err will be non-nil.
//
// Fetch will relocate existing data if there is free space from a
// call to Drop, and there is not enough space to read n bytes. If n
// is greater than cap(w.B), the error returned will be io.ErrShortBuffer.
func (w *Window) Fetch(n int) ([]byte, error) {
	if w.upto-w.pos >= n {
		w.pos += n
		return w.Bytes(), nil
	}

	if w.upto-w.start == 0 {
		w.Reset()
	} else if len(w.B)-w.upto < n {
		w.shift()
	}

	realN, err := io.ReadAtLeast(w.R, w.B[w.upto:], n)
	if realN > n {
		w.pos += n
	} else {
		w.pos += realN
	}
	w.upto += realN
	return w.Bytes(), err
}

// Reader returns an io.Reader that reads exactly n bytes
// from the underlying io.Reader. If additional data was
// read in a previous call to Fetch, it is read first.
func (w *Window) Reader(n int64) io.Reader {
	overfill := w.overfill()
	return io.MultiReader(overfill, &io.LimitedReader{R: w.R, N: n - overfill.Len()})
}

type overFillReader struct {
	*Window
	buf []byte
}

func (w *Window) overfill() *overFillReader {
	return &overFillReader{w, w.B[w.pos:w.upto]}
}

func (r *overFillReader) Len() int64 { return int64(len(r.buf)) }
func (r *overFillReader) Read(p []byte) (n int, err error) {
	n = copy(p, r.buf)
	r.buf = r.buf[n:]
	if len(r.buf) == 0 {
		r.upto = r.pos
		err = io.EOF
	}
	return n, err
}

// Bytes returns the current window of bytes. The returned byte
// slice is only valid until the next call to Fetch.
func (w *Window) Bytes() []byte {
	return w.B[w.start:w.pos:w.pos]
}

// Len returns the number of bytes currently in the Window.
func (w *Window) Len() int {
	return w.pos - w.start
}

// Shift dot and any overfill to the front of the buffer
func (w *Window) shift() {
	//fmt.Printf("shifting %q %#v\n", w.Bytes(), w)
	copy(w.B, w.B[w.start:w.upto])
	w.start, w.pos, w.upto = 0, w.pos-w.start, w.upto-w.start
	if ZeroBuffer {
		for i := range w.B[w.upto:] {
			w.B[i] = 0
		}
	}
	//fmt.Printf("shifted %q %#v\n", w.Bytes(), w)
}

// Reset resets a window, so that it contains no data.
func (w *Window) Reset() {
	w.start, w.pos, w.upto = 0, 0, 0
	if ZeroBuffer {
		for i := range w.B {
			w.B[i] = 0
		}
	}
}
