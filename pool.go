package styx

import (
	"bufio"
	"io"
	"sync"

	"aqwari.net/net/styx/styxproto"
)

var (
	decoderPool     sync.Pool
	bufioWriterPool sync.Pool
)

func newDecoder(r io.Reader) *styxproto.Decoder {
	if v := decoderPool.Get(); v != nil {
		br := v.(*styxproto.Decoder)
		br.Reset(r)
		return br
	}
	return styxproto.NewDecoderSize(r, styxproto.MinBufSize)
}

func newBufioWriter(w io.Writer) *bufio.Writer {
	if v := bufioWriterPool.Get(); v != nil {
		bw := v.(*bufio.Writer)
		bw.Reset(w)
		return bw
	}
	return bufio.NewWriterSize(w, styxproto.MinBufSize)
}

func putBufioWriter(w *bufio.Writer) {
	w.Reset(nil)
	bufioWriterPool.Put(w)
}

func putDecoder(d *styxproto.Decoder) {
	d.Reset(nil)
	decoderPool.Put(d)
}
