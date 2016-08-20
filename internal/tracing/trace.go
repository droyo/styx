// Package tracing provides tracing of sent and received 9P
// messages.
package tracing

import (
	"io"

	"aqwari.net/net/styx/styxproto"
)

// A TraceFn can be used to access 9P messages as they
// pass through a styxproto.Encoder or a styxproto.Decoder.
// Messages are not copied; a TraceFn should not modify
// msg, and msg should not be accessed after the TraceFn
// returns.
type TraceFn func(msg styxproto.Msg)

const kilobyte = 1 << 10

// Decoder creates a new styxproto.Decoder that traces messages
// received on r.
func Decoder(r io.Reader, fn TraceFn) *styxproto.Decoder {
	rd, wr := io.Pipe()
	decoderInput := styxproto.NewDecoderSize(r, 8*kilobyte)
	decoderTrace := styxproto.NewDecoderSize(rd, 8*kilobyte)
	go func() {
		for decoderInput.Next() {
			for _, m := range decoderInput.Messages() {
				fn(m)
				styxproto.Write(wr, m)
			}
		}
		wr.Close()
	}()
	return decoderTrace
}

// Encoder creates a new styxproto.Encoder that traces messages
// before writing them to w.
func Encoder(w io.Writer, fn TraceFn) *styxproto.Encoder {
	rd, wr := io.Pipe()
	encoder := styxproto.NewEncoder(wr)
	decoder := styxproto.NewDecoderSize(rd, 8*kilobyte)
	go func() {
		for decoder.Next() {
			for _, m := range decoder.Messages() {
				fn(m)
				styxproto.Write(w, m)
			}
		}
	}()
	return encoder
}
