package styxproto

import (
	"encoding/binary"
	"io"
	"math"
)

// bit-packing functions. caller is expected to check that the backing
// slice has enough space for whatever they're writing; these functions
// extend their argument slice by the amount of data encoded.

func puint8(b []byte, v uint8) []byte {
	b = b[:len(b)+1]
	b[len(b)-1] = v
	return b
}

func puint16(b []byte, v uint16) []byte {
	binary.LittleEndian.PutUint16(b[len(b):len(b)+2], v)
	return b[:len(b)+2]
}

func puint32(b []byte, v ...uint32) []byte {
	for _, vv := range v {
		binary.LittleEndian.PutUint32(b[len(b):len(b)+4], vv)
		b = b[:len(b)+4]
	}
	return b
}

func puint64(b []byte, v uint64) []byte {
	binary.LittleEndian.PutUint64(b[len(b):len(b)+8], v)
	return b[:len(b)+8]
}

func pbyte(b []byte, p []byte) []byte {
	if len(p) > math.MaxUint16 {
		panic(errLongString)
	}
	b = puint16(b, uint16(len(p)))
	copy(b[len(b):len(b)+len(p)], p)
	return b[:len(b)+len(p)]
}

func pqid(b []byte, qid ...Qid) []byte {
	for _, q := range qid {
		copy(b[len(b):len(b)+13], []byte(q[:13]))
		b = b[:len(b)+13]
	}
	return b
}

func pstring(b []byte, s ...string) []byte {
	for _, ss := range s {
		b = pbyte(b, []byte(ss))
	}
	return b
}

func pheader(buf []byte, mtype uint8, tag uint16, extra ...uint32) []byte {
	b := puint8(buf[:4], mtype)
	b = puint16(b, tag)
	b = puint32(b, extra...)
	return b
}

func writelen(b []byte) []byte {
	puint32(b[:0], uint32(len(b)))
	return b
}

// Send writes the 9P protocol representation of the provided message
// to w. An error is returned if there is a problem writing to w, or,
// in the case of Twrite and Rread messages, reading from the message's
// io.Reader.
func Send(w io.Writer, m Msg) error {
	if _, err := w.Write(m.bytes()); err != nil {
		return err
	}
	if r, ok := m.(io.Reader); ok {
		if _, err := io.Copy(w, r); err != nil {
			return err
		}
	}
	return nil
}
