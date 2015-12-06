package styxproto

import (
	"encoding/binary"
	"io"
	"math"
)

// Shorthand for parsing numbers
var (
	guint16 = binary.LittleEndian.Uint16
	guint32 = binary.LittleEndian.Uint32
	guint64 = binary.LittleEndian.Uint64

	buint16 = binary.LittleEndian.PutUint16
	buint32 = binary.LittleEndian.PutUint32
	buint64 = binary.LittleEndian.PutUint64
)

// bit-packing functions. caller is expected to check that the backing
// slice has enough space for whatever they're writing; these functions
// extend their argument slice by the amount of data encoded.

func puint8(w io.Writer, v uint8) {
	w.Write([]byte{v})
}

func puint16(w io.Writer, v uint16) {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf[:], v)
	w.Write(buf[:])
}

func puint32(w io.Writer, v ...uint32) {
	buf := make([]byte, 4)
	for _, vv := range v {
		binary.LittleEndian.PutUint32(buf, vv)
		w.Write(buf)
	}
}

func puint64(w io.Writer, v uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	w.Write(buf)
}

func pbyte(w io.Writer, p []byte) {
	if len(p) > math.MaxUint16 {
		panic(errLongString)
	}
	puint16(w, uint16(len(p)))
	w.Write(p)
}

func pqid(w io.Writer, qids ...Qid) {
	for _, q := range qids {
		w.Write(q[:13])
	}
}

func pstring(w io.Writer, s ...string) {
	for _, ss := range s {
		puint16(w, uint16(len(ss)))
		io.WriteString(w, ss)
	}
}

func pheader(w io.Writer, size uint32, mtype uint8, tag uint16, extra ...uint32) {
	puint32(w, size)
	puint8(w, mtype)
	puint16(w, tag)
	puint32(w, extra...)
}
