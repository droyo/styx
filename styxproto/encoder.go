package styxproto

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// Create 9P messages

var (
	errMaxSize    = errors.New("message size larger than max uint32")
	errLongString = errors.New("string longer than max uint16")
	errMaxCount   = errors.New("count larger than max uint32")
)

// Produce 9P2000 messages

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

func pheader(buf []byte, mtype uint8, tag uint16, more ...uint32) []byte {
	b := puint8(buf[:4], mtype)
	b = puint16(b, tag)
	for _, v := range more {
		b = puint32(b, v)
	}
	return b
}

func writelen(b []byte) []byte {
	puint32(b[:0], uint32(len(b)))
	return b
}

// NewTversion creates a new Tversion message. The
// Tversion's tag is set to NoTag. Any space left over
// in buf is returned.
func NewTversion(buf []byte, msize uint32, version string) (Tversion, []byte, error) {
	if len(version) > MaxVersionLen {
		return nil, buf, errLongVersion
	}
	if len(buf) < minSizeLUT[msgTversion]+len(version) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTversion, NoTag, msize)
	b = pstring(b, version)
	writelen(b)

	return Tversion(b), buf[len(b):], nil
}

// NewRversion creates a new Rversion message. The
// Rversion's tag is set to NoTag.
func NewRversion(buf []byte, msize uint32, version string) (Rversion, []byte, error) {
	m, rest, err := NewTversion(buf, msize, version)
	if len(m) > 4 {
		m[4] = msgRversion
	}
	return Rversion(m), rest, err
}

// NewTauth creates a new Tauth message.
func NewTauth(buf []byte, tag uint16, afid uint32, uname, aname string) (Tauth, []byte, error) {
	if len(uname) > MaxUidLen {
		return nil, buf, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return nil, buf, errLongAname
	}
	sz := minSizeLUT[msgTauth] + len(uname) + len(aname)
	if len(buf) < sz {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTauth, tag, afid)
	b = pstring(b, uname, aname)
	writelen(b)

	return Tauth(b), buf[len(b):], nil
}

// NewRauth creates a new Rauth message.
func NewRauth(buf []byte, tag uint16, qid Qid) (Rauth, []byte, error) {
	if len(buf) < maxSizeLUT[msgRauth] {
		return nil, nil, io.ErrShortBuffer
	}
	b := pheader(buf, msgRauth, tag)
	b = pqid(b, qid)
	writelen(b)

	return Rauth(b), buf[len(b):], nil
}

// NewTattach creates a new Tattach message
func NewTattach(buf []byte, tag uint16, fid, afid uint32, uname, aname string) (Tattach, []byte, error) {
	if len(uname) > MaxUidLen {
		return nil, buf, errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return nil, buf, errLongAname
	}
	sz := minSizeLUT[msgTattach] + len(uname) + len(aname)
	if len(buf) < sz {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTattach, tag, fid, afid)
	b = pstring(b, uname, aname)
	writelen(b)

	return Tattach(b), buf[len(b):], nil
}

// NewRattach creates a new Rattach message
func NewRattach(buf []byte, tag uint16, qid Qid) (Rattach, []byte, error) {
	m, rest, err := NewRauth(buf, tag, qid)
	if len(m) > 4 {
		m[5] = msgRattach
	}
	return Rattach(m), rest, err
}

// NewRerror creates a new Rerror message
func NewRerror(buf []byte, tag uint16, ename string) (Rerror, []byte, error) {
	if len(ename) > MaxErrorLen {
		return nil, buf, errLongError
	}
	if len(buf) < minSizeLUT[msgRerror]+len(ename) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRerror, tag)
	b = pstring(b, ename)
	writelen(b)

	return Rerror(b), buf[len(b):], nil
}

func NewTflush(buf []byte, tag, oldtag uint16) (Tflush, []byte, error) {
	if len(buf) < maxSizeLUT[msgTflush] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTflush, tag)
	b = puint16(b, oldtag)
	writelen(b)

	return Tflush(b), buf[len(b):], nil
}

func NewRflush(buf []byte, tag uint16) (Rflush, []byte, error) {
	if len(buf) < maxSizeLUT[msgRflush] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRflush, tag)
	writelen(b)

	return Rflush(b), buf[len(b):], nil
}

func NewTwalk(buf []byte, tag uint16, fid, newfid uint32, wname ...string) (Twalk, []byte, error) {
	if len(wname) > MaxWElem {
		return nil, buf, errMaxWElem
	}
	space := len(buf) - minSizeLUT[msgTwalk]
	for _, v := range wname {
		if len(v) > MaxFilenameLen {
			return nil, buf, errLongFilename
		}
		if space < 0 {
			break
		}
	}
	if space < 0 {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTwalk, tag, fid, newfid)
	b = puint16(b, uint16(len(wname)))
	b = pstring(b, wname...)
	writelen(b)

	return Twalk(b), buf[len(b):], nil
}

func NewRwalk(buf []byte, tag uint16, wqid ...Qid) (Rwalk, []byte, error) {
	if len(wqid) > MaxWElem {
		return nil, buf, errMaxWElem
	}
	if len(buf) < minSizeLUT[msgRwalk]+13*len(wqid) {
		return nil, buf, io.ErrShortBuffer
	}

	b := pheader(buf, msgRwalk, tag)
	b = puint16(b, uint16(len(wqid)))
	b = pqid(b, wqid...)
	writelen(b)

	return Rwalk(b), buf[len(b):], nil
}

func NewTopen(buf []byte, tag uint16, fid uint32, mode uint8) (Topen, []byte, error) {
	if len(buf) < maxSizeLUT[msgTopen] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTopen, tag, fid)
	b = puint8(b, mode)
	writelen(b)

	return Topen(b), buf[len(b):], nil
}

func NewRopen(buf []byte, tag uint16, qid Qid, iounit uint32) (Ropen, []byte, error) {
	if len(buf) < maxSizeLUT[msgRopen] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRopen, tag)
	b = pqid(b, qid)
	b = puint32(b, iounit)
	writelen(b)

	return Ropen(b), buf[len(b):], nil
}

func NewTcreate(buf []byte, tag uint16, fid uint32, name string, perm uint32, mode uint8) (Tcreate, []byte, error) {
	if len(name) > MaxFilenameLen {
		return nil, buf, errLongFilename
	}
	if len(buf) < minSizeLUT[msgTcreate]+len(name) {
		return nil, buf, io.ErrShortBuffer
	}

	b := pheader(buf, msgTcreate, tag, fid)
	b = pstring(b, name)
	b = puint32(b, perm)
	b = puint8(b, mode)
	writelen(b)

	return Tcreate(b), buf[len(b):], nil
}

func NewRcreate(buf []byte, tag uint16, qid Qid, iounit uint32) (Rcreate, []byte, error) {
	if len(buf) < maxSizeLUT[msgRcreate] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRcreate, tag)
	b = pqid(b, qid)
	b = puint32(b, iounit)
	writelen(b)

	return Rcreate(b), buf[len(b):], nil
}

// NewTread creates a New Tread message The offset must be smaller
// than MaxOffset.
func NewTread(buf []byte, tag uint16, fid uint32, offset, count int64) (Tread, []byte, error) {
	if len(buf) < maxSizeLUT[msgTread] {
		return nil, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return nil, buf, errMaxCount
	}
	b := pheader(buf, msgTread, tag, fid)
	b = puint64(b, uint64(offset))
	b = puint32(b, uint32(count))
	writelen(b)

	return Tread(b), buf[len(b):], nil
}

func NewRread(buf []byte, tag uint16, count int64, data io.Reader) (Rread, []byte, error) {
	if len(buf) < minSizeLUT[msgRread] {
		return Rread{}, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return Rread{}, buf, errTooBig
	}
	b := pheader(buf, msgRread, tag, uint32(count))
	if math.MaxUint32-int64(count) < int64(len(b)) {
		return Rread{}, buf, errTooBig
	}
	puint32(b[:0], uint32(len(b))+uint32(count))

	return Rread{Reader: io.LimitReader(data, int64(count)), msg: b}, buf[len(b):], nil
}

func NewTwrite(buf []byte, tag uint16, fid uint32, offset, count int64, data io.Reader) (Twrite, []byte, error) {
	if len(buf) < minSizeLUT[msgTwrite] {
		return Twrite{}, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return Twrite{}, buf, errTooBig
	}
	b := pheader(buf, msgTwrite, tag, fid)
	b = puint64(b, uint64(offset))
	b = puint32(b, uint32(count))
	if math.MaxUint32-int64(count) < int64(len(b)) {
		return Twrite{}, buf, errTooBig
	}
	puint32(b[:0], uint32(len(b))+uint32(count))

	return Twrite{Reader: io.LimitReader(data, int64(count)), msg: b}, buf[len(b):], nil
}

func NewRwrite(buf []byte, tag uint16, count int64) (Rwrite, []byte, error) {
	if len(buf) < maxSizeLUT[msgRwrite] {
		return nil, buf, io.ErrShortBuffer
	}
	if math.MaxUint32-int64(maxSizeLUT[msgRwrite]) < count {
		return nil, buf, errMaxCount
	}
	b := pheader(buf, msgRwrite, tag, uint32(count))
	writelen(b)

	return Rwrite(b), buf[len(b):], nil
}

func NewTclunk(buf []byte, tag uint16, fid uint32) (Tclunk, []byte, error) {
	if len(buf) < maxSizeLUT[msgTclunk] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTclunk, tag, fid)
	writelen(b)

	return Tclunk(b), buf[len(b):], nil
}

func NewRclunk(buf []byte, tag uint16) (Rclunk, []byte, error) {
	if len(buf) < maxSizeLUT[msgRclunk] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRclunk, tag)
	writelen(b)

	return Rclunk(b), buf[len(b):], nil
}

func NewTremove(buf []byte, tag uint16, fid uint32) (Tremove, []byte, error) {
	if len(buf) < maxSizeLUT[msgTremove] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTremove, tag, fid)
	writelen(b)

	return Tremove(b), buf[len(b):], nil
}

func NewRremove(buf []byte, tag uint16) (Rremove, []byte, error) {
	if len(buf) < maxSizeLUT[msgRremove] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRremove, tag)
	writelen(b)

	return Rremove(b), buf[len(b):], nil
}

func NewTstat(buf []byte, tag uint16, fid uint32) (Tstat, []byte, error) {
	if len(buf) < maxSizeLUT[msgTstat] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTstat, tag, fid)
	writelen(b)

	return Tstat(b), buf[len(b):], nil
}

func NewRstat(buf []byte, tag uint16, stat Stat) (Rstat, []byte, error) {
	if len(stat) > maxStatLen {
		return nil, buf, errLongStat
	}
	if len(stat) < minStatLen {
		return nil, buf, errShortStat
	}
	if len(buf) < minSizeLUT[msgRstat]+len(stat) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRstat, tag)
	b = pbyte(b, stat)
	writelen(b)

	return Rstat(b), buf[len(b):], nil
}

func NewTwstat(buf []byte, tag uint16, fid uint32, stat Stat) (Twstat, []byte, error) {
	if len(stat) > maxStatLen {
		return nil, buf, errLongStat
	}
	if len(stat) < minStatLen {
		return nil, buf, errShortStat
	}
	if len(buf) < minSizeLUT[msgTwstat]+len(stat) {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgTwstat, tag)
	b = pbyte(b, stat)
	writelen(b)

	return Twstat(b), buf[len(b):], nil
}

func NewRwstat(buf []byte, tag uint16) (Rwstat, []byte, error) {
	if len(buf) < maxSizeLUT[msgRwstat] {
		return nil, buf, io.ErrShortBuffer
	}
	b := pheader(buf, msgRwstat, tag)
	writelen(b)

	return Rwstat(b), buf[len(b):], nil
}
