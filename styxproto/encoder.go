package styxproto

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"sync"
)

// An Encoder writes 9P messages to an underlying
// io.Writer.
type Encoder struct {
	MaxSize int64
	mu      sync.Mutex
	w       *bufio.Writer
}

// NewEncoder creates a new Encoder that writes 9P messages
// to w. Encoders are safe to use from multiple goroutines.
// An Encoder does not perform any buffering of messages.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w: bufio.NewWriterSize(w, MinBufSize),
	}
}

// Err returns the first error encountered by an Encoder
// when writing data to its underlying io.Writer.
func (enc *Encoder) Err() error {
	enc.mu.Lock()
	defer enc.mu.Unlock()
	_, err := enc.w.Write(nil)
	return err
}

// Flush flushes any buffered data to the underlying io.Writer.
func (enc *Encoder) Flush() error {
	enc.mu.Lock()
	defer enc.mu.Unlock()
	return enc.w.Flush()
}

// Tversion writes a Tversion message to the underlying io.Writer.
// The Tag of the written message will be NoTag. If the version string
// is longer than MaxVersionLen, it is truncated.
func (enc *Encoder) Tversion(msize uint32, version string) {
	if len(version) > MaxVersionLen {
		version = version[:MaxVersionLen]
	}
	size := uint32(minSizeLUT[msgTversion] + len(version))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTversion, NoTag, msize)
	pstring(enc.w, version)
}

// Rversion writes an Rversion message to the underlying io.Writer.
// If the version string is longer than MaxVerisonLen, it is truncated.
func (enc *Encoder) Rversion(msize uint32, version string) {
	if len(version) > MaxVersionLen {
		version = version[:MaxVersionLen]
	}
	size := uint32(minSizeLUT[msgRversion] + len(version))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRversion, NoTag, msize)
	pstring(enc.w, version)
}

// Tauth writes a Tauth message to enc's underlying io.Writer. The uname
// and aname parameters will be truncated if they are longer than MaxUidLen
// and MaxAttachLen, respectively.
func (enc *Encoder) Tauth(tag uint16, afid uint32, uname, aname string) {
	if len(uname) > MaxUidLen {
		uname = uname[:MaxUidLen]
	}
	if len(aname) > MaxAttachLen {
		aname = aname[:MaxAttachLen]
	}
	size := uint32(minSizeLUT[msgTauth] + len(uname) + len(aname))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTauth, tag, afid)
	pstring(enc.w, uname, aname)
}

// Rauth writes a new Rauth message to the underlying io.Writer.
func (enc *Encoder) Rauth(tag uint16, qid Qid) {
	size := uint32(maxSizeLUT[msgRauth])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRauth, tag)
	pqid(enc.w, qid)
}

// Tattach writes a new Tattach message to the underlying io.Writer.
// If the client does not want to authenticate, afid should be NoFid.
// The uname and aname parameters will be truncated if they are longer
// than MaxUidLen and MaxAttachLen, respectively.
func (enc *Encoder) Tattach(tag uint16, fid, afid uint32, uname, aname string) {
	if len(uname) > MaxUidLen {
		uname = uname[:MaxUidLen]
	}
	if len(aname) > MaxAttachLen {
		aname = aname[:MaxAttachLen]
	}
	size := uint32(minSizeLUT[msgTattach] + len(uname) + len(aname))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTattach, tag, fid, afid)
	pstring(enc.w, uname, aname)
}

// Rattach writes a new Rattach message to the underlying io.Writer.
func (enc *Encoder) Rattach(tag uint16, qid Qid) {
	size := uint32(maxSizeLUT[msgRattach])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRattach, tag)
	pqid(enc.w, qid)
}

// Rerror writes a new Rerror message to the underlying io.Writer. Errfmt may
// be a printf-style format string, with values filled in from the
// argument list v. If the error string is longer than MaxErrorLen
// bytes, it is truncated.
func (enc *Encoder) Rerror(tag uint16, errfmt string, v ...interface{}) {
	ename := errfmt
	if len(v) > 0 {
		ename = fmt.Sprintf(errfmt, v...)
	}
	if len(ename) > MaxErrorLen {
		ename = ename[:MaxErrorLen]
	}
	size := uint32(minSizeLUT[msgRerror] + len(ename))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRerror, tag)
	pstring(enc.w, ename)
}

// Tflush writes a new Tflush message to the underlying io.Writer.
func (enc *Encoder) Tflush(tag, oldtag uint16) {
	size := uint32(maxSizeLUT[msgTflush])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTflush, tag)
	puint16(enc.w, oldtag)
}

// Rflush writes a new Rflush message to the underlying io.Writer.
func (enc *Encoder) Rflush(tag uint16) {
	size := uint32(maxSizeLUT[msgRflush])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRflush, tag)
}

// Twalk writes a new Twalk message to the underlying io.Writer. An
// error is returned if wname is longer than MaxWElem elements, or if
// any single element in wname is longer than MaxFilenameLen bytes
// long.
func (enc *Encoder) Twalk(tag uint16, fid, newfid uint32, wname ...string) error {
	if len(wname) > MaxWElem {
		return errMaxWElem
	}
	size := uint32(minSizeLUT[msgTwalk])
	for _, v := range wname {
		if len(v) > MaxFilenameLen {
			return errLongFilename
		}
		size += 2
		size += uint32(len(v))
	}

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTwalk, tag, fid, newfid)
	puint16(enc.w, uint16(len(wname)))
	pstring(enc.w, wname...)

	return nil
}

// Rwalk writes a new Rwalk message to the underlying io.Writer. An error is returned if wqid
// has more than MaxWElem elements.
func (enc *Encoder) Rwalk(tag uint16, wqid ...Qid) error {
	if len(wqid) > MaxWElem {
		return errMaxWElem
	}
	size := uint32(minSizeLUT[msgRwalk] + 13*len(wqid))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRwalk, tag)
	puint16(enc.w, uint16(len(wqid)))
	pqid(enc.w, wqid...)

	return nil
}

// NewTopen writes a new Topen message to the underlying io.Writer.
func (enc *Encoder) Topen(tag uint16, fid uint32, mode uint8) {
	size := uint32(maxSizeLUT[msgTopen])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTopen, tag, fid)
	puint8(enc.w, mode)
}

// Ropen writes a new Ropen message to the underlying io.Writer.
func (enc *Encoder) Ropen(tag uint16, qid Qid, iounit uint32) {
	size := uint32(maxSizeLUT[msgRopen])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRopen, tag)
	pqid(enc.w, qid)
	puint32(enc.w, iounit)
}

// Tcreate writes a new Tcreate message to the underlying io.Writer. If
// name is longer than MaxFilenameLen, it is truncated.
func (enc *Encoder) Tcreate(tag uint16, fid uint32, name string, perm uint32, mode uint8) {
	if len(name) > MaxFilenameLen {
		name = name[:MaxFilenameLen]
	}
	size := uint32(minSizeLUT[msgTcreate] + len(name))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTcreate, tag, fid)
	pstring(enc.w, name)
	puint32(enc.w, perm)
	puint8(enc.w, mode)
}

// Rcreate writes a new Rcreate message to the underlying io.Writer.
func (enc *Encoder) Rcreate(tag uint16, qid Qid, iounit uint32) {
	size := uint32(maxSizeLUT[msgRcreate])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRcreate, tag)
	pqid(enc.w, qid)
	puint32(enc.w, iounit)
}

// Tread writes a new Tread message to the underlying io.Writer. An error is returned
// if count is greater than the maximum value of a 32-bit unsigned integer.
func (enc *Encoder) Tread(tag uint16, fid uint32, offset, count int64) error {
	if count > math.MaxUint32 {
		return errMaxCount
	}
	size := uint32(maxSizeLUT[msgTread])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTread, tag, fid)
	puint64(enc.w, uint64(offset))
	puint32(enc.w, uint32(count))
	return nil
}

// Rread writes a new Rread message to the underlying io.Writer.
// If len(data) is greater than the Encoder's Msize, it is broken up
// into multiple Rread messages. Rread returns the number of bytes
// written, plus any IO errors encountered.
func (enc *Encoder) Rread(tag uint16, data []byte) (n int, err error) {
	var nchunk int

	msize := enc.MaxSize
	if msize < MinBufSize {
		// NOTE(droyo) I would be OK with a panic here; it implies
		// the calling code is sending a non-Rversion/Tversion message
		// on an uninitialized connection and can lead to unexpected
		// behavior.
		msize = MinBufSize
	}
	msize -= int64(minSizeLUT[msgRread])
	for first := true; first || len(data) > 0; {
		first = false
		chunk := data
		if int64(len(data)) > msize {
			chunk = data[:msize]
		}
		size := uint32(minSizeLUT[msgRread]) + uint32(len(chunk))

		enc.mu.Lock()
		pheader(enc.w, size, msgRread, tag, uint32(len(chunk)))
		nchunk, err = enc.w.Write(chunk)
		enc.mu.Unlock()

		n += nchunk
		if err != nil {
			break
		}
		data = data[len(chunk):]
	}
	return n, err
}

// Twrite writes a Twrite message to the underlying io.Writer. An error is returned
// if the message cannot fit inside a single 9P message.
func (enc *Encoder) Twrite(tag uint16, fid uint32, offset int64, data []byte) (int, error) {
	if math.MaxUint32-minSizeLUT[msgTwrite] < len(data) {
		return 0, errTooBig
	}
	size := uint32(minSizeLUT[msgTwrite]) + uint32(len(data))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTwrite, tag, fid)
	puint64(enc.w, uint64(offset))
	puint32(enc.w, uint32(len(data)))
	return enc.w.Write(data)
}

// Rwrite writes an Rwrite message to the underlying io.Writer.
// If count is greater than the maximum value of a 32-bit unsigned
// integer, a run-time panic occurs.
func (enc *Encoder) Rwrite(tag uint16, count int64) {
	if count > math.MaxUint32 {
		panic(errMaxCount)
	}
	size := uint32(maxSizeLUT[msgRwrite])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRwrite, tag, uint32(count))
}

// Tclunk writes a Tclunk message to the underlying io.Writer.
func (enc *Encoder) Tclunk(tag uint16, fid uint32) {
	size := uint32(maxSizeLUT[msgTclunk])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTclunk, tag, fid)
}

// Rclunk writes an Rclunk message to the underlying io.Writer.
func (enc *Encoder) Rclunk(tag uint16) {
	size := uint32(maxSizeLUT[msgRclunk])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRclunk, tag)
}

// Tremove writes a Tremove message to the underlying io.Writer.
func (enc *Encoder) Tremove(tag uint16, fid uint32) {
	size := uint32(maxSizeLUT[msgTremove])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTremove, tag, fid)
}

// Rremove writes an Rremove message to the underlying io.Writer.
func (enc *Encoder) Rremove(tag uint16) {
	size := uint32(maxSizeLUT[msgRremove])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRremove, tag)
}

// Tstat writes a Tstat message to the underlying io.Writer.
func (enc *Encoder) Tstat(tag uint16, fid uint32) {
	size := uint32(maxSizeLUT[msgTstat])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTstat, tag, fid)
}

// Rstat writes an Rstat message to the underlying io.Writer.
// If the Stat is larger than the maximum size allowed by
// the NewStat function, a run-time panic occurs.
func (enc *Encoder) Rstat(tag uint16, stat Stat) {
	if len(stat) > MaxStatLen {
		panic(errLongStat)
	}
	if len(stat) < minStatLen {
		panic(errShortStat)
	}
	size := uint32((minSizeLUT[msgRstat] - minStatLen) + len(stat))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRstat, tag)
	pbyte(enc.w, stat)
}

// Twstat writes a Twstat message to the underlying io.Writer.
// If the Stat is larger than the maximum size allowed by the
// NewStat function, a run-time panic occurs.
func (enc *Encoder) Twstat(tag uint16, fid uint32, stat Stat) {
	if len(stat) > MaxStatLen {
		panic(errLongStat)
	}
	if len(stat) < minStatLen {
		panic(errShortStat)
	}
	size := uint32(minSizeLUT[msgTwstat] + 2 + len(stat))

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgTwstat, tag, fid)
	pbyte(enc.w, stat)
}

// Rwstat writes an Rwstat message to the underlying io.Writer.
func (enc *Encoder) Rwstat(tag uint16) {
	size := uint32(maxSizeLUT[msgRwstat])

	enc.mu.Lock()
	defer enc.mu.Unlock()

	pheader(enc.w, size, msgRwstat, tag)
}
