package styxproto

import (
	"fmt"
	"io"
	"math"

	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/internal/wire"
)

// An Encoder writes 9P messages to an underlying
// io.Writer.
type Encoder struct {
	w  *wire.TxWriter
	ew *util.ErrWriter
}

// NewEncoder creates a new Encoder that writes 9P messages
// to w. Encoders are safe to use from multiple goroutines.
// An Encoder does not perform any buffering of messages.
func NewEncoder(w io.Writer) *Encoder {
	ew := util.ErrWriter{W: w}
	return &Encoder{
		w:  &wire.TxWriter{W: &ew},
		ew: &ew,
	}
}

// Err returns the first error encountered by an Encoder
// when writing data to its underlying io.Writer.
func (enc *Encoder) Err() error {
	return enc.ew.Err
}

// Tversion writes a Tversion message to the underlying io.Writer.
// The Tag of the written message will be NoTag.
func (enc *Encoder) Tversion(msize uint32, version string) error {
	if len(version) > MaxVersionLen {
		return errLongVersion
	}
	size := uint32(minSizeLUT[msgTversion] + len(version))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTversion, NoTag, msize)
	pstring(tx, version)
	return enc.Err()
}

// Rversion writes an Rversion message to the underlying io.Writer.
func (enc *Encoder) Rversion(msize uint32, version string) error {
	if len(version) > MaxVersionLen {
		return errLongVersion
	}
	size := uint32(minSizeLUT[msgRversion] + len(version))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRversion, NoTag, msize)
	pstring(tx, version)
	return enc.Err()
}

// Tauth writes a Tauth message to enc's underlying io.Writer. The uname
// and aname parameters must be shorter than MaxUidLen and MaxAttachLen,
// respectively.
func (enc *Encoder) Tauth(tag uint16, afid uint32, uname, aname string) error {
	if len(uname) > MaxUidLen {
		return errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return errLongAname
	}
	size := uint32(minSizeLUT[msgTauth] + len(uname) + len(aname))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTauth, tag, afid)
	pstring(tx, uname, aname)
	return enc.Err()
}

// Rauth writes a new Rauth message to the underlying io.Writer.
func (enc *Encoder) Rauth(tag uint16, qid Qid) error {
	size := uint32(maxSizeLUT[msgRauth])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRauth, tag)
	pqid(tx, qid)
	return enc.Err()
}

// Tattach writes a new Tattach message to the underlying io.Writer. If the client does not want
// to authenticate, afid should be NoFid.
func (enc *Encoder) Tattach(tag uint16, fid, afid uint32, uname, aname string) error {
	if len(uname) > MaxUidLen {
		return errLongUsername
	}
	if len(aname) > MaxAttachLen {
		return errLongAname
	}
	size := uint32(minSizeLUT[msgTattach] + len(uname) + len(aname))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTattach, tag, fid, afid)
	pstring(tx, uname, aname)
	return enc.Err()
}

// Rattach writes a new Rattach message to the underlying io.Writer.
func (enc *Encoder) Rattach(tag uint16, qid Qid) error {
	size := uint32(maxSizeLUT[msgRattach])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRattach, tag)
	pqid(tx, qid)
	return enc.Err()
}

// Rerror writes a new Rerror message to the underlying io.Writer. Errfmt may
// be a printf-style format string, with values filled in from the
// argument list v. If the error string is longer than MaxErrorLen
// bytes, it is truncated.
func (enc *Encoder) Rerror(tag uint16, errfmt string, v ...interface{}) error {
	ename := errfmt
	if len(v) > 0 {
		ename = fmt.Sprintf(errfmt, v...)
	}
	if len(ename) > MaxErrorLen {
		ename = ename[:MaxErrorLen]
	}
	size := uint32(minSizeLUT[msgRerror] + len(ename))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRerror, tag)
	pstring(tx, ename)

	return enc.Err()
}

// Tflush writes a new Tflush message to the underlying io.Writer.
func (enc *Encoder) Tflush(tag, oldtag uint16) error {
	size := uint32(maxSizeLUT[msgTflush])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTflush, tag)
	puint16(tx, oldtag)
	return enc.Err()
}

// Rflush writes a new Rflush message to the underlying io.Writer.
func (enc *Encoder) Rflush(tag uint16) error {
	size := uint32(maxSizeLUT[msgRflush])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRflush, tag)
	return enc.Err()
}

// Twalk writes a new Twalk message to the underlying io.Writer. An error is returned
// if wname is longer than MaxWElem elements, or if any single element in
// wname is longer than MaxFilenameLen bytes long.
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

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTwalk, tag, fid, newfid)
	puint16(tx, uint16(len(wname)))
	pstring(tx, wname...)

	return enc.Err()
}

// Rwalk writes a new Rwalk message to the underlying io.Writer. An error is returned if wqid
// has more than MaxWElem elements.
func (enc *Encoder) Rwalk(tag uint16, wqid ...Qid) error {
	if len(wqid) > MaxWElem {
		return errMaxWElem
	}
	size := uint32(minSizeLUT[msgRwalk] + 13*len(wqid))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRwalk, tag)
	puint16(tx, uint16(len(wqid)))
	pqid(tx, wqid...)

	return enc.Err()
}

// NewTopen writes a new Topen message to the underlying io.Writer.
func (enc *Encoder) Topen(tag uint16, fid uint32, mode uint8) error {
	size := uint32(maxSizeLUT[msgTopen])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTopen, tag, fid)
	puint8(tx, mode)

	return enc.Err()
}

// Ropen writes a new Ropen message to the underlying io.Writer.
func (enc *Encoder) Ropen(tag uint16, qid Qid, iounit uint32) error {
	size := uint32(maxSizeLUT[msgRopen])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRopen, tag)
	pqid(tx, qid)
	puint32(tx, iounit)

	return enc.Err()
}

// Tcreate writes a new Tcreate message to the underlying io.Writer.
func (enc *Encoder) Tcreate(tag uint16, fid uint32, name string, perm uint32, mode uint8) error {
	if len(name) > MaxFilenameLen {
		return errLongFilename
	}
	size := uint32(minSizeLUT[msgTcreate] + len(name))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTcreate, tag, fid)
	pstring(tx, name)
	puint32(tx, perm)
	puint8(tx, mode)

	return enc.Err()
}

// Rcreate writes a new Rcreate message to the underlying io.Writer.
func (enc *Encoder) Rcreate(tag uint16, qid Qid, iounit uint32) error {
	size := uint32(maxSizeLUT[msgRcreate])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRcreate, tag)
	pqid(tx, qid)
	puint32(tx, iounit)

	return enc.Err()
}

// Tread writes a new Tread message to the underlying io.Writer. An error is returned
// if count is greater than the maximum value of a 32-bit unsigned integer.
func (enc *Encoder) Tread(tag uint16, fid uint32, offset, count int64) error {
	if count > math.MaxUint32 {
		return errMaxCount
	}
	size := uint32(maxSizeLUT[msgTread])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTread, tag, fid)
	puint64(tx, uint64(offset))
	puint32(tx, uint32(count))
	return enc.Err()
}

// Rread writes a new Rread message to the underlying io.Writer. An error is returned
// if the message cannot fit inside a single 9P message.
func (enc *Encoder) Rread(tag uint16, data []byte) error {
	if math.MaxUint32-minSizeLUT[msgTwrite] < len(data) {
		return errTooBig
	}
	size := uint32(minSizeLUT[msgRread]) + uint32(len(data))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRread, tag, uint32(len(data)))
	tx.Write(data)
	return enc.Err()
}

// Twrite writes a Twrite message to the underlying io.Writer. An error is returned
// if the message cannot fit inside a single 9P message.
func (enc *Encoder) Twrite(tag uint16, fid uint32, offset int64, data []byte) error {
	if math.MaxUint32-minSizeLUT[msgTwrite] < len(data) {
		return errTooBig
	}
	size := uint32(minSizeLUT[msgTwrite]) + uint32(len(data))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTwrite, tag, fid)
	puint64(tx, uint64(offset))
	puint32(tx, uint32(len(data)))
	tx.Write(data)
	return enc.Err()
}

// Rwrite writes an Rwrite message to the underlying io.Writer. An error is returned
// if count is greater than the maximum value of a 32-bit unsigned
// integer.
func (enc *Encoder) Rwrite(tag uint16, count int64) error {
	if count > math.MaxUint32 {
		return errMaxCount
	}
	size := uint32(maxSizeLUT[msgRwrite])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRwrite, tag, uint32(count))

	return enc.Err()
}

// Tclunk writes a Tclunk message to the underlying io.Writer.
func (enc *Encoder) Tclunk(tag uint16, fid uint32) error {
	size := uint32(maxSizeLUT[msgTclunk])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTclunk, tag, fid)
	return enc.Err()
}

// Rclunk writes an Rclunk message to the underlying io.Writer.
func (enc *Encoder) Rclunk(tag uint16) error {
	size := uint32(maxSizeLUT[msgRclunk])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRclunk, tag)
	return enc.Err()
}

// Tremove writes a Tremove message to the underlying io.Writer.
func (enc *Encoder) Tremove(tag uint16, fid uint32) error {
	size := uint32(maxSizeLUT[msgTremove])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTremove, tag, fid)
	return enc.Err()
}

// Rremove writes an Rremove message to the underlying io.Writer.
func (enc *Encoder) Rremove(tag uint16) error {
	size := uint32(maxSizeLUT[msgRremove])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRremove, tag)
	return enc.Err()
}

// Tstat writes a Tstat message to the underlying io.Writer.
func (enc *Encoder) Tstat(tag uint16, fid uint32) error {
	size := uint32(maxSizeLUT[msgTstat])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTstat, tag, fid)
	return enc.Err()
}

// Rstat writes an Rstat message to the underlying io.Writer.
func (enc *Encoder) Rstat(tag uint16, stat Stat) error {
	if len(stat) > maxStatLen {
		return errLongStat
	}
	if len(stat) < minStatLen {
		return errShortStat
	}
	size := uint32((minSizeLUT[msgRstat] - minStatLen) + len(stat))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRstat, tag)
	pbyte(tx, stat)

	return enc.Err()
}

// Twstat writes a Twstat message to the underlying io.Writer.
func (enc *Encoder) Twstat(tag uint16, fid uint32, stat Stat) error {
	if len(stat) > maxStatLen {
		return errLongStat
	}
	if len(stat) < minStatLen {
		return errShortStat
	}
	size := uint32(minSizeLUT[msgTwstat] + len(stat))

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgTwstat, tag)
	pbyte(tx, stat)
	return enc.Err()
}

// Rwstat writes an Rwstat message to the underlying io.Writer.
func (enc *Encoder) Rwstat(tag uint16) error {
	size := uint32(maxSizeLUT[msgRwstat])

	tx := enc.w.Tx()
	defer tx.Close()

	pheader(tx, size, msgRwstat, tag)
	return enc.Err()
}
