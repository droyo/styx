package styxproto

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func benchmarkDecode(b *testing.B, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(data)
	d := NewDecoder(r)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for d.Next() {
		}
		if err := d.Err(); err != nil {
			b.Error(err)
		}
		r.Reset(data)
		d.Reset(r)
	}
}

func copyQid(q Qid) Qid {
	c := make(Qid, QidLen)
	copy(c, q)
	return c
}

// Reads 9P messages from sample data and calls the respective
// encoding methods on an Encoder
func benchmarkEncode(b *testing.B, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		b.Fatal(err)
	}
	d := NewDecoder(bytes.NewReader(data))

	var operations []func(*Encoder)

	type Fcall interface {
		Fid() uint32
	}
	for d.Next() {
		var op func(*Encoder)
		var fid uint32
		tag := d.Msg().Tag()

		if f, ok := d.Msg().(Fcall); ok {
			fid = f.Fid()
		}
		// Note: Decoder's reuse buffer space when Next is called, so
		// we have to make sure to copy any memory used in an operation
		switch m := d.Msg().(type) {
		case Rattach:
			qid := copyQid(m.Qid())
			op = func(e *Encoder) { e.Rattach(tag, qid) }
		case Rauth:
			aqid := copyQid(m.Aqid())
			op = func(e *Encoder) { e.Rauth(tag, aqid) }
		case Rclunk:
			op = func(e *Encoder) { e.Rclunk(tag) }
		case Rcreate:
			qid := copyQid(m.Qid())
			iounit := m.IOunit()
			op = func(e *Encoder) { e.Rcreate(tag, qid, uint32(iounit)) }
		case Rerror:
			ename := m.String()
			op = func(e *Encoder) { e.Rerror(tag, "%s", ename) }
		case Rflush:
			op = func(e *Encoder) { e.Rflush(tag) }
		case Ropen:
			qid := copyQid(m.Qid())
			iounit := m.IOunit()
			op = func(e *Encoder) { e.Ropen(tag, qid, uint32(iounit)) }
		case Rread:
			data, err := ioutil.ReadAll(m)
			if err != nil {
				b.Fatal(err)
			}
			op = func(e *Encoder) { e.Rread(tag, data) }
		case Rremove:
			op = func(e *Encoder) { e.Rremove(tag) }
		case Rstat:
			stat := append(Stat{}, m.Stat()...)
			op = func(e *Encoder) { e.Rstat(tag, stat) }
		case Rversion:
			version := string(m.Version())
			msize := m.Msize()
			op = func(e *Encoder) { e.Rversion(uint32(msize), version) }
		case Rwalk:
			wqid := make([]Qid, 0, m.Nwqid())
			for i := 0; i < m.Nwqid(); i++ {
				wqid = append(wqid, copyQid(m.Wqid(i)))
			}
			op = func(e *Encoder) { e.Rwalk(tag, wqid...) }
		case Rwrite:
			count := m.Count()
			op = func(e *Encoder) { e.Rwrite(tag, int64(count)) }
		case Rwstat:
			op = func(e *Encoder) { e.Rwstat(tag) }
		case Tattach:
			afid := m.Afid()
			uname := string(m.Uname())
			aname := string(m.Aname())
			op = func(e *Encoder) { e.Tattach(tag, fid, afid, uname, aname) }
		case Tauth:
			afid := m.Afid()
			uname := string(m.Uname())
			aname := string(m.Aname())
			op = func(e *Encoder) { e.Tauth(tag, afid, uname, aname) }
		case Tclunk:
			op = func(e *Encoder) { e.Tclunk(tag, fid) }
		case Tcreate:
			name := string(m.Name())
			perm := m.Perm()
			mode := m.Mode()
			op = func(e *Encoder) { e.Tcreate(tag, fid, name, perm, mode) }
		case Tflush:
			oldtag := m.Oldtag()
			op = func(e *Encoder) { e.Tflush(tag, oldtag) }
		case Topen:
			mode := m.Mode()
			op = func(e *Encoder) { e.Topen(tag, fid, mode) }
		case Tread:
			offset := m.Offset()
			count := m.Count()
			op = func(e *Encoder) { e.Tread(tag, fid, offset, count) }
		case Tremove:
			op = func(e *Encoder) { e.Tremove(tag, fid) }
		case Tstat:
			op = func(e *Encoder) { e.Tstat(tag, fid) }
		case Tversion:
			msize := m.Msize()
			version := string(m.Version())
			op = func(e *Encoder) { e.Tversion(uint32(msize), version) }
		case Twalk:
			newfid := m.Newfid()
			wname := make([]string, 0, m.Nwname())
			for i := 0; i < m.Nwname(); i++ {
				wname = append(wname, string(m.Wname(i)))
			}
			op = func(e *Encoder) { e.Twalk(tag, fid, newfid, wname...) }
		case Twrite:
			data, err := ioutil.ReadAll(m)
			if err != nil {
				b.Fatal(err)
			}
			offset := m.Offset()
			op = func(e *Encoder) { e.Twrite(tag, fid, offset, data) }
		case Twstat:
			stat := append(Stat{}, m.Stat()...)
			op = func(e *Encoder) { e.Twstat(tag, fid, stat) }
		default:
			b.Fatalf("unhandled type %T in encoder benchmark", m)
		}
		operations = append(operations, op)
	}
	if err := d.Err(); d.Err() != nil {
		b.Fatal(err)
	}

	e := NewEncoder(ioutil.Discard)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))

	for i := 0; i < b.N; i++ {
		for _, op := range operations {
			op(e)
		}
	}
}

func BenchmarkDecodeClient(b *testing.B) { benchmarkDecode(b, "testdata/sample.client.9p") }
func BenchmarkDecodeServer(b *testing.B) { benchmarkDecode(b, "testdata/sample.server.9p") }
func BenchmarkEncodeClient(b *testing.B) { benchmarkEncode(b, "testdata/sample.client.9p") }
func BenchmarkEncodeServer(b *testing.B) { benchmarkEncode(b, "testdata/sample.server.9p") }
