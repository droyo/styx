package styxproto_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"

	"aqwari.net/net/styx/internal/tracing"
	"aqwari.net/net/styx/styxproto"
)

func benchmarkDecode(b *testing.B, filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		b.Fatal(err)
	}
	r := bytes.NewReader(data)
	d := styxproto.NewDecoder(r)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for d.Next() {
			if r, ok := d.Msg().(io.Reader); ok {
				if _, err := io.Copy(ioutil.Discard, r); err != nil {
					b.Error(err)
				}
			}
		}
		if err := d.Err(); err != nil {
			b.Error(err)
		}
		r.Reset(data)
		d.Reset(r)
	}
}

func copyQid(q styxproto.Qid) styxproto.Qid {
	c := make(styxproto.Qid, styxproto.QidLen)
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

	var operations []func(*styxproto.Encoder)

	type Fcall interface {
		Fid() uint32
	}
	nMsg := 0
	var offset int64
	logMsg := func(msg styxproto.Msg) {
		nMsg++
		b.Logf("%d %s tag=%d len=%d", nMsg, msg, msg.Tag(), msg.Len())
		offset += msg.Len()
	}
	d := tracing.Decoder(bytes.NewReader(data), logMsg)
	//d := styxproto.NewDecoder(bytes.NewReader(data))
	for d.Next() {
		var op func(*styxproto.Encoder)
		var fid uint32
		tag := d.Msg().Tag()

		if f, ok := d.Msg().(Fcall); ok {
			fid = f.Fid()
		}
		// Note: Decoder's reuse buffer space when Next is called, so
		// we have to make sure to copy any memory used in an operation
		switch m := d.Msg().(type) {
		case styxproto.Rattach:
			qid := copyQid(m.Qid())
			op = func(e *styxproto.Encoder) { e.Rattach(tag, qid) }
		case styxproto.Rauth:
			aqid := copyQid(m.Aqid())
			op = func(e *styxproto.Encoder) { e.Rauth(tag, aqid) }
		case styxproto.Rclunk:
			op = func(e *styxproto.Encoder) { e.Rclunk(tag) }
		case styxproto.Rcreate:
			qid := copyQid(m.Qid())
			iounit := m.IOunit()
			op = func(e *styxproto.Encoder) { e.Rcreate(tag, qid, uint32(iounit)) }
		case styxproto.Rerror:
			ename := m.String()
			op = func(e *styxproto.Encoder) { e.Rerror(tag, "%s", ename) }
		case styxproto.Rflush:
			op = func(e *styxproto.Encoder) { e.Rflush(tag) }
		case styxproto.Ropen:
			qid := copyQid(m.Qid())
			iounit := m.IOunit()
			op = func(e *styxproto.Encoder) { e.Ropen(tag, qid, uint32(iounit)) }
		case styxproto.Rread:
			data, err := ioutil.ReadAll(m)
			if err != nil {
				b.Fatal(err)
			}
			op = func(e *styxproto.Encoder) { e.Rread(tag, data) }
		case styxproto.Rremove:
			op = func(e *styxproto.Encoder) { e.Rremove(tag) }
		case styxproto.Rstat:
			stat := append(styxproto.Stat{}, m.Stat()...)
			op = func(e *styxproto.Encoder) { e.Rstat(tag, stat) }
		case styxproto.Rversion:
			version := string(m.Version())
			msize := m.Msize()
			op = func(e *styxproto.Encoder) { e.Rversion(uint32(msize), version) }
		case styxproto.Rwalk:
			wqid := make([]styxproto.Qid, 0, m.Nwqid())
			for i := 0; i < m.Nwqid(); i++ {
				wqid = append(wqid, copyQid(m.Wqid(i)))
			}
			op = func(e *styxproto.Encoder) { e.Rwalk(tag, wqid...) }
		case styxproto.Rwrite:
			count := m.Count()
			op = func(e *styxproto.Encoder) { e.Rwrite(tag, int64(count)) }
		case styxproto.Rwstat:
			op = func(e *styxproto.Encoder) { e.Rwstat(tag) }
		case styxproto.Tattach:
			afid := m.Afid()
			uname := string(m.Uname())
			aname := string(m.Aname())
			op = func(e *styxproto.Encoder) { e.Tattach(tag, fid, afid, uname, aname) }
		case styxproto.Tauth:
			afid := m.Afid()
			uname := string(m.Uname())
			aname := string(m.Aname())
			op = func(e *styxproto.Encoder) { e.Tauth(tag, afid, uname, aname) }
		case styxproto.Tclunk:
			op = func(e *styxproto.Encoder) { e.Tclunk(tag, fid) }
		case styxproto.Tcreate:
			name := string(m.Name())
			perm := m.Perm()
			mode := m.Mode()
			op = func(e *styxproto.Encoder) { e.Tcreate(tag, fid, name, perm, mode) }
		case styxproto.Tflush:
			oldtag := m.Oldtag()
			op = func(e *styxproto.Encoder) { e.Tflush(tag, oldtag) }
		case styxproto.Topen:
			mode := m.Mode()
			op = func(e *styxproto.Encoder) { e.Topen(tag, fid, mode) }
		case styxproto.Tread:
			offset := m.Offset()
			count := m.Count()
			op = func(e *styxproto.Encoder) { e.Tread(tag, fid, offset, count) }
		case styxproto.Tremove:
			op = func(e *styxproto.Encoder) { e.Tremove(tag, fid) }
		case styxproto.Tstat:
			op = func(e *styxproto.Encoder) { e.Tstat(tag, fid) }
		case styxproto.Tversion:
			msize := m.Msize()
			version := string(m.Version())
			op = func(e *styxproto.Encoder) { e.Tversion(uint32(msize), version) }
		case styxproto.Twalk:
			newfid := m.Newfid()
			wname := make([]string, 0, m.Nwname())
			for i := 0; i < m.Nwname(); i++ {
				wname = append(wname, string(m.Wname(i)))
			}
			op = func(e *styxproto.Encoder) { e.Twalk(tag, fid, newfid, wname...) }
		case styxproto.Twrite:
			data, err := ioutil.ReadAll(m)
			if err != nil {
				b.Fatal(err)
			}
			offset := m.Offset()
			op = func(e *styxproto.Encoder) { e.Twrite(tag, fid, offset, data) }
		case styxproto.Twstat:
			stat := append(styxproto.Stat{}, m.Stat()...)
			op = func(e *styxproto.Encoder) { e.Twstat(tag, fid, stat) }
		default:
			b.Fatalf("%d offset %d unhandled %T message in encoder benchmark len=%d tag=%d: %s", nMsg, offset, m, m.Len(), m.Tag(), m)
		}
		operations = append(operations, op)
	}
	if err := d.Err(); d.Err() != nil {
		b.Fatalf("%d message %v: %s", nMsg, d.Msg(), err)
	}

	e := styxproto.NewEncoder(ioutil.Discard)
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

func BenchmarkDecodeIOHeavyClient(b *testing.B) { benchmarkDecode(b, "testdata/ioheavy.client.9p") }
func BenchmarkDecodeIOHeavyServer(b *testing.B) { benchmarkDecode(b, "testdata/ioheavy.server.9p") }
func BenchmarkEncodeIOHeavyClient(b *testing.B) { benchmarkEncode(b, "testdata/ioheavy.client.9p") }
func BenchmarkEncodeIOHeavyServer(b *testing.B) { benchmarkEncode(b, "testdata/ioheavy.server.9p") }
