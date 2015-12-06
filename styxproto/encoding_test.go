package styxproto

import (
	"bytes"
	"reflect"
	"testing"
)

func bytesFrom(v interface{}) []byte {
	return reflect.ValueOf(v).Bytes()
}

func TestEncode(t *testing.T) {
	var (
		buf     bytes.Buffer
		qbuf    = make([]byte, 13)
		statbuf = make([]byte, maxStatLen)
	)
	enc := NewEncoder(&buf)
	dec := NewDecoder(&buf)

	check := func(err error) {
		if err != nil {
			t.Fatalf("× %s", err)
		}
		for dec.Next() {
			for _, msg := range dec.Messages() {
				t.Logf("%T %s", msg, msg)
			}
		}
		if dec.Err() != nil {
			t.Fatal("× %s", dec.Err())
		}
	}

	qid, _, err := NewQid(qbuf, 1, 203, 0x83208)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%v", qid)
	}
	stat, _, err := NewStat(statbuf, "georgia", "root", "wheel", "admin")
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%v", stat)
	}
	stat.SetLength(492)
	stat.SetMode(02775)
	stat.SetType(1)
	stat.SetDev(31)
	stat.SetQid(qid)

	check(enc.Tversion(1<<12, "9P2000"))
	check(enc.Rversion(1<<11, "9P2000"))
	check(enc.Tauth(1, 1, "gopher", ""))
	check(enc.Rauth(1, qid))
	check(enc.Tattach(2, 2, 31415, "gopher", ""))
	check(enc.Rattach(2, qid))
	check(enc.Rerror(0, "some error"))
	check(enc.Tflush(3, 2))
	check(enc.Rflush(3))
	check(enc.Twalk(4, 4, 10, "var", "log", "messages"))
	check(enc.Rwalk(4, qid))
	check(enc.Topen(0, 1, 1))
	check(enc.Ropen(0, qid, 300))
	check(enc.Tcreate(1, 4, "frogs.txt", 0755, 3))
	check(enc.Rcreate(1, qid, 1200))
	check(enc.Tread(0, 32, 803280, 5308))
	check(enc.Rread(16, []byte("hello, world!")))
	check(enc.Twrite(1, 4, 10, []byte("goodbye, world!")))
	check(enc.Rwrite(1, 0))
	check(enc.Tclunk(5, 4))
	check(enc.Rclunk(5))
	check(enc.Tremove(18, 9))
	check(enc.Rremove(18))
	check(enc.Tstat(6, 13))
	check(enc.Rstat(6, stat))
	check(enc.Twstat(7, 3, stat))
	check(enc.Rwstat(7))
}
