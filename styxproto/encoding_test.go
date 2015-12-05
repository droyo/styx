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
	encode := func(v interface{}, err error) interface{} {
		if err != nil {
			t.Fatalf("× %T %s", v, err)
		}
		return v
	}

	qid, _, err := NewQid(qbuf, 1, 203, 0x83208)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%v", qid)
	}
	stat, _, err := NewStat(statbuf, "georgia", "root", "wheel", "admin")
	stat.SetLength(492)
	stat.SetMode(02775)
	stat.SetType(1)
	stat.SetDev(31)
	stat.SetQid(qid)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("%v", stat)
	}

	encode(WriteTversion(&buf, 1<<12, "9P2000"))
	encode(WriteRversion(&buf, 1<<11, "9P2000"))
	encode(WriteTauth(&buf, 1, 1, "gopher", ""))
	encode(WriteRauth(&buf, 1, qid))
	encode(WriteTattach(&buf, 2, 2, 31415, "gopher", ""))
	encode(WriteRattach(&buf, 2, qid))
	encode(WriteRerror(&buf, 0, "some error"))
	encode(WriteTflush(&buf, 3, 2))
	encode(WriteRflush(&buf, 3))
	encode(WriteTwalk(&buf, 4, 4, 10, "var", "log", "messages"))
	encode(WriteRwalk(&buf, 4, qid))
	encode(WriteTopen(&buf, 0, 1, 1))
	encode(WriteRopen(&buf, 0, qid, 300))
	encode(WriteTcreate(&buf, 1, 4, "frogs.txt", 0755, 3))
	encode(WriteRcreate(&buf, 1, qid, 1200))
	encode(WriteTread(&buf, 0, 32, 803280, 5308))
	encode(WriteRread(&buf, 16, []byte("hello, world!")))
	encode(WriteTwrite(&buf, 1, 4, 10, []byte("goodbye, world!")))
	encode(WriteRwrite(&buf, 1, 0))
	encode(WriteTclunk(&buf, 5, 4))
	encode(WriteRclunk(&buf, 5))
	encode(WriteTremove(&buf, 18, 9))
	encode(WriteRremove(&buf, 18))
	encode(WriteTstat(&buf, 6, 13))
	encode(WriteRstat(&buf, 6, stat))
	encode(WriteTwstat(&buf, 7, 3, stat))
	encode(WriteRwstat(&buf, 7))

	d := NewDecoder(&buf)
	for d.Next() {
		for _, msg := range d.Messages() {
			switch msg := msg.(type) {
			case BadMessage:
				t.Error(msg.Tag(), msg.Err)
			default:
				t.Logf("%d %d %v", msg.Tag(), msg.Len(), msg)
			}
		}
	}
	if d.Err() != nil {
		t.Error(d.Err())
	}
}
