package styxproto

import (
	"fmt"
	"io"
	"os"
	"testing"
)

func TestRequests(t *testing.T) {
	testParseMsgFile(t, "testdata/sample.client.9p")
}

func TestResponse(t *testing.T) {
	testParseMsgFile(t, "testdata/sample.server.9p")
}

func testParseMsgFile(t *testing.T, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	testParseMsg(t, file)
}

// These are in lieu of compile-time constraints
func TestMinSize(t *testing.T) {
	for _, v := range minSizeLUT {
		if v == 0 {
			continue
		}
		if v < minMsgSize {
			t.Error("minMsgSize (smallest possible message) is greater than the minimum size for an individual message")
		}
	}
}

func TestMinBufSize(t *testing.T) {
	if MinBufSize > (1<<31 - 1) {
		t.Error("Max allowed \"fixed\" message size is greater than the maximum value " +
			"of an int. This breaks assumptions in the code.")
	}
	for mtype, v := range maxSizeLUT {
		if mtype == msgTwrite || mtype == msgRread {
			continue
		}
		if MinBufSize < v {
			t.Errorf("MinBufSize (%d) is not large enough to hold the largest "+
				"allowed fixed-sized message (type %d) (%d)",
				MinBufSize, mtype, v)
		}
	}
}

func testParseMsg(t *testing.T, r io.Reader) {
	p := NewScanner(r)
	for p.Next() {
		for _, m := range p.Messages() {
			if b, ok := m.(BadMessage); ok {
				t.Error(b)
			} else if s, ok := m.(fmt.Stringer); ok {
				t.Logf("%d %s", m.Tag(), s.String())
			} else {
				t.Logf("%d %s", m.Tag(), m)
			}
		}
	}
	if err := p.Err(); err != nil {
		t.Error(err)
	}
}
