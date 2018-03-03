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

func TestV9FSRequests(t *testing.T) {
	testParseMsgFile(t, "testdata/v9fs.client.9p")
}

func TestResponse(t *testing.T) {
	testParseMsgFile(t, "testdata/sample.server.9p")
}

func TestV9FSResponse(t *testing.T) {
	testParseMsgFile(t, "testdata/v9fs.server.9p")
}

func testParseMsgFile(t *testing.T, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	testParseMsg(t, file)
}

// This is in lieu of compile-time constraints
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

func TestDefaultBufSize(t *testing.T) {
	if DefaultBufSize < MinBufSize {
		t.Errorf("DefaultBufSize (%d) less than MinBufSize(%d)",
			DefaultBufSize, MinBufSize)
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
	n := 0
	os.MkdirAll("testoutput", 0777)
	p := NewDecoder(r)
	for p.Next() {
		m := p.Msg()
		if b, ok := m.(BadMessage); ok {
			t.Error(b)
			continue
		}
		if s, ok := m.(fmt.Stringer); ok {
			t.Logf("%d %s", m.Tag(), s.String())
		} else {
			t.Logf("%d %s", m.Tag(), m)
		}
		if false { // flip to generate data for fuzz testing
			n++
			name := fmt.Sprintf("corpus/%03d.%T.9p", n, m)
			if f, err := os.Create(name); err != nil {
				t.Logf("failed to save message to %s: %s", name, err)
			} else {
				if _, err := f.Write(m.bytes()); err != nil {
					t.Logf("failed to save message to %s: %s", name, err)
				} else {
					t.Logf("saved message to %s", name)
				}
				if r, ok := m.(io.Reader); ok {
					if _, err := io.Copy(f, r); err != nil {
						t.Logf("failed to copy %T body: %s", m, err)
					} else {
						t.Logf("copied %T body to %s", m, name)
					}
				}
				f.Close()
			}
		}
	}
	if err := p.Err(); err != nil {
		t.Error(err)
	}
}
