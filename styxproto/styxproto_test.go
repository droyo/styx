package styxproto

import (
	"bufio"
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

func testParseMsg(t *testing.T, r io.Reader) {

	p := NewScanner(bufio.NewReader(r), nil)
	for p.Next() {
		for _, m := range p.Msgs() {
			if s, ok := m.(fmt.Stringer); ok {
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
