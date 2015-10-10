package styxproto

import (
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
	p := NewParser(r)
	for p.Next() {
		t.Logf("%s", p.Message())
	}
	if err := p.Err(); err != nil {
		t.Error(err)
	}
}
