package styxproto

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests ensure that bad messages, discovered by
// go-fuzz, do not crash the program.

var messages = []string{
	"F\x00\x00\x00}00>\x000000000000000000000000000000000000000000000000000000000000000",
	"G\x00\x00\x00}00>\x00000000000000000000000000000000000000000\x00\x00\x03\x00000\x05\x0000000\b\x000000000",
	"\x01\x00\x00\x00000",
	"\n\x00\x00\x00u000000",
}

func TestInvalidMsg(t *testing.T) {
	for _, s := range messages {
		testInvalidMsg(t, strings.NewReader(s))
	}
}

func TestInvalidMsgFile(t *testing.T) {
	names, err := filepath.Glob("testdata/malformed/*")
	if err != nil {
		panic(err)
	}
	for _, name := range names {
		r, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("testing %s", name)
		testInvalidMsg(t, r)
	}
}

func testInvalidMsg(t *testing.T, r io.Reader) {
	d := NewDecoder(r)
	for d.Next() {
		t.Logf("parsed %d messages", len(d.Messages()))
	}
}
