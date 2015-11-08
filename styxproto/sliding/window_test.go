package sliding_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	"aqwari.net/net/styx/styxproto/sliding"
)

type repeater string

func (r repeater) Read(p []byte) (int, error) {
	for b := p[:0]; len(b) < len(p); {
		b = append(b, r...)
	}
	return len(p), nil
}

var dummyReader = repeater(`A`)

func TestBigDropPanics(t *testing.T) {
	w := &sliding.Window{R: dummyReader, B: make([]byte, 10)}
	defer func() {
		if r := recover(); r != nil {
			t.Log("caught panic")
		} else {
			t.Errorf("Drop(1) on empty window did not panic")
		}
	}()
	w.Drop(1)
}

func TestShortBuf(t *testing.T) {
	w := &sliding.Window{R: dummyReader, B: make([]byte, 10)}
	if _, err := w.Fetch(11); err != io.ErrShortBuffer {
		t.Error("Long fetch did not return io.ErrShortBuff")
	}
}

func TestSliding(t *testing.T) {
	w := &sliding.Window{R: dummyReader, B: make([]byte, len(dummyReader)*3+1)}
	for i := 0; i < 5; i++ {
		if b, err := w.Fetch(len(dummyReader)); err != nil {
			t.Error(err)
			break
		} else if string(b) != string(dummyReader) {
			t.Errorf("%s != %s", b, dummyReader)
		}
		t.Logf("%s, %#v", w.Bytes(), w)
		w.Drop(len(dummyReader))
	}
}

func TestReader(t *testing.T) {
	w := &sliding.Window{R: dummyReader, B: make([]byte, 28)}
	if _, err := w.Fetch(12); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", w)
	r := w.Reader(24)
	if _, err := io.Copy(ioutil.Discard, r); err != nil {
		t.Fatal(err)
	}
	t.Logf("%#v", w)
}

func Example() {
	// Implement a parser for djb's 'netstrings'
	const netstring = "12:hello world!,15:goodbye, world!,"
	input := strings.NewReader(netstring)
	win := sliding.Window{R: input, B: make([]byte, 1024)}
	for {
		dot, err := win.Fetch(1)
		if err != nil {
			break
		}
		fmt.Printf("%q in window\n", win.Bytes())
		fmt.Printf("%q actually read\n", win.B[:len(netstring)])
		if dot[len(dot)-1] != ':' {
			continue
		}
		n, err := strconv.Atoi(string(dot))
		if err != nil {
			break
		}

		win.Drop(len(dot))
		dot, err = win.Fetch(n)

		fmt.Printf("parsed %s\n", dot)

		// Drop trailing comma
		dot, err = win.Fetch(1)
		if err != nil {
			break
		}
		win.Drop(n + 1)
	}
	// Output:"1" in window
	// "12:hello world!,15:goodbye, world!," actually read
	// "12" in window
	// "12:hello world!,15:goodbye, world!," actually read
	// "12:" in window
	// "12:hello world!,15:goodbye, world!," actually read
}

func ExampleWindow() {
	// Read a comma-separated list of integers
	input := strings.NewReader("34,28,")

	// Create a Window that can address at most 8KB at a time
	win := sliding.Window{R: input, B: make([]byte, 1024*8)}

	for {
		dot, err := win.Fetch(1)
		if err != nil {
			break
		}
		fmt.Printf("%q in window\n", win.Bytes())
		if dot[len(dot)-1] == ',' {
			tok := dot[:len(dot)-1]
			x, err := strconv.Atoi(string(tok))
			if err != nil {
				fmt.Printf("bad number %v: %v", tok, err)
			}
			fmt.Println("number", x)
			win.Drop(len(dot))
		}
	}
	// Output: "3" in window
	// "34" in window
	// "34," in window
	// number 34
	// "2" in window
	// "28" in window
	// "28," in window
	// number 28

}