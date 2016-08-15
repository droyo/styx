package styxfile

import (
	"bytes"
	"testing"
)

func compare(t *testing.T, file Interface, offset int64, want string) {
	buf := make([]byte, 1000)
	n, err := file.ReadAt(buf, offset)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if got != want {
		t.Errorf("ReadAt(f, %d) got %q, want %q", offset, got, want)
	} else {
		t.Logf("ReadAt(f, %d) = %q", offset, got)
	}
}

func write(t *testing.T, file Interface, offset int64, data string) {
	_, err := file.WriteAt([]byte(data), offset)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSeeker(t *testing.T) {
	r := bytes.NewReader([]byte("hello, world!"))

	file, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	compare(t, file, 0, "hello, world!")
	compare(t, file, 1, "ello, world!")
	compare(t, file, 7, "world!")
}

func TestDumb(t *testing.T) {
	var buf bytes.Buffer

	file, err := New(&buf)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	write(t, file, 0, "h")
	write(t, file, 1, "e")
	write(t, file, 2, "l")
	write(t, file, 3, "l")
	write(t, file, 4, "o")
}
