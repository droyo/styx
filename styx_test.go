package styx

import (
	"bytes"
	"errors"
	"os/exec"
	"testing"
	"net"
	"encoding/binary"
)

/* Ideas for benchmarks:

Max throughput with /dev/zero
Max concurrent connections
TLS performance

Tests:

Simulate bad connections
*/

var (
	NS string
)

func init() {
	out, _ := exec.Command("namespace").Output()
	NS = string(bytes.TrimSpace(out))
}

func read9P(addr, path string) ([]byte, error) {
	var buf bytes.Buffer
	
	cmd := exec.Command("9p", "-a", addr, "read", path)
	cmd.Stderr = &buf
	if out, err := cmd.Output(); err != nil {
		return nil, errors.New(buf.String())
	} else {
		return out, nil
	}
}

func write9P(addr, path string, data []byte) error {
	var buf bytes.Buffer
	
	cmd := exec.Command("9p", "-a", addr, "write", path)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = &buf
	
	if err := cmd.Run(); err != nil {
		return errors.New(buf.String())
	}
	return nil
}

func stat9P(addr, path string) ([]byte, error) {
	var buf bytes.Buffer
	
	cmd := exec.Command("9p", "-a", addr, "stat", path)
	cmd.Stderr = &buf
	
	if out, err := cmd.Output(); err != nil {
		return nil, errors.New(buf.String())
	} else {
		return out, nil
	}
}

func list9P(addr, path string) ([][]byte, error) {
	var buf bytes.Buffer
	
	cmd := exec.Command("9p", "-a", addr, "stat", path)
	cmd.Stderr = &buf
	
	if out, err := cmd.Output(); err != nil {
		return nil, errors.New(buf.String())
	} else {
		return bytes.Split(out, []byte("\n")), nil
	}
}

func TestReadP9P(t *testing.T) {
	if _, err := read9P(NS + "/factotum", "ctl"); err != nil {
		t.Fatal(err)
	}
}

func TestVersion(t *testing.T) {
	l, err := net.Listen("unix", "/tmp/TestVersion.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	
	go read9P("unix!/tmp/TestVersion.sock", "/")
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	var (
		size uint32
		max uint32
		typ Type
		tag Tag
		strlen uint16
	)
	if err := binary.Read(conn, binary.LittleEndian, &size); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed size as %d", size)
	
	if err := binary.Read(conn, binary.LittleEndian, &typ); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed type as %v", typ)
	
	if err := binary.Read(conn, binary.LittleEndian, &tag); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed tag as %x", tag)
	
	if err := binary.Read(conn, binary.LittleEndian, &max); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed max as %d", max)
	
	if err := binary.Read(conn, binary.LittleEndian, &strlen); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed string length as %d", strlen)
	
	buf := make([]byte, strlen)
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	t.Logf("Parsed version as %s", buf)
	ver := []byte{'9','P','2','0','0','0'}
	binary.Write(conn, binary.LittleEndian, uint32(len(ver)))
	conn.Write(ver)
}
