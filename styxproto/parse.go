package styxproto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Message []byte

func readable(msg Message) string {
	msg = msg[3:]
	if len(msg) > 16 {
		msg = msg[:16]
	}
	for _, s := range strings.Split(hex.Dump(msg), "\n") {
		if x := strings.Index(s, "|"); x >= 0 {
			return s[x:]
		}
	}
	return ""
}

func (msg Message) String() string {
	mtype := msg[0]
	tag := int32(binary.LittleEndian.Uint16(msg[1:3]))
	return fmt.Sprintf("tag %04x type %03d %s",
		tag, mtype, readable(msg))
}

type Parser struct {
	buf *bytes.Buffer
	r   io.Reader
	err error
	msg Message
}

func NewParser(r io.Reader) *Parser {
	return &Parser{
		r:   r,
		buf: new(bytes.Buffer),
	}
}

func (p *Parser) Message() Message {
	return p.msg
}

func (p *Parser) Err() error {
	if p.err == io.EOF {
		return nil
	}
	return p.err
}

func (p *Parser) Next() bool {
	if p.err != nil {
		return false
	}
	p.buf.Reset()
	p.msg = nil
	if err := copyMsg(p.buf, p.r); err != nil {
		p.err = err
		return false
	}
	if msg, err := parseMsg(p.buf.Bytes()); err != nil {
		p.err = err
		return false
	} else {
		p.msg = msg
	}
	return true
}

// copyMsg does *not* copy the first four bytes
// into dst
func copyMsg(dst io.Writer, src io.Reader) error {
	sizebuf := make([]byte, 4)

	if _, err := io.ReadFull(src, sizebuf); err != nil {
		return err
	}
	size := int64(binary.LittleEndian.Uint32(sizebuf))
	if _, err := io.CopyN(dst, src, size-4); err != nil {
		return err
	}
	return nil
}

func parseMsg(msg []byte) (Message, error) {
	if len(msg) < 3 {
		return nil, errors.New("Message is too small!")
	}
	return Message(msg), nil
}
