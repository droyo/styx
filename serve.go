package styx

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"

	"aqwari.net/net/styx/internal"
	"aqwari.net/net/styx/styxproto"
)

func (c *Conn) serve() {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.srv.logf("panic serving: %v\n%s", err, buf)
		}
		c.close()
	}()

Loop:
	for c.Next() {
		for _, msg := range c.Messages() {
			if err := c.handleMessage(msg); err != nil {
				break Loop
			}
		}
		if err := c.bw.Flush(); err != nil {
			c.srv.logf("error flushing message buffer: %v", err)
			break
		}
	}
	if err := c.bw.Flush(); err != nil {
		c.srv.logf("error flushing message buffer: %v", err)
	}
	if c.Err() != nil {
		c.srv.logf("error parsing messages: %v", c.Err())
	}
}

func (c *Conn) handleMessage(m styxproto.Msg) error {
	var (
		Rerror   = styxproto.WriteRerror
		Rversion = styxproto.WriteRversion
		Rflush   = styxproto.WriteRflush
		w        = &internal.ErrWriter{W: c.bw}
	)

	if m, ok := m.(styxproto.Tversion); ok {
		if c.state != stateNew {
			Rerror(w, m.Tag(), "late Tversion message")
			return nil
		}
	} else if c.state == stateNew {
		Rerror(w, m.Tag(), "protocol version not negotiated")
		return nil
	}

	switch m := m.(type) {
	case styxproto.Tversion:
		if !bytes.HasPrefix(m.Version(), []byte("9P2000")) {
			Rerror(w, m.Tag(), "invalid version %s", m.Version())
			break
		} else {
			Rversion(w, uint32(c.srv.MaxSize), "9P2000")
			c.state = stateActive
		}
	case styxproto.Tattach:
		if m.Afid() != styxproto.NoFid {

		} else {
		}
	case styxproto.Tauth:

	case fcall:
	case styxproto.Tflush:
		if cancel, ok := c.getPending(m.Oldtag()); ok {
			cancel()
		}
		Rflush(w, m.Tag())
	case styxproto.BadMessage:
		c.srv.logf("received bad message: %v", m.Err)
		Rerror(w, m.Tag(), "malformed message")
		break
	default:
		name := fmt.Sprintf("%T", m)
		name = name[strings.IndexByte(name, '.')+1:]
		Rerror(w, m.Tag(), "unexpected %s message", name)
	}
	return w.Err
}
