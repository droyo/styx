package styx

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"

	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/styxproto"
)

func newQid(buf []byte, qtype uint8, version uint32, path uint64) styxproto.Qid {
	if len(buf) < styxproto.QidLen {
		buf = make([]byte, styxproto.QidLen)
	}
	q, _, err := styxproto.NewQid(buf, qtype, version, path)
	if err != nil {
		panic("styxproto.NewQid returned error despite sufficient buf size")
	}
	return q
}

var aqid = newQid(nil, styxproto.QTAUTH, 0, 0)

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
			c.srv.debugf("← %s", msg)
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
	if c.Decoder.Err() != nil {
		c.srv.logf("error parsing messages: %v", c.Decoder.Err())
	}
}

func (c *Conn) handleMessage(m styxproto.Msg) error {
	if m, ok := m.(styxproto.Tversion); ok {
		if c.state != stateNew {
			c.Rerror(m.Tag(), "late Tversion message")
			return nil
		}
	} else if c.state == stateNew {
		c.Rerror(m.Tag(), "protocol version not negotiated")
		return nil
	}

	switch m := m.(type) {
	case styxproto.Tversion:
		msize := c.srv.MaxSize
		if n := m.Msize(); n < msize {
			msize = n
		}
		if ver := m.Version(); !bytes.HasPrefix(ver, []byte("9P2000")) {
			c.srv.logf("received unknown version %s from %s", ver, c.remoteAddr)
			c.Rversion(uint32(msize), "unknown")
			break
		} else {
			c.Rversion(uint32(c.srv.MaxSize), "9P2000")
			c.state = stateActive
		}
	case styxproto.Tattach:
		rootQid := newQid(c.qidbuf, styxproto.QTDIR, 0, util.Hash64(m.Aname()))
		if afid := m.Afid(); afid != styxproto.NoFid {
			_, ok := c.getSession(afid)
			if !ok {
				c.Rerror(m.Tag(), "authentication failed")
				break
			}
			c.Rattach(m.Tag(), rootQid)
		} else if c.srv.Auth != nil {
			// transport-based auth methods can authenticate
			// Tattach requests as well. This lets users manage
			// authentication without modifying their clients. We
			// pass a dummy channel to the Auth callback.
			var (
				rw    = util.BlackHole{}
				uname = string(m.Uname())
				aname = string(m.Aname())
			)
			if err := c.srv.Auth.Auth(rw, c, uname, aname); err != nil {
				c.Rerror(m.Tag(), "auth required", err)
				break
			}
			c.newSession(m)
			c.Rattach(m.Tag(), rootQid)
		} else {
			if _, inuse := c.getSession(m.Fid()); inuse {
				c.Rerror(m.Tag(), "fid already in use")
				break
			}
			c.newSession(m)
			c.Rattach(m.Tag(), rootQid)
		}
	case styxproto.Tauth:
		if c.srv.Auth == nil {
			c.Rerror(m.Tag(), "no auth required")
			break
		}
		c.Rauth(m.Tag(), aqid)
	case fcall:
		fid := m.Fid()
		_, ok := c.getSession(fid)
		if !ok {
			c.Rerror(m.Tag(), "unknown fid %d", m.Fid())
			break
		}
	case styxproto.Tflush:
		if cancel, ok := c.getPending(m.Oldtag()); ok {
			cancel()
		}
		c.Rflush(m.Tag())
	case styxproto.BadMessage:
		c.srv.logf("received bad message: %v", m.Err)
		c.Rerror(m.Tag(), "malformed message")
		break
	default:
		name := fmt.Sprintf("%T", m)
		name = name[strings.IndexByte(name, '.')+1:]
		c.Rerror(m.Tag(), "unexpected %s message", name)
	}
	return c.Encoder.Err()
}
