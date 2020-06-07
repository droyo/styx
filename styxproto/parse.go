package styxproto

import (
	"bytes"
	"errors"
	"io"
)

var msgParseLUT = [...]func(msg, io.Reader) (Msg, error){
	msgTversion: parseTversion,
	msgRversion: parseRversion,
	msgTauth:    parseTauth,
	msgRauth:    parseRauth,
	msgTattach:  parseTattach,
	msgRattach:  parseRattach,
	msgRerror:   parseRerror,
	msgTflush:   parseTflush,
	msgRflush:   parseRflush,
	msgTwalk:    parseTwalk,
	msgRwalk:    parseRwalk,
	msgTopen:    parseTopen,
	msgRopen:    parseRopen,
	msgTcreate:  parseTcreate,
	msgRcreate:  parseRcreate,
	msgTread:    parseTread,
	msgRread:    parseRread,
	msgTwrite:   parseTwrite,
	msgRwrite:   parseRwrite,
	msgTclunk:   parseTclunk,
	msgRclunk:   parseRclunk,
	msgTremove:  parseTremove,
	msgRremove:  parseRremove,
	msgTstat:    parseTstat,
	msgRstat:    parseRstat,
	msgTwstat:   parseTwstat,
	msgRwstat:   parseRwstat,
}

var (
	errShortRead = errors.New("not enough data in buffer to complete message")
)

// read just enough data to figure out the type of message and if
// it's the right size.
func (s *Decoder) nextHeader() (msg, error) {
	return s.growdot(minMsgSize)
}

// fetchMessage reads the next buffered message from the stream
// into s.msg. fetchMessage will return bufio.ErrBufferFull if there is not
// enough space in the buffer to hold the next message.
func (s *Decoder) fetchMessage() (Msg, error) {
	dot, err := s.nextHeader()
	if err != nil {
		return nil, err
	}

	if err := verifySizeAndType(dot); err != nil {
		return s.badMessage(dot, err)
	}

	msgType := dot.Type()
	msgSize := dot.Len()
	if s.MaxSize > 0 && msgSize > s.MaxSize {
		return nil, ErrMaxSize
	}

	minSize := minSizeLUT[msgType]

	if _, err := s.growdot(minSize); err != nil {
		return nil, err
	}

	if msgType == msgTwrite || msgType == msgRread {
		return s.readRW()
	}
	return s.readFixed()
}

// Every message besides Twrite and Rread have a small maximum size,
// and are stored wholly in memory for convenience.
func (s *Decoder) readFixed() (Msg, error) {
	msg := msg(s.dot())
	msgSize, msgType := msg.Len(), msg.Type()

	msg, err := s.growdot(int(msgSize))
	if err != nil {
		return nil, err
	}

	parsed, err := parseMsg(msgType, msg, nil)

	// Nothing left to read, all that's possible are parsing errors
	if err != nil {
		return s.badMessage(msg, err)
	}
	s.mark()
	return parsed, nil
}

func (s *Decoder) readRW() (Msg, error) {
	var err error

	msg := msg(s.dot())
	msgSize, msgType := msg.Len(), msg.Type()

	readSize := s.buflen() + s.dotlen()
	if int64(readSize) > msgSize {
		readSize = int(msgSize)
	}

	msg, err = s.growdot(readSize)
	if err != nil {
		// we have already buffered IOHeaderSize bytes, so
		// we are reading from the bufio.Reader's internal buffer.
		// The docs state this should never fail.
		panic("read of buffered data failed: " + err.Error())
	}

	parsed, err := parseMsg(msgType, msg, s.r)
	if err != nil {
		return s.badMessage(msg, err)
	}
	s.mark()
	return parsed, nil
}

func parseMsg(t uint8, m msg, r io.Reader) (Msg, error) {
	return msgParseLUT[t](m, r)
}

func (s *Decoder) badMessage(bad msg, reason error) (Msg, error) {
	// Invalid messages are a bit tricky; we want the caller to know right
	// away that that an invalid message was encountered (so that he may
	// choose to sever the connection), but if the message is not fully buffered,
	// we do not want to perform additional I/O (and possibly block) just to
	// skip the message. This is why the BadMessage type has a field for the
	// number of bytes to skip, rather than the bytes themselves.
	length := bad.Len()
	msg := BadMessage{
		Err:    reason,
		tag:    bad.Tag(),
		length: length,
	}
	if length == 0 {
		return nil, errZeroLen
	}
	if int64(s.buflen()+s.dotlen()) < length {
		return nil, errShortRead
	}
	// We can still continue parsing. This prevents one bad client
	// from hurting performance for others on the same connection.
	if s.dotlen() > int(length) {
		s.shrinkdot(s.dotlen() - int(length))
	} else if _, err := s.growdot(int(length)); err != nil {
		panic(err)
	}
	s.mark()
	return msg, nil
}

func parseTversion(dot msg, _ io.Reader) (Msg, error) {
	if ver, _, err := verifyField(dot.Body()[4:], true, 0); err != nil {
		return nil, err
	} else if err := verifyString(ver); err != nil {
		return nil, err
	} else if len(ver) > MaxVersionLen {
		return nil, errLongVersion
	}
	return Tversion(dot), nil
}

func parseRversion(dot msg, _ io.Reader) (Msg, error) {
	msg, err := parseTversion(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rversion(msg.(Tversion)), nil
}

func parseTauth(dot msg, _ io.Reader) (Msg, error) {
	if err := parseTauthBody(dot.Body()); err != nil {
		return nil, err
	}
	return Tauth(dot), nil
}

func parseTauthBody(body []byte) error {
	if uname, rest, err := verifyField(body[4:], false, 2); err != nil {
		return err
	} else if err := verifyString(uname); err != nil {
		return err
	} else if len(uname) > MaxUidLen {
		return errLongUsername
	} else if aname, _, err := verifyField(rest, true, 0); err != nil {
		return err
	} else if err := verifyString(aname); err != nil {
		return err
	} else if len(aname) > MaxAttachLen {
		return errLongAname
	}
	return nil
}

func parseRauth(dot msg, _ io.Reader) (Msg, error) {
	return Rauth(dot), nil
}

func parseTattach(dot msg, _ io.Reader) (Msg, error) {
	if err := parseTauthBody(dot.Body()[4:]); err != nil {
		return nil, err
	}
	return Tattach(dot), nil
}

func parseRattach(dot msg, _ io.Reader) (Msg, error) {
	msg, err := parseRauth(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rattach(msg.(Rauth)), nil
}

func parseRerror(dot msg, _ io.Reader) (Msg, error) {
	if str, _, err := verifyField(dot.Body(), true, 0); err != nil {
		return nil, err
	} else if err := verifyString(str); err != nil {
		return nil, err
	} else if len(str) > MaxErrorLen {
		return nil, errLongError
	}
	return Rerror(dot), nil
}

func parseTflush(dot msg, _ io.Reader) (Msg, error) {
	return Tflush(dot), nil
}

func parseRflush(dot msg, _ io.Reader) (Msg, error) {
	return Rflush(dot), nil
}

func parseTwalk(dot msg, _ io.Reader) (Msg, error) {
	// size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
	var (
		err       error
		el, elems []byte // first, rest in *wname
	)
	nwelem := guint16(dot.Body()[8:])
	if nwelem > MaxWElem {
		return nil, errMaxWElem
	}
	if dot.Len() < int64(minSizeLUT[msgTwalk])+int64(nwelem)*2 {
		return nil, errOverSize
	}
	elems = dot.Body()[10:]
	for i := uint16(1); i <= nwelem; i++ {
		last := i == nwelem
		padding := (int(nwelem) * 2) - (int(i) * 2)
		el, elems, err = verifyField(elems, last, padding)
		if err != nil {
			return nil, err
		} else if err := verifyPathElem(el); err != nil {
			return nil, err
		} else if len(el) > MaxFilenameLen {
			return nil, errLongFilename
		}
	}
	return Twalk(dot), nil
}

func parseRwalk(dot msg, _ io.Reader) (Msg, error) {
	nwqid := guint16(dot.Body()[:2])
	if nwqid > MaxWElem {
		return nil, errMaxWElem
	}

	msgSize := dot.Len()
	realSize := int64(minSizeLUT[msgRwalk]) + int64(nwqid)*13
	if realSize < msgSize {
		//return nil, errUnderSize
	} else if realSize > msgSize {
		return nil, errOverSize
	}
	return Rwalk(dot), nil
}

func parseTopen(dot msg, _ io.Reader) (Msg, error) {
	return Topen(dot), nil
}

func parseRopen(dot msg, _ io.Reader) (Msg, error) {
	return Ropen(dot), nil
}

func parseTcreate(dot msg, _ io.Reader) (Msg, error) {
	if name, _, err := verifyField(dot.Body()[4:], true, 5); err != nil {
		return nil, err
	} else if err := verifyString(name); err != nil {
		return nil, err
	} else if len(name) > MaxFilenameLen {
		return nil, errLongFilename
	}
	return Tcreate(dot), nil
}

func parseRcreate(dot msg, _ io.Reader) (Msg, error) {
	msg, err := parseRopen(dot, nil)
	if err != nil {
		return nil, err
	}
	return Rcreate(msg.(Ropen)), nil
}

func parseTread(dot msg, _ io.Reader) (Msg, error) {
	// size[4] Tread tag[2] fid[4] offset[8] count[4]
	return Tread(dot), nil
}

func parseRread(dot msg, r io.Reader) (Msg, error) {
	// size[4] Rread tag[2] count[4] data[count]
	m := Rread{msg: dot}

	count := m.Count()
	msgSize := m.Len()

	realSize := count + int64(minSizeLUT[msgRread])
	if realSize < msgSize {
		return nil, errUnderSize
	} else if realSize > msgSize {
		return nil, errOverSize
	}

	buffered := dot[minSizeLUT[msgRread]:]
	m.r = bytes.NewReader(buffered)
	if int64(len(buffered)) < count {
		m.r = io.MultiReader(
			m.r,
			io.LimitReader(r, count-int64(len(buffered))))
	}

	return m, nil
}

func parseTwrite(dot msg, r io.Reader) (Msg, error) {
	// size[4] Twrite tag[2] fid[4] offset[8] count[4]  data[count]
	m := Twrite{msg: dot}
	offset := m.Offset()
	if offset > MaxOffset {
		return nil, errMaxOffset
	}

	count := m.Count()
	msgSize := m.Len()

	realSize := count + int64(minSizeLUT[msgTwrite])
	if realSize < msgSize {
		return nil, errUnderSize
	}
	if realSize > msgSize {
		return nil, errOverSize
	}

	buffered := dot[minSizeLUT[msgTwrite]:]
	m.r = bytes.NewReader(buffered)
	if int64(len(buffered)) < count {
		m.r = io.MultiReader(
			m.r,
			io.LimitReader(r, count-int64(len(buffered))))
	}

	return m, nil
}

func parseRwrite(dot msg, _ io.Reader) (Msg, error) {
	return Rwrite(dot), nil
}

func parseTclunk(dot msg, _ io.Reader) (Msg, error) {
	return Tclunk(dot), nil
}

func parseRclunk(dot msg, _ io.Reader) (Msg, error) {
	return Rclunk(dot), nil
}

func parseTremove(dot msg, _ io.Reader) (Msg, error) {
	return Tremove(dot), nil
}

func parseRremove(dot msg, _ io.Reader) (Msg, error) {
	return Rremove(dot), nil
}

func parseTstat(dot msg, _ io.Reader) (Msg, error) {
	return Tstat(dot), nil
}

func parseRstat(dot msg, _ io.Reader) (Msg, error) {
	stat, _, err := verifyField(dot.Body(), true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Rstat(dot), nil
}

func parseTwstat(dot msg, _ io.Reader) (Msg, error) {
	stat, _, err := verifyField(dot.Body()[4:], true, 0)
	if err != nil {
		return nil, err
	}
	if err := verifyStat(stat); err != nil {
		return nil, err
	}
	return Twstat(dot), nil
}

func parseRwstat(dot msg, _ io.Reader) (Msg, error) {
	return Rwstat(dot), nil
}
