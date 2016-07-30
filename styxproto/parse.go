package styxproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

var (
	errShortRead = errors.New("not enough data in buffer to complete message")
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

// read just enough data to figure out the type of message and if
// it's the right size.
func (s *Decoder) nextHeader() (msg, error) {
	return s.growdot(minMsgSize)
}

// fetchMessages returns all available 9P messages from r. r must be
// a bufio.Reader with size greater than MinBufSize. fetchMessages is
// guaranteed to fetch at least one 9P message if err != nil.  For
// every invalid message, a BadMessage is added to s.msg. fetchMessages
// will only call Read if there is not enough data buffered to parse at least
// one message.
func (s *Decoder) fetchMessages() error {
	var err error
	result := s.msg[:0]

	for {
		oldstart := s.start
		result, err = s.fetchOne(result)
		if err != nil {
			break
		}
		if oldstart == s.start {
			panic("decoder did not advance but did not return an error")
		}
	}
	if (err == bufio.ErrBufferFull || err == errShortRead) && len(result) > 0 {
		err = nil
	}
	if err == io.EOF && s.dotlen() != 0 {
		err = io.ErrUnexpectedEOF
	}
	s.err = err
	s.msg = result
	return s.err
}

// fetchOne reads the next buffered message and adds it to
// result. fetchOne will return bufio.ErrBufferFull if there is not
// enough space in the buffer to hold the next message. fetchOne
// will not perform additional I/O unless this is the first message being
// parsed (len(result) == 0).
func (s *Decoder) fetchOne(result []Msg) ([]Msg, error) {
	// fetchMessages guarantees it will return at least one message.
	first := (len(result) == 0)

	if s.buflen() < minMsgSize && !first {
		return result, errShortRead
	}

	dot, err := s.nextHeader()
	if err != nil {
		return result, err
	}

	if err := verifySize(dot); err != nil {
		return s.badMessage(result, dot, err)
	}

	msgType := dot.Type()
	msgSize := dot.Len()
	if s.MaxSize > 0 && msgSize > s.MaxSize {
		return result, ErrMaxSize
	}

	minSize := minSizeLUT[msgType]
	if s.buflen()-minSize < s.dotlen() && !first {
		return result, errShortRead
	}

	if _, err := s.growdot(minSize); err != nil {
		return result, err
	}

	if msgType == msgTwrite || msgType == msgRread {
		return s.readRW(result)
	}
	return s.readFixed(result)
}

// Every message besides Twrite and Rread have a small maximum size,
// and are stored wholly in memory for convenience.
func (s *Decoder) readFixed(result []Msg) ([]Msg, error) {
	first := (len(result) == 0)
	msg := msg(s.dot())
	msgSize, msgType := msg.Len(), msg.Type()

	if int64(s.buflen())+int64(s.dotlen()) < msgSize && !first {
		return result, errShortRead
	}

	msg, err := s.growdot(int(msgSize))
	if err != nil {
		return result, err
	}

	parsed, err := parseMsg(msgType, msg, nil)

	// Nothing left to read, all that's possible are parsing errors
	if err != nil {
		return s.badMessage(result, msg, err)
	}

	s.mark()
	return append(result, parsed), nil
}

func (s *Decoder) readRW(result []Msg) ([]Msg, error) {
	var err error

	msg := msg(s.dot())
	msgSize, msgType := msg.Len(), msg.Type()

	readSize := s.buflen() + s.dotlen()
	if int64(readSize) > msgSize {
		readSize = int(msgSize)
	}

	msg, err = s.growdot(readSize)
	if err != nil {
		panic("read of buffered data failed: " + err.Error())
	}

	parsed, err := parseMsg(msgType, msg, s.r)
	if err != nil {
		return s.badMessage(result, msg, err)
	}

	s.mark()
	return append(result, parsed), nil
}

func parseMsg(t uint8, m msg, r io.Reader) (Msg, error) {
	return msgParseLUT[t](m, r)
}

func (s *Decoder) badMessage(result []Msg, bad msg, reason error) ([]Msg, error) {
	// Invalid messages are a bit tricky; we want the caller to know right
	// away that that an invalid message was encountered (so that he may
	// choose to sever the connection), but if the message is not fully buffered,
	// we do not want to perform additional I/O (and possibly block) just to
	// skip the message. This is why the BadMessage type has a field for the
	// number of bytes to skip, rather than the bytes themselves.
	length := bad.Len()
	result = append(result, BadMessage{
		Err:    reason,
		tag:    bad.Tag(),
		length: length,
	})
	if length == 0 {
		return result, errZeroLen
	}
	if int64(s.buflen()+s.dotlen()) < length {
		return result, errShortRead
	}
	// We can still continue parsing. This prevents one bad client
	// from hurting performance for others on the same connection.
	if s.dotlen() > int(length) {
		s.shrinkdot(s.dotlen() - int(length))
	} else if _, err := s.growdot(int(length)); err != nil {
		panic(err)
	}
	s.mark()
	return result, nil
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
		} else if err := verifyString(el); err != nil {
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
	stat, _, err := verifyField(dot.Body(), true, 0)
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
