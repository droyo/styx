package factotum

import (
	"errors"
	"fmt"
	"os"
	"bytes"
	"log"

	"aqwari.net/net/styx"
)

const (
	//Factotum rpc responses
	ARok = "ok"
	ARdone = "done"
	ARerror = "error"
	ARbadkey = "badkey"
	ARtoosmall = "toosmall"
	ARphase = "phase"
	ARneedkey = "needkey"

	//Factotum rpc commands
	ARread = "read"
	ARwrite = "write"
	ARauthinfo = "authinfo"
	ARstart = "start"

	AuthRpcMax = 4096
)

var tab = []string{ARok, ARdone, ARerror, ARneedkey, ARbadkey, ARtoosmall, ARphase}

var ErrMalformedRpc = errors.New("malformed rpc response")

var ErrUnknownRpc = errors.New("Unknown rpc")

var ErrBotchRpc = errors.New("authrpc botch")

type AuthRpc struct {
	*os.File
}

//See /sys/src/libauth/auth_rpc.c:/^classify/
func (a *AuthRpc) classify(b []byte) (string, []byte, error) {
	for _, s := range tab {
		if bytes.HasPrefix(b, []byte(s)) {
			if len(b) == len(s) {
				return s, b, nil
			}
			return s, b[len(s)+1:], nil
		}
	}
	return "", nil, ErrMalformedRpc
}

//See /sys/src/libauth/auth_rpc.c:/^auth_rpc/
func (a *AuthRpc) do(verb string, b []byte) (string, []byte, error) {
	b = append(append([]byte(verb), byte(' ')), b...)
	a.Write(b)

	b = make([]byte, AuthRpcMax)
	_, err := a.Read(b)
	if err != nil {
		return "", nil, err
	}

	var ret string
	ret, b, err = a.classify(b)
	if err != nil {
		return ret, b, err
	}
	log.Println("Got phase", ret)
	switch ret {
	default:
		return ret, nil, ErrUnknownRpc
	case ARdone:
	case ARok:
	case ARneedkey:
		fallthrough
	case ARbadkey:
		fallthrough
	case ARphase:
		fallthrough
	case ARerror:
		return ret, nil, errors.New(string(b))
	}
	return ret, b, nil
}

//See /sys/src/lib9p/auth.c:/^_authread/
func (a *AuthRpc) ReadAt(b []byte, off int64) (int, error) {
	ret, resp, err := a.do(ARread, b)
	if err != nil {
		return 0, err 
	}
	switch ret {
	default:
		return 0, ErrBotchRpc
	case ARdone:
		fallthrough
	case ARok:
		copy(b, resp)
		return len(b), nil
	}
	return 0, ErrBotchRpc
}

//See /sys/src/lib9p/auth.c:/^authwrite/
func (a *AuthRpc) WriteAt(b []byte, off int64) (int, error) {
	ret, _, err := a.do(ARwrite, b)
	if err != nil {
		return 0, err
	}
	switch ret {
	default:
		return 0, ErrBotchRpc
	case ARdone:
		fallthrough
	case ARok:
		return len(b), nil
	}
	return 0, ErrBotchRpc
}

func (a *AuthRpc) Close() error {
	return nil
}

func Start(proto string) (styx.AuthFunc, styx.AuthOpenFunc) {
	s := fmt.Sprintf("proto=%s role=server", proto)

	af := func(rwc *styx.Channel, user, access string) error {
		i := rwc.Context.Value("Auth")
		if i == nil {
			return errors.New("Tattach before Tauth")
		}
		a, ok := i.(*AuthRpc)
		if !ok {
			return errors.New("cast to AuthRpc failed")
		}
		ret, _, err := a.do("read", []byte{})
		if err != nil {
			return err
		}
		if ret != ARdone {
			return errors.New("Auth is not done")
		}
		return nil
	}
	aof := func() (interface{}, error) {
		f, err := os.OpenFile("/mnt/factotum/rpc", os.O_RDWR, 0755)
		if err != nil {
			return nil, nil
		}
		a := &AuthRpc{f}

		ret, _, err := a.do("start", []byte(s))
		if err != nil {
			return nil, err
		}
		if ret != ARok {
			return nil, errors.New("did not get OK for start")
		}
		return a, nil
	}
	return af, aof
}