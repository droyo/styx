package styx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"aqwari.net/net/styx/internal/netutil"
	"aqwari.net/net/styx/styxproto"
)

type testLogger struct {
	*testing.T
}

func (t testLogger) Printf(format string, args ...interface{}) {
	t.Logf(format, args...)
}

type testServer struct {
	callback func(req, rsp string)
	handler  Handler
	test     *testing.T
}

func openfile(filename string) (*os.File, func()) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return file, func() { file.Close() }
}

func (s testServer) run(input io.Reader) {
	// NOTE(droyo): Because the styxproto package re-uses the space
	// storing a styxproto.Msg with each call to Next, we need to copy
	// a message to pair it with a response. Rather than implementing
	// a message copy, we just keep a string description.
	type msg struct {
		s   string
		tag uint16
	}

	var ln netutil.PipeListener
	defer ln.Close()

	if s.callback == nil {
		s.callback = func(string, string) {}
	}
	srv := Server{
		Handler:  s.handler,
		ErrorLog: testLogger{s.test},
	}
	go srv.Serve(&ln)

	conn, _ := ln.Dial()
	in := styxproto.NewDecoder(input)
	out := styxproto.NewDecoder(conn)

	step := make(chan msg)
	go func() {
		var wg sync.WaitGroup
		for out.Next() {
			s.test.Logf("\t← %03d %s", out.Msg().Tag(), out.Msg())
			wg.Add(1)
			go func(tag uint16, s string) {
				step <- msg{tag: tag, s: s}
				wg.Done()
			}(out.Msg().Tag(), fmt.Sprintf("%s", out.Msg()))
		}
		if err := out.Err(); err != nil && err != io.ErrClosedPipe {
			s.test.Error(err)
		} else {
			s.test.Log("server closed connection")
		}
		wg.Wait()
		close(step)

		// Force client to stop writing when server is
		// done
		conn.Close()
	}()

	pending := make(map[uint16]string)
Loop:
	for in.Next() {
		req := in.Msg()
		if _, ok := pending[req.Tag()]; ok {
			rsp, ok := <-step
			if !ok {
				break Loop
			}
			if r, ok := pending[rsp.tag]; ok {
				s.callback(r, rsp.s)
				delete(pending, rsp.tag)
			}
		}
		if _, err := styxproto.Write(conn, in.Msg()); err != nil {
			break Loop
		}
		s.test.Logf("\t→ %03d %s", req.Tag(), req)
		pending[req.Tag()] = fmt.Sprintf("%s", req)
	}
	conn.Close()
	if err := out.Err(); err != nil {
		s.test.Error(err)
	}
	<-step
}

func (s testServer) runMsg(fn func(*styxproto.Encoder)) {
	rd, wr := io.Pipe()
	e := styxproto.NewEncoder(wr)
	go func() {
		e.Tversion(styxproto.DefaultMaxSize, "9P2000")
		e.Tattach(0, 0, styxproto.NoFid, "", "")
		fn(e)
		e.Tclunk(0, 0)
		e.Flush()
		wr.Close()
	}()
	s.run(rd)
}

func (s testServer) runFile(inputfile string) {
	file, cleanup := openfile(inputfile)
	defer cleanup()
	s.run(file)
}

func TestSample(t *testing.T) {
	s := testServer{test: t}
	s.runFile("styxproto/testdata/sample.client.9p")
}

// The only valid response to a Tflush request is an
// Rflush request, regardless of its success.
func TestRflush(t *testing.T) {
	s := testServer{test: t}
	s.callback = func(req, rsp string) {
		if strings.Contains(req, "Tflush") {
			if !strings.Contains(rsp, "Rflush") {
				t.Error("got %s response to %s", rsp, req)
			}
		}
	}
	s.runMsg(func(enc *styxproto.Encoder) {
		enc.Twalk(1, 0, 1)
		enc.Tflush(2, 1)
		enc.Tflush(3, 2)
		enc.Tflush(2, 1)
		enc.Tflush(2, 2)
		enc.Tflush(1, 300)
		enc.Tclunk(1, 1)
	})
}

// This test does not work because our testServer client is
// in lock-step with the server; it only sends a request when
// it receives a response to the previous request.
func TestCancel(t *testing.T) {
	srv := testServer{test: t}
	const timeout = time.Millisecond * 200
	srv.handler = HandlerFunc(func(s *Session) {
		for s.Next() {
			switch req := s.Request().(type) {
			case Tstat:
				select {
				case <-time.After(timeout):
					t.Errorf("Tstat not cancelled within %s",
						timeout)
				case <-req.Context().Done():
					t.Logf("request cancelled")
					req.Rerror("cancelled")
				}
			}
		}
	})

	srv.runMsg(func(enc *styxproto.Encoder) {
		enc.Twalk(1, 0, 1)
		enc.Tstat(1, 1)
		enc.Tflush(2, 1)
		enc.Tclunk(1, 1)
	})
}
