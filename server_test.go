package styx

import (
	"io"
	"os"
	"testing"

	"aqwari.net/net/styx/internal/netutil"
	"aqwari.net/net/styx/styxproto"
)

type testLogger struct {
	*testing.T
}

func (t testLogger) Printf(format string, args ...interface{}) {
	t.Logf(format, args...)
}

type callback func(styxproto.Msg)

type testServer struct {
	send, recv callback
	handler    Handler
	test       *testing.T
}

func openfile(filename string) (*os.File, func()) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return file, func() { file.Close() }
}

func (s testServer) run(input io.Reader) {
	var ln netutil.PipeListener
	defer ln.Close()

	if s.send == nil {
		s.send = func(styxproto.Msg) {}
	}
	if s.recv == nil {
		s.recv = func(styxproto.Msg) {}
	}
	srv := Server{
		Handler:  s.handler,
		ErrorLog: testLogger{s.test},
	}
	go srv.Serve(&ln)

	conn, _ := ln.Dial()
	in := styxproto.NewDecoder(input)
	out := styxproto.NewDecoder(conn)

	step := make(chan struct{})
	go func() {
		for out.Next() {
			s.test.Logf("← %03d %s", out.Msg().Tag(), out.Msg())
			s.recv(out.Msg())
			step <- struct{}{}
		}
		if err := out.Err(); err != nil {
			s.test.Error(err)
		} else {
			s.test.Log("server closed connection")
		}
		close(step)

		// Force client to stop writing when server is
		// done
		conn.Close()
	}()

Loop:
	for in.Next() {
		s.test.Logf("→ %03d %s", in.Msg().Tag(), in.Msg())
		if _, err := styxproto.Write(conn, in.Msg()); err != nil {
			break Loop
		}
		s.send(in.Msg())
		if _, ok := <-step; !ok {
			break Loop
		}
	}
	conn.Close()
	if err := out.Err(); err != nil {
		s.test.Error(err)
	}
}

func (s testServer) runMsg(fn func(*styxproto.Encoder)) {
	rd, wr := io.Pipe()
	e := styxproto.NewEncoder(wr)
	go func() {
		e.Tversion(styxproto.DefaultMaxSize, "9P2000")
		fn(e)
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

func TestBasic(t *testing.T) {
	s := testServer{test: t}
	s.runFile("styxproto/testdata/sample.client.9p")
}
