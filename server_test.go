package styx

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aqwari.net/net/styx/internal/netutil"
	"aqwari.net/net/styx/styxproto"
)

type dialee interface {
	Dial() (net.Conn, error)
}

type testLogger testing.T

func (t *testLogger) Printf(format string, args ...interface{}) {
	t.Logf(format, args...)
}

func sendClientTraffic(t *testing.T, ln *netutil.PipeListener) {
	c, err := ln.Dial()
	if err != nil {
		t.Error(err)
		return
	}
	file, err := os.Open(filepath.Join("styxproto", "testdata", "sample.client.9p"))
	if err != nil {
		t.Error(err)
		return
	}

	go func() {
		io.Copy(c, file)
		time.Sleep(time.Second)
		c.Close()
	}()

	d := styxproto.NewDecoder(c)
	for d.Next() {
		for _, msg := range d.Messages() {
			t.Logf("%d %s", msg.Tag(), msg)
		}
	}
	if d.Err() != nil {
		t.Log(d.Err())
	}
}

func TestServerBasic(t *testing.T) {
	srv := Server{
		ErrorLog: (*testLogger)(t),
		TraceLog: (*testLogger)(t),
	}
	var ln netutil.PipeListener
	defer ln.Close()

	go func() {
		t.Log(srv.Serve(&ln))
	}()
	sendClientTraffic(t, &ln)
}

func TestEchoServer(t *testing.T) {
	mux := NewServeMux()
	srv := Server{
		ErrorLog: (*testLogger)(t),
		TraceLog: (*testLogger)(t),
		Handler:  mux,
	}
	var ln netutil.PipeListener
	defer ln.Close()

	mux.HandleFunc("/", func(s *Session) {
		for msg := range s.Requests {
			t.Logf("%T %s", msg, msg.Path())
			switch msg := msg.(type) {
			case Topen:
				file, _ := os.Open(os.DevNull)
				msg.Ropen(file, 0666)
			default:
				msg.defaultResponse()
			}
		}
	})
	go func() {
		t.Log(srv.Serve(&ln))
	}()
	sendClientTraffic(t, &ln)
}
