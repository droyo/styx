package styx

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"aqwari.net/net/styx/internal"
)

type dialee interface {
	Dial() (net.Conn, error)
}

type testLogger testing.T

func (t *testLogger) Printf(format string, v ...interface{}) {
	t.Logf(format, v...)
}

func sendTraffic(t *testing.T, ln *internal.PipeListener) {
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
	io.Copy(c, file)
}

func TestServerBasic(t *testing.T) {
	srv := Server{
		ErrorLog: (*testLogger)(t),
		TraceLog: (*testLogger)(t),
	}
	var ln internal.PipeListener
	defer ln.Close()

	go func() {
		t.Log(srv.Serve(&ln))
	}()
	sendTraffic(t, &ln)
}
