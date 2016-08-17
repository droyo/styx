package qidpool

import (
	"testing"

	"aqwari.net/net/styx/styxproto"
)

func TestQidpool(t *testing.T) {
	pool := New()
	pool.Put("/foo/bar", styxproto.QTDIR)

	var oldpath uint64
	var oldver uint32

	if q, ok := pool.Get("/foo/bar"); !ok {
		t.Error("could not find qid")
	} else if q.Type() != styxproto.QTDIR {
		t.Error("qid was not set to given type")
	} else {
		oldpath = q.Path()
		oldver = q.Version()
	}

	pool.Del("/foo/bar")
	if _, ok := pool.Get("/foo/bar"); ok {
		t.Error("Del did not delete qid")
	}

	pool.Put("/foo/bar", styxproto.QTDIR)
	if q, ok := pool.Get("/foo/bar"); !ok {
		t.Error("second Put did not put qid")
	} else if q.Version() == oldver && q.Path() == oldpath {
		t.Error("Put on same file did not use new qid")
	}

	pool.Put("/foo/bar", styxproto.QTAUTH)
	if q, ok := pool.Get("/foo/bar"); !ok {
		t.Error("repeated Get of qid failed")
	} else if q.Type() != styxproto.QTDIR {
		t.Error("subsequent Put replaced old qid")
	}
}
