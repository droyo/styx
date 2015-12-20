package styx

import (
	"errors"
	"io"
	"net"
	"path"
	"strings"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/internal/util"
	"aqwari.net/net/styx/styxproto"
)

func newQid(qtype uint8, version uint32, path uint64) styxproto.Qid {
	var buf [styxproto.QidLen]byte
	q, _, err := styxproto.NewQid(buf[:], qtype, version, path)
	if err != nil {
		panic(err)
	}
	return q
}

type session struct {
	uname, aname string
}

var (
	errFidInUse     = errors.New("fid already in use")
	errNoFid        = errors.New("no such fid")
	errNotSupported = errors.New("not supported")
)

// an open file or position in a directory
type file struct {
	path  string
	ftype uint8
	data  io.ReadWriteCloser
}

// A conn implements the styxproto.Server interface.
type conn struct {
	srv    *Server
	qidbuf [styxproto.QidLen]byte
	cx     context.Context

	afid    util.Map //map[fid] session
	session util.Map //map[fid] session
	file    util.Map //map[fid] file
}

func (h *conn) validAfid(afid uint32, user, access string) bool {
	var s session
	return h.afid.Fetch(afid, &s) && s.uname == user && s.aname == access
}

func (h *conn) getSession(fid uint32) (session, bool) {
	s, ok := h.session.Get(fid)
	return s.(session), ok
}

func (h *conn) putSession(fid uint32, uname, aname string) {
	h.session.Put(fid, session{
		uname: uname,
		aname: aname,
	})
}

// returns an error if fid is in use for another file
func (h *conn) putFile(fid uint32, path string, ftype uint8, data io.ReadWriteCloser) error {
	if h.file.Add(fid, file{path: path, ftype: ftype, data: data}) {
		return nil
	}
	return errFidInUse
}

func (h *conn) getFile(fid uint32) (f file, ok bool) {
	ok = h.file.Fetch(fid, &f)
	return f, ok
}

// newConn returns a conn for a new connection.
func newConn(srv *Server, cx context.Context) *conn {
	return &conn{
		srv: srv,
	}
}

func (h *conn) Attach(w *styxproto.ResponseWriter, m styxproto.Tattach) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	rootQid := newQid(styxproto.QTDIR, 0, util.Hash64(m.Aname()))
	if afid := m.Afid(); afid == styxproto.NoFid && h.srv.Auth != nil {
		ch := Channel{
			Context:         h.cx,
			ReadWriteCloser: util.BlackHole{},
		}
		err := h.srv.Auth.Auth(&ch, string(m.Uname()), string(m.Aname()))
		if err != nil {
			w.Rerror(m.Tag(), "%s", err)
			return
		}
	} else if afid != styxproto.NoFid && h.srv.Auth != nil {
		if !h.validAfid(afid, string(m.Uname()), string(m.Aname())) {
			w.Rerror(m.Tag(), "auth failed")
			return
		}
	}
	if err := h.putFile(m.Fid(), "/", rootQid.Type(), nil); err != nil {
		w.Rerror(m.Tag(), "%s", err)
	} else {
		w.Rattach(m.Tag(), rootQid)
	}
}

func (h *conn) Auth(w *styxproto.ResponseWriter, m styxproto.Tauth) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	if h.srv.Auth == nil {
		w.Rerror(m.Tag(), "not supported")
		return
	}

	aqid := newQid(styxproto.QTAUTH, 0, 0)
	client, server := net.Pipe()
	if err := h.putFile(m.Afid(), "", styxproto.QTAUTH, client); err != nil {
		w.Rerror(m.Tag(), "%s", err)
		client.Close()
		return
	}
	uname, aname := string(m.Uname()), string(m.Aname())

	ch := Channel{
		Context:         w.Context,
		ReadWriteCloser: server,
	}
	go h.srv.Auth.Auth(&ch, uname, aname)
	w.Rauth(m.Tag(), aqid)
}

func (h *conn) Clunk(w *styxproto.ResponseWriter, m styxproto.Tclunk) {
	defer w.Close()
	h.srv.debugf("← %s", m)

	file, ok := h.getFile(m.Fid())
	if !ok {
		w.Rerror(m.Tag(), "%s", errNoFid)
		return
	}
	h.file.Del(m.Fid())
	if file.data != nil {
		file.data.Close()
	}
	w.Rclunk(m.Tag())
}

func (h *conn) Create(w *styxproto.ResponseWriter, m styxproto.Tcreate) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Open(w *styxproto.ResponseWriter, m styxproto.Topen) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Read(w *styxproto.ResponseWriter, m styxproto.Tread) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	_, ok := h.getFile(m.Fid())
	if !ok {
		w.Rerror(m.Tag(), "%s", errNoFid)
		return
	}
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Remove(w *styxproto.ResponseWriter, m styxproto.Tremove) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Stat(w *styxproto.ResponseWriter, m styxproto.Tstat) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Walk(w *styxproto.ResponseWriter, m styxproto.Twalk) {
	defer w.Close()
	h.srv.debugf("← %s", m)

	parent, ok := h.getFile(m.Fid())
	if !ok {
		w.Rerror(m.Tag(), "%s", errNoFid)
		return
	}
	if parent.ftype == styxproto.QTAUTH {
		w.Rerror(m.Tag(), "cannot walk from afid")
		return
	}
	s := make([]string, 0, m.Nwname()+1)
	s = append(s, parent.path)
	q := make([]styxproto.Qid, 0, m.Nwname())
	for i := 0; i < m.Nwname(); i++ {
		s = append(s, string(m.Wname(i)))
		q = append(q, newQid(styxproto.QTDIR, 0, util.Hash64(m.Wname(i))))
	}
	p := path.Clean(strings.Join(s, "/"))
	if strings.Contains(p, "Trash") {
		w.Rerror(m.Tag(), "file %q not found", p)
		return
	}
	if err := h.putFile(m.Newfid(), p, styxproto.QTDIR, nil); err != nil {
		w.Rerror(m.Tag(), "%s", err)
	} else {
		h.srv.debugf("walked from %q to %q", parent.path, p)
		w.Rwalk(m.Tag(), q...)
	}
}

func (h *conn) Write(w *styxproto.ResponseWriter, m styxproto.Twrite) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}

func (h *conn) Wstat(w *styxproto.ResponseWriter, m styxproto.Twstat) {
	defer w.Close()
	h.srv.debugf("← %s", m)
	w.Rerror(m.Tag(), "%s", errNotSupported)
}
