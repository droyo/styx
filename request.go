package styx

import (
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/styxproto"
)

// A Request is a request by a client to perform an operation
// on a file or set of files. Types of requests may range from
// checking if a file exists (Twalk) to opening a file (Topen)
// to changing a file's name (Twstat).
type Request interface {
	// The context.Context interface is used to implement cancellation and
	// request timeouts. If an operation is going to take a long time to
	// complete, you can allow for the client to cancel the request by receiving
	// on the channel returned by Done().
	context.Context

	// If a request is invalid, not allowed, or cannot be completed properly
	// for some other reason, its Rerror method should be used to respond
	// to it.
	Rerror(format string, args ...interface{})

	// Path returns the Path of the file being operated on.
	Path() string

	// For the programmer's convenience, each request type has a default
	// response. Programmers can choose to ignore requests of a given
	// type and have the styx package send default responses to them.
	// In most cases, the default response is to send an error that the user
	// has insufficient permissions or the file in question does not exist.
	defaultResponse()
}

// common fields among all requests. Some may be nil for
// certain requests.
type reqInfo struct {
	context.Context
	tag     uint16
	fid     uint32
	session *Session
	msg     styxproto.Msg
	path    string
}

// Path returns the absolute path of the file being operated on.
func (info reqInfo) Path() string {
	return info.path
}

func (info reqInfo) Rerror(format string, args ...interface{}) {
	info.session.conn.Rerror(info.tag, format, args...)
}

func newReqInfo(cx context.Context, s *Session, msg fcall, filepath string) reqInfo {
	return reqInfo{
		session: s,
		tag:     msg.Tag(),
		fid:     msg.Fid(),
		Context: cx,
		msg:     msg,
		path:    filepath,
	}
}

func qidType(mode os.FileMode) uint8 {
	var qtype uint8
	if mode&os.ModeDir != 0 {
		qtype = styxproto.QTDIR
	}
	if mode&os.ModeAppend != 0 {
		qtype |= styxproto.QTAPPEND
	}
	if mode&os.ModeExclusive != 0 {
		qtype |= styxproto.QTEXCL
	}
	if mode&os.ModeTemporary != 0 {
		qtype |= styxproto.QTTMP
	}
	return qtype
}

func fileMode(perm uint32) os.FileMode {
	var mode os.FileMode
	if perm&styxproto.DMDIR != 0 {
		mode = os.ModeDir
	}
	if perm&styxproto.DMAPPEND != 0 {
		mode |= os.ModeAppend
	}
	if perm&styxproto.DMEXCL != 0 {
		mode |= os.ModeExclusive
	}
	if perm&styxproto.DMTMP != 0 {
		mode |= os.ModeTemporary
	}
	mode |= (os.FileMode(perm) & os.ModePerm)
	return mode
}

func modePerm(mode os.FileMode) uint32 {
	var perm uint32
	if mode&os.ModeDir != 0 {
		perm |= styxproto.DMDIR
	}
	if mode&os.ModeAppend != 0 {
		perm |= styxproto.DMAPPEND
	}
	if mode&os.ModeExclusive != 0 {
		perm |= styxproto.DMEXCL
	}
	if mode&os.ModeTemporary != 0 {
		perm |= styxproto.DMTMP
	}
	return perm | uint32(mode&os.ModePerm)
}

// A Topen message is sent when a client wants to open a file for writing.
// The Ropen method should be called to provide the opened file.
type Topen struct {
	Flag int // the mode to open the file in
	reqInfo
}

func (t Topen) Ropen(rwc io.ReadWriteCloser, mode os.FileMode) {
	var file file
	t.session.files.Update(t.fid, &file, func() {
		file.rwc = rwc
	})
	qid := t.session.conn.qid(t.Path(), qidType(mode))
	t.session.conn.Ropen(t.tag, qid, 0)
}

func (t Topen) defaultResponse() {
	t.Rerror("permission denied")
}

// A Twalk message is sent when a client wants to check that a given
// file exists. Call its Rwalk method to answer.
type Twalk struct {
	newfid  uint32
	newpath string
	reqInfo
}

// NOTE(droyo) This API needs some more thought. An Rwalk
// gives back the Qids for the path from the Twalk's fid, to
// the final element in nwelem. We're not taking info for the
// intermediates from the user, instead assuming QTDIR.
// Is that correct in every case?

func (t Twalk) Rwalk(exists bool, mode os.FileMode) {
	if !exists {
		t.defaultResponse()
		return
	}

	t.session.files.Put(t.newfid, file{name: t.newpath})
	t.session.conn.sessionFid.Put(t.newfid, t.session)
	t.session.IncRef()

	qtype := qidType(mode)
	wqid := make([]styxproto.Qid, strings.Count(t.newpath, "/")+1)
	wqid[len(wqid)-1] = t.session.conn.qid(t.newpath, qtype)
	dir, _ := path.Split(t.newpath)
	for i := len(wqid) - 2; i >= 0; i-- {
		wqid[i] = t.session.conn.qid(dir, styxproto.QTDIR)
		if wqid[i].Type()&styxproto.QTDIR == 0 {
			t.Rerror("not a directory: %q", dir)
			return
		}
		dir, _ = path.Split(dir)
	}
	if err := t.session.conn.Rwalk(t.tag, wqid...); err != nil {
		panic(err)
	}
}

func (t Twalk) defaultResponse() {
	t.Rerror("no such file or directory")
}

// A Tstat message is sent when a client wants metadata about a file.
type Tstat struct {
	reqInfo
}

func (t Tstat) Rstat(info os.FileInfo) {
	buf := make([]byte, styxproto.MaxStatLen)
	stat, _, err := styxproto.NewStat(buf,
		info.Name(), // name
		"nobody",    // uid (TODO)
		"nobody",    // guid (TODO)
		"nobody",    // muid (TODO)
	)
	if err != nil {
		// should never happen
		panic(err)
	}
	stat.SetLength(info.Size())
	stat.SetMode(modePerm(info.Mode()))
	stat.SetAtime(uint32(info.ModTime().Unix())) // TODO: get atime
	stat.SetMtime(uint32(info.ModTime().Unix()))
	stat.SetQid(t.session.conn.qid(t.Path(), qidType(info.Mode())))
	t.session.conn.Rstat(t.tag, stat)
}

func (t Tstat) defaultResponse() {
	t.Rerror("permission denied")
}

// A Tcreate message is sent when a client wants to create a new file
// and open it with the provided Mode. The Path method of a Tcreate
// message returns the absolute path of the containing directory. A user
// must have write permissions in the directory to create a file.
type Tcreate struct {
	Name string      // name of the file to create
	Perm os.FileMode // permissions and file type to create
	Flag int         // flags to open the new file with
	reqInfo
}

func (t Tcreate) Rcreate(rwc io.ReadWriteCloser) {
	file := file{name: path.Join(t.Path(), t.Name), rwc: rwc}

	// fid for parent directory is now the fid for the new file,
	// so there is no increase in references to this session.
	t.session.files.Put(t.fid, file)

	qtype := qidType(t.Perm)
	qid := t.session.conn.qid(file.name, qtype)
	t.session.conn.Rcreate(t.tag, qid, 0)
}

func (t Tcreate) defaultResponse() {
	t.Rerror("permission denied")
}

// A Tremove message is sent when a client wants to delete a file
// from the server.
type Tremove struct {
	reqInfo
}

func (t Tremove) Rremove() {
	t.session.conn.sessionFid.Del(t.fid)
	t.session.files.Del(t.fid)
	t.session.conn.qids.Del(t.Path())
	t.session.conn.Rremove(t.tag)
	if !t.session.DecRef() {
		t.session.close()
	}
}

func (t Tremove) defaultResponse() {
	t.Rerror("permission denied")
}

// A Twstat message is sent when a client wants to update the
// metadata about a file on the server.
type Twstat struct {
	Stat os.FileInfo
	reqInfo
}

func (t Twstat) Rwstat() {
	t.session.conn.Rwstat(t.tag)
}

func (t Twstat) defaultResponse() {
	t.Rerror("permission denied")
}
