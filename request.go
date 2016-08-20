package styx

import (
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/net/context"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/internal/sys"
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
	defer info.session.conn.clearTag(info.tag)
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

func (t Topen) Ropen(rwc interface{}, mode os.FileMode) {
	defer t.session.conn.clearTag(t.tag)
	var (
		file file
		f    styxfile.Interface
		err  error
	)
	if dir, ok := rwc.(Directory); ok && mode.IsDir() {
		f = styxfile.NewDir(dir, t.Path(), t.session.conn.qidpool)
	} else {
		f, err = styxfile.New(rwc)
	}

	if err != nil {
		t.session.conn.srv.logf("%s open %s failed: %s", t.path, err)

		// Don't want to expose too many implementation details
		// to clients.
		t.Rerror("open failed")
		return
	}
	t.session.files.Update(t.fid, &file, func() {
		file.rwc = f
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
	// We have to keep the original path around to give
	// the client the correct sequence of qids.
	dirtypath string
	reqInfo
}

// Path returns the absolute path of the directory the client
// is walking to. The path is normalized; all '..' sequences,
// double slashes, etc are removed.
func (t Twalk) Path() string {
	return t.newpath
}

// NOTE(droyo) This API needs some more thought. An Rwalk
// gives back the Qids for the path from the Twalk's fid, to
// the final element in nwelem. We're not taking info for the
// intermediates from the user, instead assuming QTDIR.
// Is that correct in every case?

func (t Twalk) Rwalk(exists bool, mode os.FileMode) {
	defer t.session.conn.clearTag(t.tag)
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
	defer t.session.conn.clearTag(t.tag)
	buf := make([]byte, styxproto.MaxStatLen)
	uid, gid, muid := sys.FileOwner(info)
	stat, _, err := styxproto.NewStat(buf,
		info.Name(), // name
		uid,
		gid,
		muid,
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

func (t Tcreate) Rcreate(rwc interface{}) {
	defer t.session.conn.clearTag(t.tag)
	var (
		f   styxfile.Interface
		err error
	)
	if dir, ok := rwc.(Directory); t.Perm.IsDir() && ok {
		f = styxfile.NewDir(dir, path.Join(t.Path(), t.Name), t.session.conn.qidpool)
	} else {
		f, err = styxfile.New(rwc)
	}
	if err != nil {
		t.session.conn.srv.logf("create %s failed: %s", t.Name, err)
		t.Rerror("create failed")
		return
	}
	file := file{name: path.Join(t.Path(), t.Name), rwc: f}

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
	defer t.session.conn.clearTag(t.tag)
	t.session.conn.sessionFid.Del(t.fid)
	t.session.files.Del(t.fid)
	t.session.conn.qidpool.Del(t.Path())
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
	defer t.session.conn.clearTag(t.tag)
	t.session.conn.Rwstat(t.tag)
}

func (t Twstat) defaultResponse() {
	t.Rerror("permission denied")
}

// Make a Stat look like an os.FileInfo
type statInfo styxproto.Stat

func (s statInfo) Name() string { return string(styxproto.Stat(s).Name()) }
func (s statInfo) Size() int64  { return styxproto.Stat(s).Length() }

func (s statInfo) Mode() os.FileMode {
	return fileMode(styxproto.Stat(s).Mode())
}

func (s statInfo) ModTime() time.Time {
	return time.Unix(int64(styxproto.Stat(s).Mtime()), 0)
}

func (s statInfo) IsDir() bool {
	return styxproto.Stat(s).Mode()&styxproto.DMDIR != 0
}

func (s statInfo) Sys() interface{} {
	return styxproto.Stat(s)
}
