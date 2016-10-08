package styx

import (
	"os"
	"path"

	"context"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/internal/sys"
	"aqwari.net/net/styx/styxproto"
)

// A Request is a request by a client to perform an operation
// on a file or set of files. Types of requests may range from
// checking if a file exists (Twalk) to opening a file (Topen)
// to changing a file's name (Twstat).
type Request interface {
	// Context is used to implement cancellation and request timeouts. If
	// an operation is going to take a long time to complete, you can
	// allow for the client to cancel the request by receiving on the
	// channel returned by the Context's Done method.
	Context() context.Context

	// WithContext returns a copy of the request with a new Context. It
	// can be used with nested handlers to attach information, deadlines,
	// and cancellations to a request.
	WithContext(context.Context) Request

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
	handled() bool

	// Used for nested request handlers to swap a request between
	// sub-sessions.
	setSession(*Session)
}

// common fields among all requests. Some may be nil for
// certain requests.
type reqInfo struct {
	ctx     context.Context
	tag     uint16
	fid     uint32
	session *Session
	msg     styxproto.Msg
	path    string
}

func (info reqInfo) setSession(new *Session) {
	info.session = new
}

func (info reqInfo) handled() bool {
	return !info.session.unhandled
}

func (info reqInfo) defaultResponse() {
	info.Rerror("permission denied.")
}

// Context returns the context associated with the request.
func (t reqInfo) Context() context.Context {
	return t.ctx
}

// Path returns the absolute path of the file being operated on.
func (t reqInfo) Path() string {
	return t.path
}

// Rerror sends an error to the client.
func (t reqInfo) Rerror(format string, args ...interface{}) {
	t.session.unhandled = false
	if t.session.conn.clearTag(t.tag) {
		t.session.conn.Rerror(t.tag, format, args...)
	}
}

func newReqInfo(ctx context.Context, s *Session, msg fcall, filepath string) reqInfo {
	return reqInfo{
		session: s,
		tag:     msg.Tag(),
		fid:     msg.Fid(),
		ctx:     ctx,
		msg:     msg,
		path:    filepath,
	}
}

// A Topen message is sent when a client wants to open a file for I/O
// Use the Ropen method to provide the opened file.
//
// The default response to a Topen message to send an Rerror message
// saying "permssion denied".
type Topen struct {
	// The mode to open the file with. One of the flag constants
	// in the os package, such as O_RDWR, O_APPEND etc.
	Flag int
	reqInfo
}

func (t Topen) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// The Ropen method signals to the client that a file has succesfully
// been opened and is ready for I/O. After Ropen returns, future reads
// and writes to the opened file handle will pass through rwc.
//
// The value rwc must implement some of the interfaces in the io package
// for reading and writing. If the type implements io.Seeker or io.ReaderAt
// and io.WriterAt, clients may read or write at arbitrary offsets within
// the file. Types that only implement Read or Write operations will return
// errors on writes and reads, respectively.
//
// If rwc implements the Stat method of os.File, that will be used to
// answer Tstat requests. Otherwise, the styx package will assemble Rstat
// responses out of default values merged with any methods rwc provides
// from the os.FileInfo interface.
//
// If a file does not implement any of the Read or Write interfaces in
// the io package, A generic error is returned to the client, and a message
// will be written to the server's ErrorLog.
func (t Topen) Ropen(rwc interface{}, err error) {
	var (
		file file
		f    styxfile.Interface
	)
	if err != nil {
		t.Rerror("%s", err)
		return
	}
	// The type of the file (regular or directory) will have been
	// established in a previous Twalk request.
	qid := t.session.conn.qid(t.Path(), 0)
	mode := styxfile.ModeOS(uint32(qid.Type()) << 24)

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
	t.session.unhandled = false
	if t.session.conn.clearTag(t.tag) {
		t.session.conn.Ropen(t.tag, qid, 0)
	}
}

// A Tstat message is sent when a client wants metadata about a file.
// A client should have read access to the file's containing directory.
// Call the Rstat method for a succesful request.
//
// The default response for a Tstat message is an Rerror message
// saying "permission denied".
type Tstat struct {
	reqInfo
}

func (t Tstat) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rstat responds to a succesful Tstat request. The styx package will
// translate the os.FileInfo value into the appropriate 9P structure. Rstat
// will attempt to resolve the names of the file's owner and group. If
// that cannot be done, an empty string is sent. If err is non-nil, and error
// is sent to the client instead.
func (t Tstat) Rstat(info os.FileInfo, err error) {
	if err != nil {
		t.Rerror("%s", err)
		return
	}
	buf := make([]byte, styxproto.MaxStatLen)
	uid, gid, muid := sys.FileOwner(info)
	name := info.Name()
	if name == "/" {
		name = "."
	}
	stat, _, err := styxproto.NewStat(buf, name, uid, gid, muid)
	if err != nil {
		// should never happen
		panic(err)
	}
	mode := styxfile.Mode9P(info.Mode())
	stat.SetLength(info.Size())
	stat.SetMode(mode)
	stat.SetAtime(uint32(info.ModTime().Unix())) // TODO: get atime
	stat.SetMtime(uint32(info.ModTime().Unix()))
	stat.SetQid(t.session.conn.qid(t.Path(), styxfile.QidType(mode)))
	t.session.unhandled = false
	if t.session.conn.clearTag(t.tag) {
		t.session.conn.Rstat(t.tag, stat)
	}
}

// A Tcreate message is sent when a client wants to create a new file
// and open it with the provided Mode. The Path method of a Tcreate
// message returns the absolute path of the containing directory. A user
// must have write permissions in the directory to create a file.
//
// The default response to a Tcreate message is an Rerror message
// saying "permission denied".
type Tcreate struct {
	Name string      // name of the file to create
	Mode os.FileMode // permissions and file type to create
	Flag int         // flags to open the new file with
	reqInfo
}

func (t Tcreate) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// NewPath joins the path for the Tcreate's containing directory
// with its Name field, returning the absolute path to the new file.
func (t Tcreate) NewPath() string {
	return path.Join(t.Path(), t.Name)
}

// Path returns the absolute path to the containing directory of the
// new file.
func (t Tcreate) Path() string {
	return t.reqInfo.Path() // overrode this method for the godoc comments
}

// Rcreate is used to respond to a succesful create request. With 9P, creating
// a file also opens the file for I/O. Once Rcreate returns, future read
// and write requests to the file handle will pass through rwc. The value
// rwc must meet the same criteria listed for the Ropen method of a Topen
// request.
func (t Tcreate) Rcreate(rwc interface{}, err error) {
	var (
		f styxfile.Interface
	)
	if err != nil {
		t.Rerror("%s", err)
		return
	}

	if dir, ok := rwc.(Directory); t.Mode.IsDir() && ok {
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

	qtype := styxfile.QidType(styxfile.Mode9P(t.Mode))
	qid := t.session.conn.qid(file.name, qtype)
	t.session.unhandled = false
	if t.session.conn.clearTag(t.tag) {
		t.session.conn.Rcreate(t.tag, qid, 0)
	}
}

// A Tremove message is sent when a client wants to delete a file
// from the server. The Rremove method should be called once the
// file has been succesfully deleted.
//
// The default response to a Tremove message is an Rerror message
// saying "permission denied".
type Tremove struct {
	reqInfo
}

func (t Tremove) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rremove signals to the client that a file has been succesfully
// removed. The file handle for the file is no longer valid, and may be
// re-used for other files. Whether or not any other file handles associated
// with the file continue to be usable for I/O is implementation-defined;
// many Unix file systems allow a process to continue writing to a file that
// has been "unlinked", so long as the process has an open file descriptor.
//
// If err is non-nil, an Rerror message is sent to the client. Regardless, the
// file handle is no longer valid.
func (t Tremove) Rremove(err error) {
	t.session.conn.sessionFid.Del(t.fid)
	t.session.files.Del(t.fid)

	t.session.unhandled = false
	if !t.session.conn.clearTag(t.tag) {
		// cancelled, do not send response
		return
	}

	// NOTE(droyo): This is not entirely correct; if the server wants
	// to implement unix-like semantics (the file hangs around as
	// long as there's 1 descriptor for it), we should not delete the
	// qid until *all* references to it are removed. We'll need to implement
	// reference counting for that :\
	if err != nil {
		t.session.conn.Rerror(t.tag, "%s", err)
	} else {
		t.session.conn.qidpool.Del(t.Path())
		t.session.conn.Rremove(t.tag)
	}

	if !t.session.DecRef() {
		t.session.close()
	}
}
