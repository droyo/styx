package styx

import (
	"fmt"
	"os"
	"path"
	"strings"

	"context"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/styxproto"
)

// The walk RPC is one of the more complex requests in the 9P protocol
// (though that's not saying much). There are a number of different
// responses that a server must make:
//
// 	- If the file exists: Rwalk with nwname qids
// 	- If no elements in the path exist: Rerror
// 	- If at least 1 element in the path exists: Rwalk with n(<nwname) qids
//
// In addition, walks are relative to another file, so a server must track
// that as well. The styx package attempts to hide this complexity from the
// (API) user.
//
// For any Twalk requests with nwname > 1, the styx package will synthesize
// nwname individual Twalk requests, such that each request is the next
// element in the path.
//
// The relative path in the Twalk request is combined with the path of fid
// to produce an absolute path to the requested file. All paths are Cleaned
// before being passed to user code.
//
// Thus given the following protocol message (fids replaced with their paths):
//
// 	Twalk /usr/share 6 ../include/linux/../../bin
//
// The user's program will instead see and respond to, *IN THIS ORDER*
//
// 	Twalk /usr
// 	Twalk /usr/include
// 	Twalk /usr/include/linux
// 	Twalk /usr/include
// 	Twalk /usr
// 	Twalk /usr/bin
//
// The order that the program sees the path in is important, as it allows
// certain synthetic file systems to create resources "on-demand", as the
// client asks for them.
type walkElem struct {
	index int
	qid   styxproto.Qid // nil if not present
	err   error
}

type walker struct {
	qids, found []styxproto.Qid
	filled      []int32
	count       int
	complete    chan struct{}
	collect     chan walkElem
	newfid      uint32
	path        string

	// for cancellation
	ctx context.Context

	session *Session
	tag     uint16
}

func newWalker(s *Session, ctx context.Context, msg styxproto.Twalk, base string, elem ...string) *walker {
	qids := make([]styxproto.Qid, len(elem))
	found := qids[:0]
	newpath := path.Join(base, strings.Join(elem, "/"))
	w := &walker{
		qids:     qids,
		found:    found,
		filled:   make([]int32, len(elem)),
		complete: make(chan struct{}),
		collect:  make(chan walkElem),
		session:  s,
		newfid:   msg.Newfid(),
		path:     newpath,
		tag:      msg.Tag(),
		ctx:      ctx,
	}
	go w.run()
	return w
}

// runs in its own goroutine
func (w *walker) run() {
	var err error
Loop:
	for {
		select {
		case <-w.ctx.Done():
			break Loop
		case el, ok := <-w.collect:
			if !ok {
				break Loop
			}
			if el.err != nil {
				err = el.err
			}
			w.count++
			w.qids[el.index] = el.qid
			for i := len(w.found); i < cap(w.found); i++ {
				if w.qids[i] != nil {
					w.found = w.found[:i+1]
				}
			}
			if w.count == len(w.qids) {
				break Loop
			}
		}
	}
	close(w.complete)
	if !w.session.conn.clearTag(w.tag) {
		return
	}
	if len(w.found) == 0 {
		if err != nil {
			w.session.conn.Rerror(w.tag, "%s", err)
		} else {
			w.session.conn.Rerror(w.tag, "No such file or directory")
		}
	} else {
		w.session.files.Put(w.newfid, file{name: w.path})
		w.session.conn.sessionFid.Put(w.newfid, w.session)
		w.session.IncRef()
		if err := w.session.conn.Rwalk(w.tag, w.found...); err != nil {
			panic(err) // should never happen
		}
	}
	w.session.conn.Flush()
}

// A client sends a Twalk message both to probe if a file exists, and to
// move a "cursor" within the filesystem hierarchy. In a traditional file
// system, a Twalk request is similar to using chdir to change the current
// directory.  File servers are free to attach additional meaning to Twalk
// requests. For instance, a server may create directories on-demand as
// clients walk to them.
//
// The 9P protocol allows for clients to walk multiple directories with
// a single 9P message. The styx package translates such requests into
// multiple Twalk values, providing the following guarantees:
//
// 	- Path() will return a cleaned, absolute path
// 	- Consecutive, related Twalk requests will differ by at
// 	  most 1 path element.
//
// The default response to a Twalk request is an Rerror message saying
// "No such file or directory".
type Twalk struct {
	index int
	walk  *walker
	reqInfo
}

func (t Twalk) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

func (t Twalk) handled() bool {
	return t.walk.filled[t.index] == 1
}

// Rwalk signals to the client that the file named by the Twalk's
// Path method exists and is of the given mode. The permission bits of
// mode are ignored, and only the file type bits, such as os.ModeDir,
// are sent to the client. If err is non-nil, an error response is sent to the
// client instead.
func (t Twalk) Rwalk(info os.FileInfo, err error) {
	var qid styxproto.Qid
	var mode os.FileMode
	if err == nil {
		mode = info.Mode()
		qid = t.session.conn.qid(t.Path(), styxfile.QidType(styxfile.Mode9P(mode)))
	}
	t.walk.filled[t.index] = 1
	elem := walkElem{qid: qid, index: t.index, err: err}
	select {
	case t.walk.collect <- elem:
	case <-t.walk.complete:
	}
}

// Rerror signals to the client that the file named by the Twalk's
// Path method does not exist.
func (t Twalk) Rerror(format string, args ...interface{}) {
	t.Rwalk(nil, fmt.Errorf(format, args...))
}

func (t Twalk) defaultResponse() {
	t.Rerror("No such file or directory")
}
