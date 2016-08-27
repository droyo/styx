package styx

import (
	"os"
	"path"
	"strings"

	"golang.org/x/net/context"

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
}

type walker struct {
	qids, found []styxproto.Qid
	filled      []bool
	count       int
	complete    chan struct{}
	collect     chan walkElem
	newfid      uint32
	path        string

	// for cancellation
	cx context.Context

	session *Session
	tag     uint16
}

func newWalker(s *Session, cx context.Context, msg styxproto.Twalk, base string, elem ...string) *walker {
	qids := make([]styxproto.Qid, len(elem))
	found := qids[:0]
	newpath := path.Join(base, strings.Join(elem, "/"))
	w := &walker{
		qids:     qids,
		found:    found,
		filled:   make([]bool, len(elem)),
		complete: make(chan struct{}),
		collect:  make(chan walkElem),
		session:  s,
		newfid:   msg.Newfid(),
		path:     newpath,
		tag:      msg.Tag(),
		cx:       cx,
	}
	go w.run()
	return w
}

// runs in its own goroutine
func (w *walker) run() {
Loop:
	for {
		select {
		case <-w.cx.Done():
			break Loop
		case el, ok := <-w.collect:
			if !ok {
				break Loop
			}
			if w.filled[el.index] {
				continue
			}
			w.count++
			w.filled[el.index] = true
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
	w.session.conn.clearTag(w.tag)
	if len(w.found) == 0 {
		w.session.conn.Rerror(w.tag, "No such file or directory")
	} else {
		w.session.files.Put(w.newfid, file{name: w.path})
		w.session.conn.sessionFid.Put(w.newfid, w.session)
		w.session.IncRef()
		if err := w.session.conn.Rwalk(w.tag, w.found...); err != nil {
			panic(err) // should never happen
		}
	}
}

// A Twalk message is sent when a client wants to check that a given
// file exists. A server should call Rwalk if the file exists, or Rerror
// otherwise.
type Twalk struct {
	index int
	walk  *walker
	reqInfo
}

// Rwalk signals to the client that the file named by the Twalk's
// Path method exists and is of the given mode. The permission bits of
// mode are ignored, and only the file type bits, such as os.ModeDir,
// are sent to the client.
func (t Twalk) Rwalk(mode os.FileMode) {
	qid := t.session.conn.qid(t.Path(), qidType(mode))
	select {
	case t.walk.collect <- walkElem{qid: qid, index: t.index}:
	case <-t.walk.complete:
	}
}

// Rerror signals to the client that the file named by the Twalk's
// Path method does not exist.
func (t Twalk) Rerror(format string, args ...interface{}) {
	select {
	case t.walk.collect <- walkElem{index: t.index}:
	case <-t.walk.complete:
	}
}

func (t Twalk) defaultResponse() {
	t.Rerror("no such file or directory")
}
