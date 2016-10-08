package styx

import (
	"fmt"
	"math"
	"os"
	"sync/atomic"
	"time"

	"context"

	"aqwari.net/net/styx/internal/styxfile"
	"aqwari.net/net/styx/styxproto"
)

// In the plan 9 manual, stat(5) has this to say about modifying
// fields via Twstat:
//
// 	A wstat request can avoid modifying some properties of the
// 	file by providing explicit ``don't touch'' values in the
// 	stat data that is sent: zero-length strings for text values
// 	and the maximum unsigned value of appropriate size for inte-
// 	gral values.
//
// This keeps the protocol simpler by allowing a single message
// to modify multiple file attributes. However, it shifts the burden to
// the server to determine what fields are being modified and what
// fields should be untouched. The styx package will attempt to hide
// this complexity from the user, in a similar way to how it hides the
// complexity of the walk transaction; by generating multiple fake
// requests for each attribute to be changed, and assembling the
// responses. If any one of the responses are succesful, an Rwstat
// is returned.
//
// Note that for certain synthetic messages, there will be some overlap
// with certain 9P2000.u or 9P2000.L extensions (such as Trename).
// This is OK, we'll make the type generic enough for both.
type twstat struct {
	status chan error
	filled []int32
	index  int
	reqInfo
}

// Call Rerror to provide a descriptive error message explaining
// why a file attribute could not be updated.
func (t twstat) Rerror(format string, args ...interface{}) {
	t.respond(fmt.Errorf(format, args...))
}

func (t twstat) respond(err error) {
	p := &t.filled[t.index]
	if atomic.CompareAndSwapInt32(p, 0, 1) {
		t.status <- err
	}
}

func (t twstat) handled() bool {
	return atomic.LoadInt32(&t.filled[t.index]) == 1
}

func (s *Session) handleTwstat(ctx context.Context, msg styxproto.Twstat, file file) bool {
	// mode, atime+mtime, length, name, uid+gid, sync
	// we will ignore muid
	const numMutable = 6

	// By convention, sending a Twstat message with a stat structure consisting
	// entirely of "don't touch" values indicates that the client wants the server
	// to sync the file to disk.
	var haveChanges bool
	var messages int

	stat := msg.Stat()

	// We buffer the channel so that the response
	// methods for each attribute do not block.
	status := make(chan error, numMutable)
	info := newReqInfo(ctx, s, msg, file.name)
	filled := make([]int32, numMutable)

	atime, mtime := stat.Atime(), stat.Mtime()
	if atime != math.MaxUint32 || mtime != math.MaxUint32 {
		haveChanges = true
		s.requests <- Tutimes{
			Atime:  time.Unix(int64(atime), 0),
			Mtime:  time.Unix(int64(mtime), 0),
			twstat: twstat{status, filled, messages, info},
		}
		messages++
	}
	if uid, gid := string(stat.Uid()), string(stat.Gid()); uid != "" || gid != "" {
		haveChanges = true
		s.requests <- Tchown{
			User:   uid,
			Group:  gid,
			twstat: twstat{status, filled, messages, info},
		}
		messages++
	}
	if name := string(stat.Name()); name != "" && name != file.name {
		haveChanges = true
		s.requests <- Trename{
			OldPath: file.name,
			NewPath: name,
			twstat:  twstat{status, filled, messages, info},
		}
		messages++
	}
	if length := stat.Length(); length != -1 {
		haveChanges = true
		s.requests <- Ttruncate{
			Size:   length,
			twstat: twstat{status, filled, messages, info},
		}
		messages++
	}
	if stat.Mode() != math.MaxUint32 {
		haveChanges = true
		s.requests <- Tchmod{
			Mode:   styxfile.ModeOS(stat.Mode()),
			twstat: twstat{status, filled, messages, info},
		}
		messages++
	}
	if len(stat.Muid()) != 0 {
		// even though we won't respond to this field, we don't
		// want to needlessly stimulate a sync request
		haveChanges = true
	}
	if !haveChanges {
		s.requests <- Tsync{
			twstat: twstat{status, filled, messages, info},
		}
		messages++
	}

	go func() {
		var (
			success bool
			err     error
		)
		for i := 0; i < messages; i++ {
			if e, ok := <-status; !ok {
				panic("closed Twstat channel prematurely")
			} else if e != nil {
				err = e
			} else {
				success = true
			}
		}
		if !s.conn.clearTag(msg.Tag()) {
			return
		}
		if success {
			s.conn.Rwstat(msg.Tag())
		} else {
			s.conn.Rerror(msg.Tag(), "%s", err)
		}
		s.conn.Flush()
	}()

	return true
}

// A Trename message is sent by the client to change the name of
// an existing file. Use the Rrename method to indicate success.
//
// The default response for a Trename request is an Rerror message
// saying "permission denied"
type Trename struct {
	OldPath, NewPath string
	twstat
}

func (t Trename) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// The Path method of a Trename request returns the current path
// to the file, before a rename has taken place.
func (t Trename) Path() string {
	return t.OldPath
}

// Rrename indicates to the server that the rename was succesful.  Once
// Rrename is called with a nil error, future stat requests should
// reflect the updated name.
func (t Trename) Rrename(err error) {
	// BUG(droyo) renaming a file with one fid will break Twalk
	// requests that attempt to clone another fid pointing to the
	// same file.
	if err == nil {
		t.session.qidpool.Do(func(m map[interface{}]interface{}) {
			if qid, ok := m[t.OldPath]; ok {
				m[t.NewPath] = qid
			}
		})
	}
	t.respond(err)
}

// A Tchmod message is sent by the client to change the permissions
// of an existing file. The client must have write access to the file's
// containing directory. Use the Rchmod method to indicate success.
//
// The default response for a Tchmod request is an Rerror saying
// "permission denied"
type Tchmod struct {
	Mode os.FileMode
	twstat
}

func (t Tchmod) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rchmod, when called with a nil error, indicates that the permissions
// of the file were updated. Future stat requests should reflect the new
// file mode.
func (t Tchmod) Rchmod(err error) { t.respond(err) }

// A Tutimes message is sent by the client to change the modification
// time of a file. Use the Rutime method to indicate success.
//
// The default response to a Tutimes message is an Rerror message
// saying "permission denied"
type Tutimes struct {
	Atime, Mtime time.Time
	twstat
}

func (t Tutimes) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rutimes, when called with a nil error, indicates that the file
// times were succesfully updated. Future stat requests should reflect
// the new access and modification times.
func (t Tutimes) Rutimes(err error) { t.respond(err) }

// A Tchown message is sent by the client to change the user and group
// associated with a file. Use the Rchown method to indicate success.
//
// The default response to a Tchown message is an Rerror message
// saying "permission denied".
type Tchown struct {
	User, Group string

	// These will only be set if using the 9P2000.u or 9P2000.L
	// extensions, and will be -1 otherwise.
	Uid, Gid int
	twstat
}

func (t Tchown) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rchown, when called with a nil error, indicates that file and group
// ownership attributes were updated for the given file. Future stat
// requests for the same file should reflect the changes.
func (t Tchown) Rchown(err error) { t.respond(err) }

// A Ttruncate requests for the size of a file to be changed. Use the Rtruncate
// method to indicate success.
//
// The default response to a Ttruncate message is an Rerror message
// saying "permission denied".
type Ttruncate struct {
	Size int64
	twstat
}

func (t Ttruncate) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rtruncate, when called with a nil error, indicates that the file has been
// updated to reflect Size. Future reads, writes and stats should reflect
// the new file length.
func (t Ttruncate) Rtruncate(err error) { t.respond(err) }

// A Tsync request is made by the client to indicate that the client would
// like any changes made to the file to be flushed to durable storage. Use
// the Rsync method to indicate success.
//
// The default response to a Tsync message is an Rerror message saying
// "not supported".
type Tsync struct {
	twstat
}

func (t Tsync) WithContext(ctx context.Context) Request {
	t.ctx = ctx
	return t
}

// Rsync, when called with a nil error, indicates that the file has
// been flushed to durable storage. Note that different servers will
// have different definitions of what "durable" means, and provide
// different consistency guarantees.
func (t Tsync) Rsync(err error) { t.respond(err) }

func (t Tsync) defaultResponse() { t.Rerror("not supported") }
