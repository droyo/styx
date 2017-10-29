package styx

import (
	"io"
	"os"
	"sync"

	"aqwari.net/net/styx/internal/filetree"
)

// A ServeMux combines multiple Handlers into one and
// routes requests to the appropriate Handler through pattern
// matching. Any updates to a ServeMux are only reflected in
// subsequent 9P sessions. A ServeMux must be created
// by a call to NewServeMux.
type ServeMux struct {
	mu   sync.RWMutex
	tree map[string]Handler
}

type muxEntry struct {
	filetree.Entry
	n int
}

func (e *muxEntry) Readdir(n int) ([]os.FileInfo, error) {
	children := e.Children[e.n:]
	if n < 0 || n > len(children) {
		n = len(children)
	}
	if n == 0 {
		return nil, io.EOF
	}
	fi := make([]os.FileInfo, 0, n)
	for i := range children[:n] {
		fi = append(fi, &children[i])
	}
	e.n = n
	return fi, nil
}

// NewServeMux creates an empty ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{tree: make(map[string]Handler)}
}

// Handle registers a Handler with a path and all of its children.  All
// requests to files at or below prefix in the file hierarchy will be
// routed to handler. When a request is routed to a registered handler,
// the prefix of the handler is stripped from the request path.
func (mux *ServeMux) Handle(prefix string, handler Handler) {
	mux.mu.Lock()
	mux.tree[prefix] = handler
	mux.mu.Unlock()
}

func (mux *ServeMux) gentree(s *Session) *filetree.Tree {
	tree := filetree.New()

	mux.mu.RLock()
	defer mux.mu.RUnlock()

	for pat, handler := range mux.tree {
		sub := runSubSession(s, StripPrefix(pat, handler))
		tree.Put(pat, os.ModeDir|0777, sub)
	}
	return tree
}

// Serve9P serves a new 9P session, routing requests for
// files to matching Handlers.
func (mux *ServeMux) Serve9P(s *Session) {
	tree := mux.gentree(s)

	for s.Next() {
		r := s.Request()
		match, ok := tree.LongestPrefix(r.Path())
		if !ok {
			continue
		}
		switch {
		case match.Value == nil || match.FullName == r.Path():
			// This is an intermediate directory in /path/to/handler,
			// we'll serve it as a read-only directory for the user.
			switch r := r.(type) {
			case Topen:
				r.Ropen(&muxEntry{Entry: match}, nil)
			case Tstat:
				r.Rstat(&match, nil)
			case Twalk:
				fmt.Printf("%s %v %o\n", r.Path(), match.IsDir(), match.Mode())
				r.Rwalk(&match, nil)
			}
		case len(r.Path()) >= len(match.FullName):
			// The request is for a file under the purview of a
			// registered Handler. Pass it along.
			session := match.Value.(*Session)
			r.setSession(session)
			session.requests <- r
			if _, ok := <-session.pipeline; !ok {
				// Premature handler exit
				goto Cleanup
			}
		}
	}

Cleanup:
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	for path := range mux.tree {
		entry, _ := tree.Get(path)
		session := entry.Value.(*Session)
		close(session.requests)

		// Wait for handler to exit
		for range session.pipeline {
		}
	}
}
