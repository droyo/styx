package styx_test

import (
	"context"
	"fmt"
	"sync/atomic"

	"aqwari.net/net/styx"
)

func ExampleStack() {
	// Associate a session ID with each session
	var sessionID int64
	sessionid := styx.HandlerFunc(func(s *styx.Session) {
		id := atomic.AddInt64(&sessionID, 1)
		for s.Next() {
			req := s.Request()
			ctx := context.WithValue(req.Context(), "session", id)
			s.UpdateRequest(req.WithContext(ctx))
		}
	})

	// echo requests to stdout
	echo := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			req := s.Request()
			id := req.Context().Value("session")
			fmt.Printf("session %v user %q %q %T %s",
				id, s.User, s.Access, req, req.Path())
		}
	})

	// Disallow removal of any files
	blockops := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			if t, ok := s.Request().(styx.Tremove); ok {
				t.Rerror("permission denied")
			}
		}
	})

	handler := styx.Stack(sessionid, echo, blockops)
	styx.ListenAndServe(":564", handler)
}
