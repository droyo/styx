package styx

// Stack combines multiple handlers into one. When a new message is received
// from the client, it is passed to each handler, from left to right, until a
// response is sent. If no response is sent.  by any handlers in the stack,
// the documented default response for that message type will be sent to
// the client. Handlers may use the UpdateRequest to pass information to
// downstream handlers.
func Stack(handlers ...Handler) Handler {
	h := make([]Handler, len(handlers))
	copy(h, handlers)
	return stack(h)
}

type stack []Handler

func (handlers stack) Serve9P(s *Session) {
	running := make([]Session, len(handlers))
	for i, handler := range handlers {
		sub := &running[i]
		sub.User = s.User
		sub.Access = s.Access
		sub.requests = make(chan Request)
		sub.pipeline = make(chan Request)
		sub.authC = s.authC
		sub.conn = s.conn
		sub.RefCount = s.RefCount
		sub.files = s.files
		go func(h Handler) {
			h.Serve9P(sub)
			close(sub.pipeline)
		}(handler)
	}
	for s.Next() {
		req := s.Request()
		for i := range running {
			session := &running[i]
			req.setSession(session)
			session.requests <- req
			if next, ok := <-session.pipeline; !ok {
				// A handler has exited prematurely. abort
				goto Cleanup
			} else if next == nil {
				// The request has been handled, no point
				// in passing it down the chain.
				s.unhandled = false
				break
			} else {
				req = next
			}
		}
		req.setSession(s)
	}

Cleanup:
	for i := range running {
		close(running[i].requests)

		// Wait for the handler to exit
		for range running[i].pipeline {
		}
	}
}
