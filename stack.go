package styx

// Stack combines multiple handlers into one. When a new message is received
// from the client, it is passed to each handler, in order. Handlers may
// use the Pass method of a Session to modify messages that will show up in
// subsequent handlers. A message will continue to be passed to the next
// handler in the chain until a response is sent. If no response is sent
// by any handlers in the chain, the documented default response for that
// message type will be sent.
func Stack(handlers ...Handler) Handler {
	h := make([]Handler, len(handlers))
	copy(h, handlers)
	return stack(h)
}

type stack []Handler

func (handlers stack) Serve9P(s *Session) {
	running := make([]*Session, 0, len(handlers))
	for _, h := range handlers {
		session := *s
		session.requests = make(chan Request)
		session.pipeline = make(chan Request)
		go func() {
			h.Serve9P(&session)
			close(session.pipeline)
		}()
		running = append(running, &session)
	}
	for s.Next() {
		req := s.Request()
		for _, h := range running {
			h.requests <- req
			if next, ok := <-h.pipeline; !ok {
				// A handler has exited prematurely. abort
				goto Cleanup
			} else if next == nil {
				// The request has been handled, no point
				// in passing it down the chain.
				break
			}
		}
	}

Cleanup:
	for _, h := range running {
		close(h.requests)

		// Wait for the handler to exit
		for range h.pipeline {
		}
	}
}
