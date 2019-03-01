package util_test

import "aqwari.net/net/styx/internal/util"

type Session struct {
	util.RefCount
	User, Tree string
	Requests   chan []byte
}

func (s *Session) end() {
	select {
	case <-s.Requests:
		return
	}
}

func ExampleRefCount() {
	s := &Session{Requests: make(chan []byte)}
	for i := 0; i < 10; i++ {
		s.IncRef()
	}

	for i := 0; i < 20; i++ {
		if !s.DecRef() {
			s.end()
			break
		}
	}
}
