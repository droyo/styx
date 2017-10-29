package styx_test

import (
	"fmt"

	"aqwari.net/net/styx"
)

func ExampleMux() {
	h1 := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			req := s.Request()
			fmt.Printf("handler1 %q %T %s", req, req.Path())
		}
	})
	h2 := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			req := s.Request()
			fmt.Printf("handler2 %q %T %s", req, req.Path())
		}
	})

	mux := styx.NewServeMux()
	mux.Handle("/dir1", h1)
	mux.Handle("/dir2", h2)

	styx.ListenAndServe(":564", mux)
}
