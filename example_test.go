package styx_test

import (
	"log"
	"path"

	"aqwari.net/net/styx"
)

func ExampleSession() {
	var n int
	h := styx.HandlerFunc(func(s *styx.Session) {
		isdir := make(map[string]bool)
		for s.Next() {
			n++
			switch t := s.Request().(type) {
			case styx.Topen:
				parent, _ := path.Split(t.Path())
				isdir[parent] = true
				if isdir[t.Path()] {
					t.Ropen(nil, 0666)
				} else {
					t.Ropen(nil, 0666)
				}
			case styx.Tstat:
			case styx.Twalk:
				for parent, _ := path.Split(t.Path()); parent != ""; parent, _ = path.Split(parent) {
					isdir[parent] = true
				}
			}
		}
	})
	log.Fatal(styx.ListenAndServe(":564", h))
}
