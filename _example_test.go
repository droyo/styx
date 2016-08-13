package styx_test

import (
	"log"
	"path"
	"strconv"
	"strings"

	"aqwari.net/net/styx"
)

func ExampleSession() {
	var n int
	styx.HandleFunc("/", func(s *styx.Session) {
		isdir := make(map[string]bool)
		for t := range s.Requests {
			n++
			switch t := t.(type) {
			case styx.Topen:
				parent, file := path.Split(t.Path)
				isdir[parent] = true
				if isdir[t.Path] {
					t.Ropen(nil)
				} else {
					r := strings.NewReader(strconv.Itoa(n) + " hello, " + s.User + "!\n")
					t.Ropen(nil)
				}
			case styx.Tstat:
				if isdir[parent] {
					t.Directory()
				} else {
					t.RegularFile()
				}
			case styx.Twalk:
				for parent, _ := path.Split(t.Path); parent != ""; parent, _ = path.Split(parent) {
					isdir[parent] = true
				}
			}
		}
	})
	log.Fatal(styx.ListenAndServe(":9pfs", nil))
}
