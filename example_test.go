package styx_test

import (
	"io"
	"log"
	"os"
	"time"

	"aqwari.net/net/styx"
)

type emptyDir struct{}

func (emptyDir) Readdir(n int) ([]os.FileInfo, error) { return nil, io.EOF }
func (emptyDir) Mode() os.FileMode                    { return os.ModeDir | 0777 }
func (emptyDir) IsDir() bool                          { return true }
func (emptyDir) ModTime() time.Time                   { return time.Now() }
func (emptyDir) Name() string                         { return "" }
func (emptyDir) Size() int64                          { return 0 }
func (emptyDir) Sys() interface{}                     { return nil }

func Example() {
	// Run a file server that creates directories (and only directories)
	// on-demand, as a client walks to them.

	h := styx.HandlerFunc(func(s *styx.Session) {
		for s.Next() {
			switch t := s.Request().(type) {
			case styx.Tstat:
				t.Rstat(emptyDir{})
			case styx.Twalk:
				t.Rwalk(os.ModeDir)
			case styx.Topen:
				t.Ropen(emptyDir{}, emptyDir{}.Mode())
			}
		}
	})
	log.Fatal(styx.ListenAndServe(":564", h))
}
