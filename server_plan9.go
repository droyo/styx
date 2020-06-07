package styx

import (
	"fmt"
	"os"
)

// Post creates a service in /srv/ named service and starts a new conn.
func (srv *Server) Post(service string) error {
	in, out, err := os.Pipe()
	if err != nil {
		return err
	}
	f, err := os.OpenFile("/srv/"+service, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(fmt.Sprintf("%d", in.Fd())))
	if err != nil {
		in.Close()
		out.Close()
		f.Close()
		return err
	}
	newConn(srv, out).serve()
	return nil
}
