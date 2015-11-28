package styxproto_test

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"aqwari.net/net/styx/styxproto"
)

func ExampleNewStat() {
	buf := make([]byte, 100)
	s, buf, err := styxproto.NewStat(buf, "messages.log", "root", "wheel", "")
	if err != nil {
		log.Fatal(err)
	}
	s.SetLength(309)
	s.SetMode(0640)
	fmt.Println(s)

	// Output: size=70 type=0 dev=0 qid="type=0 ver=0 path=0" mode=640 atime=0 mtime=0 length=309 name="messages.log" uid="root" gid="wheel" muid=""
}

func ExampleNewQid() {
	buf := make([]byte, 13)
	qid, buf, err := styxproto.NewQid(buf, 1, 369, 0x84961)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(qid)

	// Output: type=1 ver=369 path=84961
}

func ExampleDecoder() {
	l, err := net.Listen("tcp", ":564")
	if err != nil {
		log.Fatal(err)
	}
	rwc, err := l.Accept()
	if err != nil {
		log.Fatal(err)
	}

	d := styxproto.NewDecoder(rwc)
	for d.Next() {
		for _, msg := range d.Messages() {
			switch msg := msg.(type) {
			case styxproto.Tversion:
				log.Printf("Client wants version %s", msg.Version())
				styxproto.WriteRversion(rwc, 8192, "9P2000")
			case styxproto.Tread:
				styxproto.WriteRread(rwc, msg.Tag(), 10,
					strings.NewReader("data data data data"))
			case styxproto.Twrite:
				log.Printf("Receiving %d bytes from client", msg.Count())
				io.Copy(ioutil.Discard, msg)
			}
		}
	}
}
