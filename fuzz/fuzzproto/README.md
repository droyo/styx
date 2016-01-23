This directory contains fuzz tests for the 'styxproto' package,
along with test inputs.

To start fuzz testing, run

	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build

	go-fuzz-build aqwari.net/net/styx/fuzz/fuzzproto
	go-fuzz -bin=./fuzzproto-fuzz.zip -workdir=.

