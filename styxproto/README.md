The `styxproto` package is parses and produces 9P2000
protocol messages. See the package documentation for
more details.

# Fuzz testing the styxproto package

This directory contains fuzz tests for the 'styxproto' package,
along with test inputs.

To start fuzz testing, run

	go get github.com/dvyukov/go-fuzz/go-fuzz
	go get github.com/dvyukov/go-fuzz/go-fuzz-build

	go-fuzz-build aqwari.net/net/styx/styxproto
	go-fuzz -bin=./styxproto-fuzz.zip

