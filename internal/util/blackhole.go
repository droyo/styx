package util

import "io"

// A BlackHole is an io.ReadWriteCloser that accepts an infinite
// amount of input and produces no output.
type BlackHole struct{}

func (BlackHole) Read(p []byte) (int, error)  { return 0, io.EOF }
func (BlackHole) Write(p []byte) (int, error) { return len(p), nil }
func (BlackHole) Close() error                { return nil }
