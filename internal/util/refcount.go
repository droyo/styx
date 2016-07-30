package util

import (
	"errors"
	"sync/atomic"
)

// A Refcount can be embedded in structures to provide
// reference-counting of resources.
type RefCount struct {
	n uint64
}

var errOverflow = errors.New("reference count overflow")

// IncRef increments refcount by 1. It is a run-time
// panic to create more than ^uint64(0) references.
func (r *RefCount) IncRef() {
	if atomic.AddUint64(&r.n, 1) == 0 {
		panic(errOverflow)
	}
}

// DecRef decrements refcount by 1. If the reference count
// has reached 0, DecRef will return false.
func (r *RefCount) DecRef() (remaining bool) {
	return atomic.AddUint64(&r.n, ^uint64(0)) != 0
}
