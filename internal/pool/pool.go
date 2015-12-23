// Package pool manages pools of integer identifiers.
//
// The pool package provides a thread-safe allocator for
// unique 32-bit integers. It is used to manage fid and tag
// pools for 9P clients.
package pool

import (
	"sort"
	"sync"
	"sync/atomic"
)

const (
	FidPoolCeiling = 1<<32 - 1
	TagPoolCeiling = 1<<16 - 1
)

// save some typing
var (
	add  = atomic.AddUint32
	load = atomic.LoadUint32
	cas  = atomic.CompareAndSwapUint32
)

type uint32slice []uint32

func (s uint32slice) Less(i, j int) bool { return s[i] < s[j] }
func (s uint32slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s uint32slice) Len() int           { return len(s) }

// BUG(droyo): The pool implementation allocates numbers in a contiguous
// sequence from [0, max). When a number X is Free'd, but is not at
// the end of the sequence, the FidPool implementation cannot use it until
// all allocated numbers greater than X have also been freed. While
// this can result in FidPools becoming full prematurely for certain
// pathological workloads, this tradeoff allows a FidPool to be simple,
// and small, and allows the Get implementation to be lock-free.

// A FidPool maintains a pool of free identifiers.  It is safe for
// concurrent use. The zero value of a FidPool is an empty pool that will
// provide identifiers in the range [0, DefaultFidPoolSize).
type FidPool struct {
	pool
}

type pool struct {
	next uint32

	mu      sync.Mutex // protects the clunked slice
	clunked []uint32   // items we've discarded
}

// A TagPool is suitable for allocating tags for
// 9P messages.
type TagPool struct {
	pool
}

// Get retrieves a free identifier from a TagPool. If the pool is full,
// the second return value of Get will be false. Once an identifier
// is no longer needed, it must be released using the Free method.
// The return value is guaranteed to be less than TagPoolCeiling.
func (p *TagPool) Get() (tag uint16, ok bool) {
	t, notfull := p.get(TagPoolCeiling)
	return uint16(t), notfull
}

// Get retrieves a free identifier from a FidPool. If the pool is full,
// the second return value of Get will be false. Once an identifier
// is no longer needed, it must be released using the Free method.
// The return value is guaranteed to be less than FidPoolCeiling.
func (p *FidPool) Get() (fid uint32, ok bool) {
	return p.get(FidPoolCeiling)
}

func (p *pool) get(ceil uint32) (id uint32, ok bool) {
	if load(&p.next) == ceil {
		return 0, false
	}
	return add(&p.next, 1) - 1, true
}

// Free releases a tag. After Free returns, it is valid for subsequent
// calls to Get on the same pool to return old. Free may only be called
// once for any given tag.
func (p *TagPool) Free(old uint16) {
	p.free(uint32(old))
}

// Free releases a fid. After Free returns, it is valid for subsequent
// calls to Get on the same pool to return old. Free may only be called
// once for any given fid.
func (p *FidPool) Free(old uint32) {
	p.free(old)
}

func (p *pool) free(old uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// best case; old was returned by the latest call to Get
	if !cas(&p.next, old+1, old) {
		p.clunked = append(p.clunked, old)
		sort.Sort(uint32slice(p.clunked))
	}

	for i := len(p.clunked); i > 0; i-- {
		if cas(&p.next, p.clunked[i-1]+1, p.clunked[i-1]) {
			p.clunked = p.clunked[:len(p.clunked)-1]
		} else {
			break
		}
	}
}
