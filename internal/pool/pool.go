package pool

import (
	"sort"
	"sync"
	"sync/atomic"
)

// DefaultPoolMax is the default maximum for the
// zero value of a Pool.
const DefaultPoolMax = ^uint32(0)

// save some typing
var (
	add = atomic.AddUint32
	cas = atomic.CompareAndSwapUint32
)

type uint32slice []uint32

func (s uint32slice) Less(i, j int) bool { return s[i] < s[j] }
func (s uint32slice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s uint32slice) Len() int           { return len(s) }

// New creates a new Pool. Numbers returned
// by the Get method on the returned Pool will
// not exceed max - 1.
func New(max uint32) *Pool {
	return &Pool{max: max}
}

// A Pool maintains a pool of free identifiers.  It is safe for
// concurrent use. The zero value of a Pool is an empty pool that will
// provide identifiers in the range [0, DefaultPoolSize).
type Pool struct {
	next, max uint32

	mu      sync.Mutex // protects the clunked slice
	clunked []uint32   // items we've discarded
}

// Get retrieves a free identifier from a pool. If the pool is full,
// the second return value of Get will be false. Once an identifier
// is no longer needed, it must be released using the Free method.
func (p *Pool) Get() (id uint32, notfull bool) {
	// This makes the zero value of Pool usable as a fid pool
	cas(&p.max, 0, DefaultPoolMax)

	if cas(&p.next, p.max, p.max-1) {
		return 0, false
	}

	return add(&p.next, 1) - 1, true
}

// After Free returns, it is valid for subsequent calls to Get on the
// same pool to return old. Free may only be called once
// for any given identifier.
func (p *Pool) Free(old uint32) {
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
