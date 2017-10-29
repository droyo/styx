// Package qidpool manages pools of 9P Qids, 13-bit unique identifiers
// for files.
package qidpool

import (
	"sync"
	"sync/atomic"

	"aqwari.net/net/styx/styxproto"
)

// A Pool maintains a pool of unique 13-bit identifiers
// for files on a 9P file server. A Pool must be created
// with a call to New.
type Pool struct {
	m    sync.Map
	path uint64
}

// New returns a new, empty Pool.
func New() *Pool {
	return &Pool{}
}

// LoadOrStore creates a new, unique Qid of the given type and adds it to
// the pool. The returned Qid should be considered read-only. Put will not
// modify an existing Qid; if there is already a Qid associated with name,
// it is returned instead.
func (p *Pool) LoadOrStore(name string, qtype uint8) styxproto.Qid {
	println("qidpool.LoadOrStore", name, qtype)
	if v, ok := p.m.Load(name); ok {
		return v.(styxproto.Qid)
	}
	buf := make([]byte, styxproto.QidLen)
	path := atomic.AddUint64(&p.path, 1)

	qid, _, err := styxproto.NewQid(buf, qtype, 0, path)
	if err != nil {
		panic(err)
	}

	return p.LoadOrStoreQid(name, qid)
}

func (p *Pool) LoadOrStoreQid(name string, qid styxproto.Qid) styxproto.Qid {
	actual, _ := p.m.LoadOrStore(name, qid)
	return actual.(styxproto.Qid)
}

// Del removes a Qid from a Pool. Once a Qid is removed from a pool, it
// will never be used again.
func (p *Pool) Del(name string) {
	p.m.Delete(name)
}

// Load fetches the Qid currently associated with name from the pool. The
// Qid is only valid if the second return value is true.
func (p *Pool) Load(name string) (styxproto.Qid, bool) {
	if v, ok := p.m.Load(name); ok {
		return v.(styxproto.Qid), true
	}
	return nil, false
}
