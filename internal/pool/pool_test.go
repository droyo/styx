package pool

import "testing"

func TestPoolFull(t *testing.T) {
	p := New(1)
	p.Get()

	_, ok := p.Get()
	if ok {
		t.Errorf("Get from full pool did not fail")
	}
}
