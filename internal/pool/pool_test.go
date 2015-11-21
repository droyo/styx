package pool

import "testing"

func TestPoolFree(t *testing.T) {
	var pool FidPool

	for i := 0; i < 100; i++ {
		if n, ok := pool.Get(); !ok {
			t.Error("pool marked full prematurely")
			break
		} else if uint32(i) != n {
			t.Fatal("expected pool.Get to return ids in ascending order")
		}
	}

	for i := 0; i < 100; i++ {
		pool.Free(uint32(i))
	}

	if n, ok := pool.Get(); !ok {
		t.Error("pool full after freeing all ids")
	} else if n != 0 {
		t.Errorf("pool returned non-zero %d on empty pool %#v", n, &pool)
	}
}

func TestPool(t *testing.T) {
	var pool FidPool

	// We're abusing defer a little bit here; this runs
	// after all ids have been freed, so we should expect
	// to get 0 here.
	defer func() {
		if n, ok := pool.Get(); !ok {
			t.Error("pool full after freeing all ids")
		} else if n != 0 {
			t.Errorf("pool returned non-zero %d on empty pool %#v", n, &pool)
		}
	}()

	for i := 0; i < 100; i++ {
		if n, ok := pool.Get(); !ok {
			t.Error("pool marked full prematurely")
			break
		} else {
			t.Logf("acquired %d", n)

			// This frees the ids in LIFO order, the optimal
			// pattern for our implementation
			defer func() {
				pool.Free(n)
				t.Logf("released %d", n)
			}()
		}
	}
}
