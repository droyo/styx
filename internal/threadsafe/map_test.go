package threadsafe

import "testing"

func TestMap(t *testing.T) {
	var (
		s string
		i int
	)

	m := NewMap()
	m.Put("foo", 82)
	m.Put("bar", "bundle")

	if !m.Fetch("foo", &i) {
		t.Error("m.Fetch(\"foo\") returned false")
	} else if i != 82 {
		t.Error("m.Fetch did not store int value")
	}

	if !m.Fetch("bar", &s) {
		t.Error("m.Fetch(\"bar\") returned false")
	} else if s != "bundle" {
		t.Error("m.Fetch did not store string value")
	}

	if m.Fetch("baz", &s) {
		t.Error("m.Fetch returned true for non-existant key")
	} else if s != "bundle" {
		t.Error("m.Fetch updated return value for nil entry")
	}

	var x int
	ok := m.Update("foo", &x, func() {
		x++
	})
	if !ok {
		t.Error("m.Update did not find \"foo\" in map")
	}
	if !m.Fetch("foo", &x) {
		t.Error("m.Fetch did not find \"foo\" in map")
	} else if x != 83 {
		t.Error("m.Update did not update value for \"foo\" (%v)", x)
	}
}
