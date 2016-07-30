package util

import (
	"reflect"
	"sync"
)

// A Map is a map that is safe for concurrent access and
// updates. A Map must be created with NewMap.
type Map struct {
	once   sync.Once
	mu     sync.RWMutex
	values map[interface{}]interface{}
}

func NewMap() *Map {
	return &Map{
		values: make(map[interface{}]interface{}),
	}
}

// Get retrieves a value from the Map. If the value is not
// present, ok will be false.
func (m *Map) Get(key interface{}) (val interface{}, ok bool) {
	m.mu.RLock()
	val, ok = m.values[key]
	m.mu.RUnlock()
	return val, ok
}

// Put stores a value in the map, overwriting any previous values
// stored under the key.
func (m *Map) Put(key, val interface{}) {
	m.mu.Lock()
	m.values[key] = val
	m.mu.Unlock()
}

// Add stores a value in the map under key. If there is already
// a value in the map for key, Add does not replace it, and
// returns false.
func (m *Map) Add(key, val interface{}) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.values[key]; ok {
		return false
	}
	m.values[key] = val
	return true
}

// Del deletes a value from a map. Subsequent Gets on the map
// will turn up empty.
func (m *Map) Del(key interface{}) {
	m.mu.Lock()
	delete(m.values, key)
	m.mu.Unlock()
}

// Fetch stores the value corresponding with key in the Map into v. v
// must be a pointer to the value's type, or a run-time panic will
// occur. If the key is not present in the Map, v is untouched and
// Fetch returns false.
func (m *Map) Fetch(key, v interface{}) bool {
	val, ok := m.Get(key)
	if ok {
		reflect.ValueOf(v).Elem().Set(reflect.ValueOf(val))
		return true
	}
	return false
}

// Do calls f while holding the write lock for a Map.
func (m *Map) Do(f func(map[interface{}]interface{})) {
	m.mu.Lock()
	f(m.values)
	m.mu.Unlock()
}
