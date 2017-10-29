package filetree

import "testing"

func TestBasic(t *testing.T) {
	fs := New()
	fs.Put("/usr/bin", nil)
	fs.Put("/usr/lib64", nil)

	dir, _ := fs.Get("/usr/../usr/./././/")
	for _, entry := range dir.Children {
		t.Log(entry.Name)
	}
	for path, entry := range fs.index {
		t.Logf("%s: %s", path, entry.Name())
	}
}

func TestSameValue(t *testing.T) {
	fs := New()
	fs.Put("/usr/bin/emacs", "vi")

	entry, ok := fs.Get("/usr/bin")
	if !ok {
		t.Error("/usr/bin not found")
	}
	direct, ok := fs.Get("/usr/bin/emacs")
	if !ok {
		t.Error("/usr/bin/emacs not found")
	}
	if direct.Value != "vi" {
		t.Errorf("unexpected content %v", direct.Value)
	}
	if len(entry.Children) != 1 {
		t.Errorf("/usr/bin has %d children, expected 1",
			len(entry.Children))
	} else if child := entry.Children[0]; direct.Value != child.Value {
		t.Errorf("%v != %v", direct.Value, child.Value)
	}
}

func TestMatch(t *testing.T) {
	const (
		ancestor   = "/usr"
		descendant = "/usr/local/bin/httpd"
	)
	fs := New()
	fs.Put(ancestor, "foo")

	entry, ok := fs.LongestPrefix(descendant)
	if !ok {
		t.Fatalf("LongestPrefix did not find ancestor %s of %s",
			ancestor, descendant)
	}
	t.Logf("Matched ancestor %v for %v", entry.Name, descendant)
	if entry.FullName != ancestor {
		t.Errorf("got %v, wanted %v",
			entry.Name, ancestor)
	}

	if entry.Value != "foo" {
		t.Errorf("ancestor entry did not contain expected Value: "+
			"got %v, wanted \"foo\"", entry.Value)
	}
}
