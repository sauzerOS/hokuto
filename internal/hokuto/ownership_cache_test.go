package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// The ownership map is updated per package, not rebuilt: adding, changing,
// invalidating and removing packages must leave exactly the owners a full
// rebuild would give.
func TestFileOwnershipCacheIncremental(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "var", "db", "hokuto", "installed")
	write := func(pkg string, paths ...string) {
		t.Helper()
		dir := filepath.Join(installed, pkg)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, p := range paths {
			lines = append(lines, p+"  0000")
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A later mtime, as a reinstall would leave.
		later := time.Now().Add(time.Duration(len(paths)) * time.Second)
		os.Chtimes(filepath.Join(dir, "manifest"), later, later)
	}
	owners := func(c *fileOwnershipCache, path string) []string {
		got := append([]string(nil), c.snapshotFor(root, installed).owners[path]...)
		sort.Strings(got)
		return got
	}
	var c fileOwnershipCache

	write("a", "/usr/bin/a", "/usr/share/common")
	write("b", "/usr/bin/b", "/usr/share/common")
	if got := owners(&c, "/usr/share/common"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("shared path owners = %v", got)
	}

	// a drops the shared file and gains another.
	write("a", "/usr/bin/a", "/usr/bin/a2", "/usr/lib/new")
	if got := owners(&c, "/usr/share/common"); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("after a changed: %v", got)
	}
	if got := owners(&c, "/usr/lib/new"); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("new path of a: %v", got)
	}

	// Invalidation forgets the package until its manifest is read again.
	c.invalidatePackage("b")
	if got := owners(&c, "/usr/share/common"); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("b re-read after invalidation: %v", got)
	}

	// Uninstalled: its paths lose their owner.
	if err := os.RemoveAll(filepath.Join(installed, "b")); err != nil {
		t.Fatal(err)
	}
	snap := c.snapshotFor(root, installed)
	if _, ok := snap.owners["/usr/share/common"]; ok {
		t.Fatalf("path of a removed package still owned: %v", snap.owners["/usr/share/common"])
	}
	if got := owners(&c, "/usr/bin/a"); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("a's own path: %v", got)
	}
}
