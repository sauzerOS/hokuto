package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestStaleIconThemeCaches(t *testing.T) {
	icons := t.TempDir()
	old := time.Now().Add(-time.Hour)
	theme := func(name string, index bool) string {
		dir := filepath.Join(icons, name)
		if err := os.MkdirAll(filepath.Join(dir, "16x16", "apps"), 0o755); err != nil {
			t.Fatal(err)
		}
		if index {
			if err := os.WriteFile(filepath.Join(dir, "index.theme"), []byte("[Icon Theme]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	writeCache := func(dir string, mtime time.Time) {
		cache := filepath.Join(dir, "icon-theme.cache")
		if err := os.WriteFile(cache, []byte("cache"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(cache, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	setDirTimes := func(dir string, mtime time.Time) {
		for _, d := range []string{filepath.Join(dir, "16x16", "apps"), filepath.Join(dir, "16x16"), dir} {
			if err := os.Chtimes(d, mtime, mtime); err != nil {
				t.Fatal(err)
			}
		}
	}

	noCache := theme("NoCache", true)

	current := theme("Current", true)
	writeCache(current, old)
	setDirTimes(current, old.Add(-time.Minute))

	outdated := theme("Outdated", true)
	writeCache(outdated, old)
	setDirTimes(outdated, old.Add(-time.Minute))
	newer := old.Add(time.Minute)
	if err := os.Chtimes(filepath.Join(outdated, "16x16", "apps"), newer, newer); err != nil {
		t.Fatal(err)
	}

	// An uninstalled theme leaves its unowned cache behind.
	leftover := filepath.Join(icons, "Removed")
	if err := os.MkdirAll(leftover, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCache(leftover, old)

	// Without an index but with other files, the directory is not ours to clean.
	cursors := theme("Cursors", false)
	writeCache(cursors, old)

	got := staleIconThemeCaches(icons)
	want := []string{noCache, outdated}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stale themes = %v, want %v", got, want)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover theme directory still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cursors, "icon-theme.cache")); err != nil {
		t.Fatalf("cache of a theme without index was removed: %v", err)
	}
}
