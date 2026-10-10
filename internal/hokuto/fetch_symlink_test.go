package hokuto

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReplaceSymlinkAtomicConcurrent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "source.tar.gz")
	if err := os.WriteFile(target, []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.tar.gz")

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 64 {
		wg.Go(func() {
			if err := replaceSymlinkAtomic(target, link); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent replaceSymlinkAtomic: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("link = %q, %v; want %q", got, err, target)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("leftover temporary links: %d entries in %s", len(entries), dir)
	}
}
