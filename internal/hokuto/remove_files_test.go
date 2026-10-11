package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveFilesInBatches(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("tests the rm batches, which root does not use")
	}
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 600; i++ { // more than two batches
		path := filepath.Join(dir, fmt.Sprintf("file-%03d.py", i))
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	paths = append(paths, filepath.Join(dir, "already-gone.py"))

	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(locked, "stuck.py")
	if err := os.WriteFile(stuck, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	paths = append(paths[:300], append([]string{stuck}, paths[300:]...)...)

	failed := removeFiles(paths, &Executor{Context: context.Background()})
	if len(failed) != 1 || failed[stuck] == nil {
		t.Fatalf("only the file that could not be removed must be reported: %v", failed)
	}
	for _, path := range paths {
		if path == stuck {
			continue
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed", path)
		}
	}
}
