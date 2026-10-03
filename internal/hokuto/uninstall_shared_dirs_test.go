package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoriesListedElsewhere(t *testing.T) {
	installed := t.TempDir()
	write := func(pkg, manifest string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(installed, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installed, pkg, "manifest"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("sauzeros-base", "/usr/\n/usr/aarch64-linux-gnu/usr/bin/\n/usr/aarch64-linux-gnu/bin 000000")
	write("aarch64-glibc", "/usr/aarch64-linux-gnu/usr/bin/\n/usr/aarch64-linux-gnu/usr/bin/ld.so abc\n/usr/aarch64-linux-gnu/usr/share/glibc/\n")

	got := directoriesListedElsewhere(installed, "aarch64-glibc", []string{"/usr/aarch64-linux-gnu/usr/bin/", "/usr/aarch64-linux-gnu/usr/share/glibc/"})
	if !got["/usr/aarch64-linux-gnu/usr/bin/"] {
		t.Fatalf("usr/bin is also sauzeros-base's: got %v", got)
	}
	if got["/usr/aarch64-linux-gnu/usr/share/glibc/"] {
		t.Fatalf("share/glibc is only aarch64-glibc's own: got %v", got)
	}
}
