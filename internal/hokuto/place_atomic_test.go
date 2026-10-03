package hokuto

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

// The tar-copy placement (staging on another filesystem, as in the build
// container) must replace files, never rewrite them in place: a program with
// the old file open or mapped keeps its intact copy, and a new file's mode,
// setuid included, is applied even when the path already existed.
func TestCopyTreeWithTarReplacesAtomically(t *testing.T) {
	staging, root := t.TempDir(), t.TempDir()
	write := func(dir, rel, data string, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	// Installed state.
	write(root, "usr/lib/libfoo.so.1", "old library contents", 0o755)
	write(root, "usr/bin/passwd", "old passwd", 0o755)
	if err := os.Symlink("libfoo.so.1", filepath.Join(root, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	// New package contents.
	write(staging, "usr/lib/libfoo.so.2", "new library contents", 0o755)
	write(staging, "usr/lib/libfoo.so.1", "new library, same soname", 0o755)
	write(staging, "usr/bin/passwd", "new passwd", 0o755|os.ModeSetuid)
	write(staging, "usr/bin/tool", "tool", 0o755)
	if err := os.Link(filepath.Join(staging, "usr/bin/tool"), filepath.Join(staging, "usr/bin/tool-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libfoo.so.2", filepath.Join(staging, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}

	// A running program holding the old library.
	held, err := os.Open(filepath.Join(root, "usr/lib/libfoo.so.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	oldInode := inodeOf(t, filepath.Join(root, "usr/lib/libfoo.so.1"))

	if err := copyTreeWithTar(staging, root, &Executor{}); err != nil {
		t.Fatal(err)
	}

	if got, _ := io.ReadAll(held); string(got) != "old library contents" {
		t.Errorf("the running program's copy was changed underneath it: %q", got)
	}
	if inodeOf(t, filepath.Join(root, "usr/lib/libfoo.so.1")) == oldInode {
		t.Error("the library was rewritten in place instead of replaced")
	}
	if data, _ := os.ReadFile(filepath.Join(root, "usr/lib/libfoo.so.1")); string(data) != "new library, same soname" {
		t.Errorf("new library contents %q", data)
	}
	info, err := os.Stat(filepath.Join(root, "usr/bin/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 || info.Mode().Perm() != 0o755 {
		t.Errorf("passwd mode %v, want setuid 0755", info.Mode())
	}
	if target, _ := os.Readlink(filepath.Join(root, "usr/lib/libfoo.so")); target != "libfoo.so.2" {
		t.Errorf("symlink points to %q", target)
	}
	if inodeOf(t, filepath.Join(root, "usr/bin/tool")) != inodeOf(t, filepath.Join(root, "usr/bin/tool-alias")) {
		t.Error("hard links inside the package must stay linked")
	}
	entries, _ := os.ReadDir(filepath.Join(root, "usr/lib"))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), placementTmpSuffix) {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestCopyFilePreservingMetadataKeepsSetuid(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "src"), filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFilePreservingMetadata(src, dst, info); err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode()&os.ModeSetuid == 0 || got.Mode().Perm() != 0o755 {
		t.Errorf("mode %v, want setuid 0755", got.Mode())
	}
}

// sauzeros-base ships /var/lock as a link to ../run/lock; a root where it is
// still an empty directory must take the link in both placement paths, while
// a directory holding files is kept and reported.
func TestPlacementReplacesEmptyDirectoryWithSymlink(t *testing.T) {
	place := map[string]func(staging, root string) error{
		"hardlink": placeStagingByHardlink,
		"tar": func(staging, root string) error {
			return copyTreeWithTar(staging, root, &Executor{})
		},
	}
	for name, fn := range place {
		t.Run(name, func(t *testing.T) {
			staging, root := t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(staging, "var"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../run/lock", filepath.Join(staging, "var", "lock")); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "var", "lock"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fn(staging, root); err != nil {
				t.Fatalf("placing over an empty directory: %v", err)
			}
			if target, err := os.Readlink(filepath.Join(root, "var", "lock")); err != nil || target != "../run/lock" {
				t.Fatalf("/var/lock = %q, %v; want the link", target, err)
			}

			root = t.TempDir()
			kept := filepath.Join(root, "var", "lock", "LCK..ttyS0")
			if err := os.MkdirAll(filepath.Dir(kept), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(kept, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := fn(staging, root); err == nil {
				t.Fatal("placing over a directory with files succeeded")
			}
			if _, err := os.Stat(kept); err != nil {
				t.Fatalf("file in the kept directory: %v", err)
			}
		})
	}
}
