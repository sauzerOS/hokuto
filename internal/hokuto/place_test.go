package hokuto

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no stat_t for %s", path)
	}
	return st.Ino
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestPlaceStagingByHardlinkBasicTree(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(staging, "usr/bin/tool"), "payload", 0o755)
	writeFile(t, filepath.Join(staging, "usr/lib/libfoo.so.1"), "lib", 0o644)
	if err := os.Symlink("libfoo.so.1", filepath.Join(staging, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	// A setuid binary exercises the bits Perm() alone would drop.
	writeFile(t, filepath.Join(staging, "usr/bin/priv"), "suid", 0o755|os.ModeSetuid)

	srcInode := inode(t, filepath.Join(staging, "usr/bin/tool"))

	if err := placeStagingByHardlink(staging, root); err != nil {
		t.Fatalf("placement failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("content = %q, err = %v", got, err)
	}
	if inode(t, filepath.Join(root, "usr/bin/tool")) != srcInode {
		t.Error("placed file is a copy, not a hard link")
	}

	target, err := os.Readlink(filepath.Join(root, "usr/lib/libfoo.so"))
	if err != nil || target != "libfoo.so.1" {
		t.Fatalf("symlink target = %q, err = %v", target, err)
	}

	fi, err := os.Stat(filepath.Join(root, "usr/bin/priv"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Errorf("setuid bit lost, mode = %v", fi.Mode())
	}
}

func TestPlaceStagingByHardlinkKeepsDirLinks(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	root := filepath.Join(base, "root")

	// Reproduce the sauzerOS layout: /lib is a symlink into usr/.
	if err := os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(staging, "lib/libc.so.6"), "libc", 0o755)

	if err := placeStagingByHardlink(staging, root); err != nil {
		t.Fatalf("placement failed: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(root, "lib"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("root/lib was replaced by a real directory")
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib/libc.so.6")); err != nil {
		t.Fatalf("file was not written through the dir symlink: %v", err)
	}
}

func TestPlaceStagingByHardlinkReplacesAtomically(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	root := filepath.Join(base, "root")

	// An already installed file, standing in for a binary that is running.
	writeFile(t, filepath.Join(root, "usr/bin/tool"), "old", 0o755)
	oldInode := inode(t, filepath.Join(root, "usr/bin/tool"))
	held, err := os.Open(filepath.Join(root, "usr/bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	writeFile(t, filepath.Join(staging, "usr/bin/tool"), "new", 0o755)

	if err := placeStagingByHardlink(staging, root); err != nil {
		t.Fatalf("placement failed: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "usr/bin/tool"))
	if err != nil || string(got) != "new" {
		t.Fatalf("content = %q, err = %v", got, err)
	}
	if inode(t, filepath.Join(root, "usr/bin/tool")) == oldInode {
		t.Error("the destination was written through instead of replaced")
	}

	// The open handle must still see the bytes it was opened on.
	buf := make([]byte, 3)
	if _, err := held.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "old" {
		t.Errorf("open handle now reads %q; the running inode was modified", buf)
	}

	// No temporary files may be left behind.
	entries, err := os.ReadDir(filepath.Join(root, "usr/bin"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == placementTmpSuffix {
			t.Errorf("leftover temporary file %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected a single entry, got %d", len(entries))
	}
}

func TestPlaceStagingByHardlinkPreservesInternalLinks(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(staging, "usr/bin/gcc"), "compiler", 0o755)
	if err := os.Link(filepath.Join(staging, "usr/bin/gcc"), filepath.Join(staging, "usr/bin/cc")); err != nil {
		t.Fatal(err)
	}

	if err := placeStagingByHardlink(staging, root); err != nil {
		t.Fatalf("placement failed: %v", err)
	}

	if inode(t, filepath.Join(root, "usr/bin/gcc")) != inode(t, filepath.Join(root, "usr/bin/cc")) {
		t.Error("hard links inside the package were not preserved")
	}
}

func TestPlaceStagingByHardlinkReplacesDanglingDirLink(t *testing.T) {
	base := t.TempDir()
	staging := filepath.Join(base, "staging")
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink that does not resolve to a directory must not survive where
	// the package ships a real directory.
	if err := os.Symlink("nowhere", filepath.Join(root, "usr")); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(staging, "usr/share/doc/readme"), "hi", 0o644)

	if err := placeStagingByHardlink(staging, root); err != nil {
		t.Fatalf("placement failed: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(root, "usr"))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("root/usr is %v, want a directory", fi.Mode())
	}
	if _, err := os.Stat(filepath.Join(root, "usr/share/doc/readme")); err != nil {
		t.Fatal(err)
	}
}

func TestSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	same, err := sameFilesystem(dir, sub)
	if err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Error("two directories in one temp dir reported as different filesystems")
	}
	if _, err := sameFilesystem(dir, filepath.Join(dir, "missing")); err == nil {
		t.Error("expected an error for a missing path")
	}
}
