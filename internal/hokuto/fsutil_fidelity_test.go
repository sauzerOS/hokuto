package hokuto

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCopyTreeWithTarPreservesXattrsAndHardLinks guards the two things the tar
// path silently dropped before, which matter once it is the only fallback left
// behind hard-link placement:
//
//   - extended attributes, which is where file capabilities live
//     (/usr/bin/kwin_wayland carries cap_sys_nice=ep on a real system)
//   - hard links inside a package, which rsync -H preserved and a naive tar
//     turns into duplicated copies
func TestCopyTreeWithTarPreservesXattrsAndHardLinks(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "stage")
	dst := filepath.Join(base, "dest")
	if err := os.MkdirAll(filepath.Join(src, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	withXattr := filepath.Join(src, "usr/bin/withcap")
	if err := os.WriteFile(withXattr, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(withXattr, "user.testcap", []byte("cap_sys_nice=ep"), 0); err != nil {
		t.Skipf("filesystem here does not support xattrs: %v", err)
	}

	toolA := filepath.Join(src, "usr/bin/toolA")
	if err := os.WriteFile(toolA, []byte("shared payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(toolA, filepath.Join(src, "usr/bin/toolB")); err != nil {
		t.Fatal(err)
	}

	if err := copyTreeWithTar(src, dst, &Executor{}); err != nil {
		t.Fatalf("copyTreeWithTar: %v", err)
	}

	buf := make([]byte, 256)
	n, err := unix.Getxattr(filepath.Join(dst, "usr/bin/withcap"), "user.testcap", buf)
	if err != nil || n <= 0 {
		t.Errorf("xattr not preserved: %v", err)
	} else if got := string(buf[:n]); got != "cap_sys_nice=ep" {
		t.Errorf("xattr value mangled: %q", got)
	}

	var a, b unix.Stat_t
	if err := unix.Stat(filepath.Join(dst, "usr/bin/toolA"), &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(dst, "usr/bin/toolB"), &b); err != nil {
		t.Fatal(err)
	}
	if a.Ino != b.Ino {
		t.Errorf("hard link not preserved: toolA ino=%d toolB ino=%d (duplicated)", a.Ino, b.Ino)
	}
}
