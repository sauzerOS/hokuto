package hokuto

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsCrossDeviceLinkError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"EXDEV: separate mount, e.g. /boot", &os.LinkError{Err: syscall.EXDEV}, true},
		{"EPERM: filesystem refuses hard links", &os.LinkError{Err: syscall.EPERM}, true},
		{"EOPNOTSUPP: vfat has no hard links", &os.LinkError{Err: syscall.EOPNOTSUPP}, true},
		{"ENOENT is a real failure", &os.LinkError{Err: syscall.ENOENT}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isCrossDeviceLinkError(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestCopyFilePreservingMetadata covers the path taken when a destination
// cannot be hard linked to, as happens for /boot on a Pi (vfat, separate mount).
func TestCopyFilePreservingMetadata(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kernel8.img")
	dst := filepath.Join(dir, "placed", "kernel8.img")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("kernel payload")
	if err := os.WriteFile(src, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFilePreservingMetadata(src, dst, info); err != nil {
		t.Fatalf("copy: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("contents differ: %q", got)
	}
	di, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != info.Mode().Perm() {
		t.Errorf("mode not preserved: got %v want %v", di.Mode().Perm(), info.Mode().Perm())
	}
	// The copy must be an independent inode, not a link.
	if os.SameFile(info, di) {
		t.Error("destination is the same inode; expected a copy")
	}
}
