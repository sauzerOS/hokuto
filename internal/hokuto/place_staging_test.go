package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallStagingBasePrefersRootFilesystem(t *testing.T) {
	root := t.TempDir()
	fallback := t.TempDir()

	got := installStagingBase(root, fallback, nil)
	want := filepath.Join(root, "var/cache/hokuto/staging")
	if got != want {
		t.Fatalf("expected the first same-filesystem candidate\n got  %q\n want %q", got, want)
	}
	if fi, err := os.Stat(got); err != nil || !fi.IsDir() {
		t.Fatalf("staging base was not created: %v", err)
	}
}

func TestInstallStagingBaseHonoursConfigOverride(t *testing.T) {
	root := t.TempDir()
	override := filepath.Join(t.TempDir(), "custom-staging")
	cfg := &Config{Values: map[string]string{"STAGINGDIR": override}}

	if got := installStagingBase(root, t.TempDir(), cfg); got != override {
		t.Fatalf("STAGINGDIR ignored: got %q want %q", got, override)
	}
}

// TestCopyTreeWithTarWritesThroughDirSymlink covers the merged-/usr case that
// `cp -aT` could not handle: the destination has lib -> usr/lib while the
// staging tree carries a real lib/ directory. The file must land in usr/lib and
// the symlink must survive.
func TestCopyTreeWithTarWritesThroughDirSymlink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run as an unprivileged user")
	}
	base := t.TempDir()
	dst := filepath.Join(base, "dest")
	src := filepath.Join(base, "stage")

	if err := os.MkdirAll(filepath.Join(dst, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/lib", filepath.Join(dst, "lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "lib", "new.so"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyTreeWithTar(src, dst, &Executor{}); err != nil {
		t.Fatalf("copyTreeWithTar: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dst, "lib"))
	if err != nil {
		t.Fatalf("lib vanished: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("dest/lib was replaced by a real directory; merged-/usr would be broken")
	}
	if _, err := os.Stat(filepath.Join(dst, "usr/lib", "new.so")); err != nil {
		t.Fatalf("file was not written through the symlink: %v", err)
	}
}
