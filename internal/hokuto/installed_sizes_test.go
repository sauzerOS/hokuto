package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledPackageSizesRecordedAndFallback(t *testing.T) {
	withTempDependencyRepo(t)
	root := t.TempDir()
	oldRoot := rootDir
	rootDir = root
	t.Cleanup(func() { rootDir = oldRoot })
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")

	// "new" was installed with a recorded size; "old" before sizes were
	// recorded: its size is added up from its manifest.
	writeInstalledTestPackage(t, "new")
	if err := os.WriteFile(filepath.Join(Installed, "new", installedSizeFile), []byte("4096\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeInstalledTestPackage(t, "old")
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "old"), make([]byte, 700), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Installed, "old", "manifest"), []byte("/usr/bin/\n/usr/bin/old  aaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sizes := installedPackageSizes([]string{"new", "old", "missing"})
	if sizes["new"] != 4096 || sizes["old"] != 700 {
		t.Fatalf("sizes = %v, want new 4096 (recorded), old 700 (from its manifest)", sizes)
	}
	if _, ok := sizes["missing"]; ok {
		t.Fatal("a package without size or manifest has no size")
	}
}

func TestRecordStagedInstalledSize(t *testing.T) {
	staging := t.TempDir()
	meta := filepath.Join(staging, "var", "db", "hokuto", "installed", "foo")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkginfo"), []byte("name=foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "usr", "bin", "foo"), make([]byte, 1000), 0o755); err != nil {
		t.Fatal(err)
	}
	// A hard link counts once.
	if err := os.Link(filepath.Join(staging, "usr", "bin", "foo"), filepath.Join(staging, "usr", "bin", "foo2")); err != nil {
		t.Fatal(err)
	}
	recordStagedInstalledSize(staging, "foo", &Executor{Context: context.Background()})
	data, err := os.ReadFile(filepath.Join(meta, installedSizeFile))
	if err != nil {
		t.Fatal(err)
	}
	// The binary once plus its own metadata (pkginfo, 9 bytes).
	if got := strings.TrimSpace(string(data)); got != "1009" {
		t.Fatalf("recorded size = %s, want 1009", got)
	}
}
