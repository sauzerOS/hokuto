package hokuto

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A package installed under a parallel name by an older hokuto (atkmm-2.28)
// lists its archive's metadata paths (installed/atkmm/...) in its manifest.
// Removing it deleted the metadata of the atkmm installed next to it.
func TestUninstallLeavesOtherPackagesMetadata(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	oldRoot := rootDir
	rootDir = root
	t.Cleanup(func() { rootDir = oldRoot })
	cfg.Values["HOKUTO_ROOT"] = root
	db := filepath.Join(root, "var", "db", "hokuto", "installed")
	Installed = db

	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The current atkmm.
	for _, f := range []string{"manifest", "pkginfo", "version", "depends", "signature"} {
		write("var/db/hokuto/installed/atkmm/"+f, f+"\n")
	}
	write("usr/lib/libatkmm-2.36.so.1", "new")
	// atkmm-2.28 with the old-style manifest.
	write("usr/lib/libatkmm-1.6.so.1", "old")
	for _, f := range []string{"pkginfo", "version", "depends"} {
		write("var/db/hokuto/installed/atkmm-2.28/"+f, f+"\n")
	}
	write("var/db/hokuto/installed/atkmm-2.28/manifest", "/usr/\n/usr/lib/\n/usr/lib/libatkmm-1.6.so.1  000000\n"+
		"/var/db/hokuto/installed/atkmm/\n/var/db/hokuto/installed/atkmm/manifest  abc\n"+
		"/var/db/hokuto/installed/atkmm/pkginfo  abc\n/var/db/hokuto/installed/atkmm/version  abc\n"+
		"/var/db/hokuto/installed/atkmm-2.28/\n/var/db/hokuto/installed/atkmm-2.28/pkginfo  000000\n")

	execCtx := &Executor{Context: context.Background()}
	if err := pkgUninstallWithRemovalSet("atkmm-2.28", cfg, execCtx, true, true, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(db, "atkmm-2.28")); !os.IsNotExist(err) {
		t.Fatalf("atkmm-2.28 should be gone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib/libatkmm-1.6.so.1")); !os.IsNotExist(err) {
		t.Fatalf("atkmm-2.28's library should be gone: %v", err)
	}
	for _, f := range []string{"manifest", "pkginfo", "version", "depends", "signature"} {
		if _, err := os.Stat(filepath.Join(db, "atkmm", f)); err != nil {
			t.Errorf("atkmm's %s must stay: %v", f, err)
		}
	}
}

func TestRenameManifestMetadataPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest")
	in := "/usr/lib/libatkmm-1.6.so.1  aaa\n/var/db/hokuto/installed/atkmm/\n/var/db/hokuto/installed/atkmm/pkginfo  bbb\n/var/db/hokuto/installed/atkmmx/keep  ccc\n"
	if err := os.WriteFile(path, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renameManifestMetadataPaths(path, "atkmm", "atkmm-2.28", &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := "/usr/lib/libatkmm-1.6.so.1  aaa\n/var/db/hokuto/installed/atkmm-2.28/\n/var/db/hokuto/installed/atkmm-2.28/pkginfo  bbb\n/var/db/hokuto/installed/atkmmx/keep  ccc\n"
	if string(got) != want {
		t.Fatalf("manifest =\n%s\nwant\n%s", got, want)
	}
}
