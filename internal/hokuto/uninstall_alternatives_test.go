package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCanonicalUninstallPathMatchesUsrMergeAliases(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}

	preserved := make(map[string]bool)
	addCanonicalUninstallPath(preserved, root, "/usr/bin/X")

	if !containsCanonicalUninstallPath(preserved, root, filepath.Join(root, "bin", "X")) {
		t.Fatal("restored /usr/bin/X alternative was not preserved for /bin/X manifest alias")
	}
}

func registerSymlinkAlternativeSet(t *testing.T, root string, count int, keepOriginal bool) (*GlobalAlternativesDB, []string, *Executor) {
	t.Helper()
	execCtx := &Executor{Context: context.Background()}
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	incomingDir := t.TempDir()
	requests := make([]AlternativeRequest, 0, count)
	paths := make([]string, 0, count)
	for i := range count {
		name := fmt.Sprintf("X-%d", i)
		path := "/usr/bin/" + name
		if err := os.Symlink("XLibre", filepath.Join(usrBin, name)); err != nil {
			t.Fatal(err)
		}
		incoming := filepath.Join(incomingDir, name)
		if err := os.Symlink("Xorg", incoming); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, AlternativeRequest{
			FilePath:     path,
			IncomingPkg:  "xorg-server",
			CurrentPkg:   "xlibre",
			IncomingFile: incoming,
			KeepOriginal: keepOriginal,
		})
		paths = append(paths, path)
	}
	if err := BatchRegisterAlternatives(root, requests, execCtx); err != nil {
		t.Fatal(err)
	}
	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	return db, paths, execCtx
}

func TestBatchRegisterAlternativesCanonicalizesUsrMergeAlias(t *testing.T) {
	root := t.TempDir()
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(root, "bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("XLibre", filepath.Join(usrBin, "X")); err != nil {
		t.Fatal(err)
	}

	incomingDir := t.TempDir()
	incoming := filepath.Join(incomingDir, "X")
	if err := os.Symlink("Xorg", incoming); err != nil {
		t.Fatal(err)
	}

	err := BatchRegisterAlternatives(root, []AlternativeRequest{{
		FilePath:     "/bin/X",
		IncomingPkg:  "xorg-server",
		CurrentPkg:   "xlibre",
		IncomingFile: incoming,
		KeepOriginal: false,
	}}, &Executor{Context: context.Background()})
	if err != nil {
		t.Fatal(err)
	}

	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	if db.Files["/usr/bin/X"] == nil {
		t.Fatalf("expected canonical /usr/bin/X conflict set, got %#v", db.Files)
	}
	if db.Files["/bin/X"] != nil {
		t.Fatal("alternatives database retained non-canonical /bin/X alias")
	}
}

func TestActivateAlternativesForOwnerBatch(t *testing.T) {
	root := t.TempDir()
	db, paths, execCtx := registerSymlinkAlternativeSet(t, root, 12, true)

	changed, err := activateAlternativesForOwnerBatch(root, db, paths, "xorg-server", execCtx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != len(paths) {
		t.Fatalf("changed %d alternatives, want %d", changed, len(paths))
	}
	for _, path := range paths {
		target, err := os.Readlink(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if target != "Xorg" {
			t.Fatalf("%s points to %q, want Xorg", path, target)
		}
	}

	changed, err = activateAlternativesForOwnerBatch(root, db, paths, "xorg-server", execCtx)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Fatalf("already active batch reported %d changes", changed)
	}
}

func TestRestoreAlternativesOnUninstallRunsBatch(t *testing.T) {
	root := t.TempDir()
	_, paths, execCtx := registerSymlinkAlternativeSet(t, root, 12, false)
	for _, path := range paths {
		diskPath := filepath.Join(root, path)
		if err := os.Remove(diskPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("Xorg", diskPath); err != nil {
			t.Fatal(err)
		}
	}

	restored, err := restoreAlternativesOnUninstallSet("xorg-server", root, execCtx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if !restored[path] {
			t.Fatalf("%s was not marked restored", path)
		}
		target, err := os.Readlink(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if target != "XLibre" {
			t.Fatalf("%s points to %q, want XLibre", path, target)
		}
	}
}
