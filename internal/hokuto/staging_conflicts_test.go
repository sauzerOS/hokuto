package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCheckStagingConflictsRegistersAllGroupsInOneBatch(t *testing.T) {
	root := t.TempDir()
	stagingDir := t.TempDir()
	oldInstalled := Installed
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	t.Cleanup(func() { Installed = oldInstalled })

	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := strings.Repeat("0", 64)
	// Two installed owners and one unmanaged file, all replaced by "newpkg".
	write(filepath.Join(Installed, "pkg-b", "manifest"), "/usr/bin/b  "+sum+"\n")
	write(filepath.Join(Installed, "pkg-a", "manifest"), "/usr/bin/a  "+sum+"\n")
	var stagingManifest strings.Builder
	for _, name := range []string{"a", "b", "c"} {
		write(filepath.Join(root, "usr", "bin", name), "original "+name+"\n")
		write(filepath.Join(stagingDir, "usr", "bin", name), "incoming "+name+"\n")
		stagingManifest.WriteString("/usr/bin/" + name + "  " + sum + "\n")
	}
	manifestPath := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", "newpkg", "manifest")
	write(manifestPath, stagingManifest.String())

	// Answer "keep original" for the package conflicts and the unmanaged one.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("o\no\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	execCtx := &Executor{Context: context.Background()}
	if err := checkStagingConflicts("newpkg", stagingDir, root, manifestPath, execCtx, false, false, map[string]bool{}, nil); err != nil {
		t.Fatal(err)
	}

	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	wantOwner := map[string]string{"a": "pkg-a", "b": "pkg-b", "c": "unmanaged"}
	for name, owner := range wantOwner {
		path := "/usr/bin/" + name
		entry := db.Files[path]
		if entry == nil || len(entry.Alternatives) != 2 {
			t.Fatalf("%s: expected two alternatives, got %#v", path, entry)
		}
		for _, alt := range entry.Alternatives {
			switch alt.State {
			case StateActive:
				if !slices.Equal(alt.Owners, []string{owner}) {
					t.Errorf("%s: original owned by %v, want [%s]", path, alt.Owners, owner)
				}
			case StateStashed:
				if !slices.Equal(alt.Owners, []string{"newpkg"}) {
					t.Errorf("%s: stashed incoming owned by %v, want [newpkg]", path, alt.Owners)
				}
				if data, err := os.ReadFile(getStashedFilePath(root, alt.B3Sum)); err != nil || string(data) != "incoming "+name+"\n" {
					t.Errorf("%s: store holds %q (%v)", path, data, err)
				}
			}
		}
		if _, err := os.Lstat(filepath.Join(stagingDir, "usr", "bin", name)); !os.IsNotExist(err) {
			t.Errorf("%s: kept-original file must be removed from staging, got %v", path, err)
		}
		if data, _ := os.ReadFile(filepath.Join(root, "usr", "bin", name)); string(data) != "original "+name+"\n" {
			t.Errorf("%s: original on disk changed to %q", path, data)
		}
	}
}
