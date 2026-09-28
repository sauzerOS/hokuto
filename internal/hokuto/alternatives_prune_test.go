package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPruneAlternativeStoreRemovesOnlyUnreferencedDigests(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(root, GlobalAlternativesStoreDir)
	if err := os.MkdirAll(storeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	digest := func(c string) string { return strings.Repeat(c, 64) }
	referenced, orphan := digest("a"), digest("b")
	for name, data := range map[string]string{
		referenced:  "kept",
		orphan:      "garbage",
		"README":    "not a digest",
		digest("c"): "", // replaced by a directory below
	} {
		if name == digest("c") {
			if err := os.Mkdir(filepath.Join(storeDir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(storeDir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db := &GlobalAlternativesDB{Files: map[string]*FileEntry{
		"/usr/bin/java": {Path: "/usr/bin/java", Alternatives: []*Alternative{
			{B3Sum: referenced, State: StateStashed, Owners: []string{"jdk"}},
		}},
	}}
	execCtx := &Executor{Context: context.Background()}

	// Files written moments ago may belong to another process's pending save.
	if removed, err := pruneAlternativeStoreAt(root, db, execCtx, time.Now()); err != nil || removed != 0 {
		t.Fatalf("fresh store files must survive the grace period: removed %d, err %v", removed, err)
	}

	removed, err := pruneAlternativeStoreAt(root, db, execCtx, time.Now().Add(2*alternativeStoreGracePeriod))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d files, want 1", removed)
	}
	if _, err := os.Stat(filepath.Join(storeDir, orphan)); !os.IsNotExist(err) {
		t.Fatalf("unreferenced store file still present: %v", err)
	}
	for _, name := range []string{referenced, "README", digest("c")} {
		if _, err := os.Lstat(filepath.Join(storeDir, name)); err != nil {
			t.Fatalf("%s must be kept: %v", name, err)
		}
	}
}

func TestPruneAlternativeStoreWithoutStoreDir(t *testing.T) {
	db := &GlobalAlternativesDB{Files: map[string]*FileEntry{}}
	if removed, err := pruneAlternativeStore(t.TempDir(), db, nil); err != nil || removed != 0 {
		t.Fatalf("missing store must be a no-op: removed %d, err %v", removed, err)
	}
}

func TestBatchRegisterAlternativesConcurrentBothModes(t *testing.T) {
	root := t.TempDir()
	incomingDir := t.TempDir()
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}

	var useNew, keepOld []AlternativeRequest
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("tool%02d", i)
		// Shared contents make several requests store the same digest at once.
		original := fmt.Sprintf("original %d\n", i%4)
		incoming := fmt.Sprintf("incoming %d\n", i%4)
		if err := os.WriteFile(filepath.Join(usrBin, name), []byte(original), 0o755); err != nil {
			t.Fatal(err)
		}
		incomingPath := filepath.Join(incomingDir, name)
		if err := os.WriteFile(incomingPath, []byte(incoming), 0o755); err != nil {
			t.Fatal(err)
		}
		req := AlternativeRequest{FilePath: "/usr/bin/" + name, IncomingPkg: "new", CurrentPkg: "old", IncomingFile: incomingPath}
		if i%2 == 0 {
			useNew = append(useNew, req)
		} else {
			req.KeepOriginal = true
			keepOld = append(keepOld, req)
		}
	}

	execCtx := &Executor{Context: context.Background()}
	if err := BatchRegisterAlternatives(root, useNew, execCtx); err != nil {
		t.Fatal(err)
	}
	if err := BatchRegisterAlternatives(root, keepOld, execCtx); err != nil {
		t.Fatal(err)
	}

	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Files) != 32 {
		t.Fatalf("expected 32 conflict sets, got %d", len(db.Files))
	}
	for i := 0; i < 32; i++ {
		path := fmt.Sprintf("/usr/bin/tool%02d", i)
		entry := db.Files[path]
		if entry == nil || len(entry.Alternatives) != 2 {
			t.Fatalf("%s: expected two alternatives, got %#v", path, entry)
		}
		wantActive, wantStashedContent := "new", fmt.Sprintf("original %d\n", i%4)
		if i%2 == 1 {
			wantActive, wantStashedContent = "old", fmt.Sprintf("incoming %d\n", i%4)
		}
		for _, alt := range entry.Alternatives {
			if alt.State == StateActive {
				if !slices.Contains(alt.Owners, wantActive) {
					t.Errorf("%s: active alternative owned by %v, want %s", path, alt.Owners, wantActive)
				}
				continue
			}
			stored, err := os.ReadFile(getStashedFilePath(root, alt.B3Sum))
			if err != nil {
				t.Fatalf("%s: stashed alternative missing from store: %v", path, err)
			}
			if string(stored) != wantStashedContent {
				t.Errorf("%s: store holds %q, want %q", path, stored, wantStashedContent)
			}
		}
	}
}
