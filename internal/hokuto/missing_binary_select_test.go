package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

func TestBuildIgnoreFollowsRecipeRelease(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "icewm", "") // version 1.0 1
	writeTestPackage(t, repo, "xrdp", "")

	old := BuildIgnoreFile
	BuildIgnoreFile = filepath.Join(t.TempDir(), "build-ignore.json")
	t.Cleanup(func() { BuildIgnoreFile = old })
	if err := os.WriteFile(BuildIgnoreFile, []byte(`[
  {"package": "icewm", "version": "1.0-1", "added_at": "2026-09-29T00:00:00Z"},
  {"package": "xrdp", "version": "0.9-1", "added_at": "2026-09-29T00:00:00Z"},
  {"package": "removed-recipe", "version": "1.0-1", "added_at": "2026-09-29T00:00:00Z"}
]`), 0o644); err != nil {
		t.Fatal(err)
	}
	ignores, err := loadBuildIgnoreList()
	if err != nil {
		t.Fatal(err)
	}
	if !buildIgnored(ignores, "icewm") {
		t.Fatal("icewm is blacklisted at its current release")
	}
	if buildIgnored(ignores, "xrdp") {
		t.Fatal("xrdp moved to a new version, its blacklisting must end")
	}

	// A revision bump ends it too.
	if err := os.WriteFile(filepath.Join(repo, "icewm", "version"), []byte("1.0 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if buildIgnored(ignores, "icewm") {
		t.Fatal("icewm got a new revision, its blacklisting must end")
	}
	if !pruneBuildIgnores(ignores) || len(ignores) != 0 {
		t.Fatalf("stale entries not pruned: %v", ignores)
	}

	// A missing file is an empty blacklist.
	BuildIgnoreFile = filepath.Join(t.TempDir(), "missing.json")
	if ignores, err := loadBuildIgnoreList(); err != nil || len(ignores) != 0 {
		t.Fatalf("missing file: %v %v", ignores, err)
	}
}

// runSelectorWithKeys drives the list on a simulation screen.
func runSelectorWithKeys(t *testing.T, entries []missingBinaryEntry, keys ...tcell.Key) ([]string, []string) {
	t.Helper()
	return runSelectorWithEvents(t, entries, func(screen tcell.SimulationScreen) {
		for _, k := range keys {
			screen.InjectKey(k, 0, tcell.ModNone)
		}
	})
}

func runSelectorWithEvents(t *testing.T, entries []missingBinaryEntry, inject func(tcell.SimulationScreen)) ([]string, []string) {
	t.Helper()
	screen := tcell.NewSimulationScreen("UTF-8")
	type result struct {
		build, blacklist []string
		err              error
	}
	done := make(chan result, 1)
	go func() {
		build, blacklist, err := runMissingBinarySelector(entries, screen)
		done <- result{build, blacklist, err}
	}()
	// Give the application time to start reading events.
	time.Sleep(100 * time.Millisecond)
	inject(screen)
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.build, r.blacklist
	case <-time.After(5 * time.Second):
		t.Fatal("selector did not finish")
	}
	return nil, nil
}

func keyRunes(screen tcell.SimulationScreen, runes string) {
	for _, r := range runes {
		screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
}

func TestMissingBinarySelector(t *testing.T) {
	entries := []missingBinaryEntry{
		{Name: "cunit", Info: "2.1-3 -> 2.1.3 (cunit)"},
		{Name: "fmt", Info: "12.2.0-1 -> 12.2.0-2 (fmt)"},
		{Name: "icewm", Info: "4.1.0-4 -> 4.1.0-8 (icewm)"},
		{Name: "xrdp", Info: "0.10.6.1 -> git.5da996f (xrdp)"},
	}

	// Select fmt and icewm, build.
	build, blacklist := runSelectorWithEvents(t, entries, func(s tcell.SimulationScreen) {
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		keyRunes(s, " ")
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		keyRunes(s, " b")
	})
	if !reflect.DeepEqual(build, []string{"fmt", "icewm"}) || len(blacklist) != 0 {
		t.Fatalf("build %v blacklist %v", build, blacklist)
	}

	// x with nothing selected blacklists the row under the cursor; a selects
	// all but the blacklisted ones.
	build, blacklist = runSelectorWithEvents(t, entries, func(s tcell.SimulationScreen) {
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		keyRunes(s, "xab")
	})
	if !reflect.DeepEqual(build, []string{"cunit", "fmt", "icewm"}) || !reflect.DeepEqual(blacklist, []string{"xrdp"}) {
		t.Fatalf("build %v blacklist %v", build, blacklist)
	}

	// x on a selection blacklists the selected packages; quitting builds
	// nothing but still returns the blacklist.
	build, blacklist = runSelectorWithEvents(t, entries, func(s tcell.SimulationScreen) {
		keyRunes(s, " ")
		s.InjectKey(tcell.KeyDown, 0, tcell.ModNone)
		keyRunes(s, " xq")
	})
	if len(build) != 0 || !reflect.DeepEqual(blacklist, []string{"cunit", "fmt"}) {
		t.Fatalf("build %v blacklist %v", build, blacklist)
	}

	// x again unblacklists; b without a selection does not quit.
	build, blacklist = runSelectorWithEvents(t, entries, func(s tcell.SimulationScreen) {
		keyRunes(s, "xxb")
		keyRunes(s, " b")
	})
	if !reflect.DeepEqual(build, []string{"cunit"}) || len(blacklist) != 0 {
		t.Fatalf("build %v blacklist %v", build, blacklist)
	}

	// Escape leaves without building.
	if build, blacklist := runSelectorWithKeys(t, entries, tcell.KeyEscape); len(build) != 0 || len(blacklist) != 0 {
		t.Fatalf("escape: build %v blacklist %v", build, blacklist)
	}
}
