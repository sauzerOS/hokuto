package hokuto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

func TestRebuildReason(t *testing.T) {
	for message, want := range map[string]string{
		// bump's ABI rebuild commit: package list subject, reason in the body.
		"droidcam-obs-plugin: 2.4.3: 1 → 2\ngvfs: 1.62.0: 2 → 3\n\n" +
			"rebuild for libplist (libplist++-2.0.so.4, libplist++-2.0.so.4.7.0, libplist-2.0.so.4, libplist-2.0.so.4.7.0) ABI change": "rebuild for libplist ABI change",
		"a: 1: 1 → 2\n\nrebuild for icu (libicuuc.so.77), libxml2 (libxml2.so.2) ABI change": "rebuild for icu, libxml2 ABI change",
		// A manual bump message.
		"rust: 1.90.0: 1 → 2 rebuild for llvm 22.1.8": "rebuild for llvm 22.1.8",
		"Rebuild for Python 3.14.":                    "Rebuild for Python 3.14",
		// No reason given.
		"gvfs: 1.60.3 → 1.62.0": "",
		"":                      "",
	} {
		if got := rebuildReason(message); got != want {
			t.Errorf("rebuildReason(%q) = %q, want %q", message, got, want)
		}
	}
}

func TestVersionCommitMessageReadsLastVersionChange(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "gvfs", "")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "gvfs: 1.62.0: 1 → 2")
	if err := os.WriteFile(filepath.Join(repo, "gvfs", "version"), []byte("1.62.0 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "gvfs: 1.62.0: 2 → 3\n\nrebuild for libplist (libplist-2.0.so.4) ABI change")
	// A later commit that does not touch the version file is not the reason.
	if err := os.WriteFile(filepath.Join(repo, "gvfs", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "gvfs: add build script")

	got := versionCommitMessages([]string{"gvfs", "missing"})
	if reason := rebuildReason(got["gvfs"]); reason != "rebuild for libplist ABI change" {
		t.Fatalf("gvfs commit %q gives reason %q", got["gvfs"], reason)
	}
	if got["missing"] != "" {
		t.Fatalf("a package without a recipe has no commit, got %q", got["missing"])
	}
}

func TestMissingBinarySelectorShowsReasonAndCommit(t *testing.T) {
	entries := []missingBinaryEntry{
		{Name: "gvfs", Info: "1.62.0-2 -> 1.62.0-3 (gvfs)", Reason: "rebuild for libplist ABI change",
			Commit: "gvfs: 1.62.0: 2 → 3\n\nrebuild for libplist (libplist-2.0.so.4) ABI change"},
		{Name: "fmt", Info: "12.2.0-1 -> 12.2.0-2 (fmt)"},
	}
	var screenText string
	runSelectorWithEvents(t, entries, func(s tcell.SimulationScreen) {
		time.Sleep(100 * time.Millisecond)
		cells, width, _ := s.GetContents()
		var b strings.Builder
		for i, cell := range cells {
			if i > 0 && i%width == 0 {
				b.WriteByte('\n')
			}
			if len(cell.Runes) > 0 {
				b.WriteRune(cell.Runes[0])
			} else {
				b.WriteByte(' ')
			}
		}
		screenText = b.String()
		s.InjectKey(tcell.KeyEscape, 0, tcell.ModNone)
	})
	for _, want := range []string{"rebuild for libplist ABI change", "Commit", "libplist-2.0.so.4"} {
		if !strings.Contains(screenText, want) {
			t.Errorf("screen does not show %q:\n%s", want, screenText)
		}
	}
}
