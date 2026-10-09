package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withTempBlacklist(t *testing.T) {
	t.Helper()
	oldIgnore, oldBump := BuildIgnoreFile, BumpIgnoreFile
	dir := t.TempDir()
	BuildIgnoreFile = filepath.Join(dir, "build-ignore.json")
	BumpIgnoreFile = filepath.Join(dir, "bump-ignore.json")
	t.Cleanup(func() { BuildIgnoreFile, BumpIgnoreFile = oldIgnore, oldBump })
	ownBuildFailures.Lock()
	old := ownBuildFailures.m
	ownBuildFailures.m = make(map[string]bool)
	ownBuildFailures.Unlock()
	t.Cleanup(func() {
		ownBuildFailures.Lock()
		ownBuildFailures.m = old
		ownBuildFailures.Unlock()
	})
}

// Only a package whose own build failed is blacklisted, per architecture, and
// the entry ends with the recipe's release.
func TestBlacklistFailedBuilds(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	withTempBlacklist(t)
	writeTestPackage(t, repo, "broken", "")
	writeTestPackage(t, repo, "blocked", "")
	results := filepath.Join(t.TempDir(), "results")
	t.Setenv(buildResultsEnv, results)

	noteOwnBuildFailure("broken")
	added := blacklistFailedBuilds([]string{"broken", "blocked"}, "", recipeRelease, ownBuildFailed)
	if len(added) != 1 || added[0] != "broken" {
		t.Fatalf("blacklisted %v, want [broken]", added)
	}
	ignores, err := loadBuildIgnoreList()
	if err != nil {
		t.Fatal(err)
	}
	if !buildIgnoredArch(ignores, "broken", "", "1.0-1") || buildIgnoredArch(ignores, "broken", "aarch64", "1.0-1") {
		t.Fatalf("native entry missing or leaking to aarch64: %+v", ignores)
	}
	if !buildIgnored(ignores, "broken") {
		t.Fatal("update --build-missing-binaries would still build broken")
	}

	// The same package failing for aarch64 is a separate entry.
	blacklistFailedBuilds([]string{"broken"}, "aarch64", recipeRelease, ownBuildFailed)
	ignores, _ = loadBuildIgnoreList()
	if len(ignores) != 2 || !buildIgnoredArch(ignores, "broken", "aarch64", "1.0-1") {
		t.Fatalf("aarch64 entry missing: %+v", ignores)
	}

	// A new revision ends both.
	if err := os.WriteFile(filepath.Join(repo, "broken", "version"), []byte("1.0 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pruneBuildIgnores(ignores) || len(ignores) != 0 {
		t.Fatalf("entries survived a revision bump: %+v", ignores)
	}

	data, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\tblacklisted\tbroken\t1.0-1\t"); got != 2 {
		t.Fatalf("want two blacklisted results, got:\n%s", data)
	}
}

func TestRemoveBuildIgnores(t *testing.T) {
	ignores := map[string]buildIgnoreEntry{
		buildIgnoreKey("foo", ""):        {Package: "foo", Version: "1-1"},
		buildIgnoreKey("foo", "aarch64"): {Package: "foo", Arch: "aarch64", Version: "1-1"},
		buildIgnoreKey("bar", ""):        {Package: "bar", Version: "1-1"},
	}
	if got := removeBuildIgnores(ignores, []string{"foo"}, "aarch64"); len(got) != 1 || got[0] != "foo (aarch64)" {
		t.Fatalf("removed %v", got)
	}
	if got := removeBuildIgnores(ignores, []string{"foo", "bar"}, ""); len(got) != 2 {
		t.Fatalf("removed %v", got)
	}
	if len(ignores) != 0 {
		t.Fatalf("left %+v", ignores)
	}
}

// An unmatched Repology project is reported once, not every run.
func TestReportNewNoMatchesOnlyOnce(t *testing.T) {
	withTempBlacklist(t)
	results := filepath.Join(t.TempDir(), "results")
	t.Setenv(buildResultsEnv, results)

	reportNewNoMatches("sauzeros", map[string]string{"python:dbus-python": "python-dbus-python\t1.4.0"})
	reportNewNoMatches("sauzeros", map[string]string{"python:dbus-python": "python-dbus-python\t1.4.0", "foo": "foo\t2"})
	data, err := os.ReadFile(results)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 reports (dbus-python once, foo once), got:\n%s", data)
	}
	if f := strings.Split(lines[0], "\t"); f[1] != "nomatch" || f[2] != "python:dbus-python" || f[3] != "1.4.0" || !strings.Contains(f[6], "pkgdev.go") {
		t.Fatalf("first report = %q", lines[0])
	}
}

func TestRoundCountsIgnoreNotes(t *testing.T) {
	round := WebsiteRound{Steps: []WebsiteRoundStep{{Packages: []WebsiteRoundPackage{
		{Status: "success"}, {Status: "failed"}, {Status: "blacklisted"}, {Status: "nomatch"},
	}}}}
	if built, failed := roundCounts(round); built != 1 || failed != 1 {
		t.Fatalf("roundCounts = %d, %d; want 1, 1", built, failed)
	}
}
