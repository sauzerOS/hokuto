package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCrossSystemSyncTargetsFollowRecipesNotInstalls(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "gcc", "")
	writeTestPackage(t, repo, "glibc", "")
	if err := os.WriteFile(filepath.Join(repo, "gcc", "version"), []byte("16.2.0 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	index := []RepoEntry{
		{Name: "aarch64-gcc", Version: "16.2.0", Revision: "1", Arch: "aarch64"}, // outdated
		{Name: "aarch64-glibc", Version: "1.0", Revision: "1", Arch: "aarch64"},  // current
		{Name: "aarch64-gone", Version: "1.0", Revision: "1", Arch: "aarch64"},   // recipe removed
		{Name: "aarch64-base-devel", Type: "meta", Arch: "meta"},
		{Name: "gcc", Version: "16.2.0", Revision: "2", Arch: "aarch64"}, // native, not -system
	}

	targets := crossSystemSyncTargets(index)
	if len(targets) != 2 || targets[0].Full != "aarch64-gcc" || targets[1].Full != "aarch64-glibc" {
		t.Fatalf("targets: %+v", targets)
	}
	if targets[0].Base != "gcc" || targets[0].Version != "16.2.0" || targets[0].Revision != "2" {
		t.Fatalf("aarch64-gcc target should be built from gcc at its recipe version: %+v", targets[0])
	}

	missing := missingSyncPackages(targets, index)
	if len(missing) != 1 || missing[0].Full != "aarch64-gcc" {
		t.Fatalf("missing: %+v", missing)
	}

	// A local package of the recipe version counts as present.
	path := filepath.Join(BinDir, StandardizeRemoteName("aarch64-gcc", "16.2.0", "2", "aarch64", "generic"))
	if err := os.WriteFile(path, []byte("pkg"), 0o644); err != nil {
		t.Fatal(err)
	}
	if missing := missingSyncPackages(targets, index); len(missing) != 0 {
		t.Fatalf("cached package still reported missing: %+v", missing)
	}
}
