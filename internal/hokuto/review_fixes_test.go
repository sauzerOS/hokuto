package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseManifestLinePreservesPathWhitespace(t *testing.T) {
	entry, ok, err := parseManifestLine("/usr/share/My App/data  file.txt  abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("manifest entry was skipped")
	}
	if entry.Path != "/usr/share/My App/data  file.txt" || entry.Checksum != "abc123" {
		t.Fatalf("unexpected entry: %#v", entry)
	}

	dir, ok, err := parseManifestLine("/usr/share/My App/empty dir/")
	if err != nil || !ok {
		t.Fatalf("directory parse failed: ok=%v err=%v", ok, err)
	}
	if dir.Path != "/usr/share/My App/empty dir/" || dir.Checksum != "" {
		t.Fatalf("unexpected directory entry: %#v", dir)
	}
}

func TestParseManifestFilePathPreservesDirectoryWhitespace(t *testing.T) {
	const path = "/usr/share/Program Files/Common Files/"
	if got := parseManifestFilePath(path); got != path {
		t.Fatalf("got %q, want %q", got, path)
	}
}

func TestParseManifestRetainsDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest")
	data := "/usr/share/My App/empty dir/\n/usr/share/My App/file.txt  abc123\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := entries["/usr/share/My App/empty dir/"]; !ok {
		t.Fatalf("directory entry was dropped: %#v", entries)
	}
	if got := entries["/usr/share/My App/file.txt"].Checksum; got != "abc123" {
		t.Fatalf("unexpected file checksum %q", got)
	}
}

func TestRemoveManifestEntriesKeepsDirectoryRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest")
	data := "/usr/share/My App/empty dir/\n/usr/share/My App/keep.txt  keep\n/usr/share/My App/remove.txt  remove\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	execCtx := &Executor{Context: context.Background()}
	if err := removeManifestEntries(path, map[string]bool{"usr/share/My App/remove.txt": true}, execCtx); err != nil {
		t.Fatal(err)
	}

	entries, err := parseManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := entries["/usr/share/My App/empty dir/"]; !ok {
		t.Fatal("directory record was lost while rewriting manifest")
	}
	if _, ok := entries["/usr/share/My App/keep.txt"]; !ok {
		t.Fatal("unrelated file record was lost")
	}
	if _, ok := entries["/usr/share/My App/remove.txt"]; ok {
		t.Fatal("requested file record was not removed")
	}
}

func TestFindOwnerPackageSupportsSpaces(t *testing.T) {
	oldInstalled := Installed
	Installed = filepath.Join(t.TempDir(), "installed")
	t.Cleanup(func() { Installed = oldInstalled })
	pkgDir := filepath.Join(Installed, "demo")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest"), []byte("/usr/share/My App/file.txt  abc123\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	owner, err := findOwnerPackage("/usr/share/My App/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "demo" {
		t.Fatalf("unexpected owner %q", owner)
	}
}

func TestBatchRegisterAlternativesResolvesOwnerFromSnapshot(t *testing.T) {
	root := t.TempDir()
	oldInstalled := Installed
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	t.Cleanup(func() { Installed = oldInstalled })

	const filePath = "/usr/share/Program Files/demo.txt"
	if err := os.MkdirAll(filepath.Join(Installed, "demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "/usr/share/Program Files/\n" + filePath + "  " + strings.Repeat("0", 64) + "\n"
	if err := os.WriteFile(filepath.Join(Installed, "demo", "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, filePath)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	incoming := filepath.Join(t.TempDir(), "demo.txt")
	if err := os.WriteFile(incoming, []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// No CurrentPkg: the owner must come from the installed manifests.
	if err := BatchRegisterAlternatives(root, []AlternativeRequest{{
		FilePath: filePath, IncomingPkg: "other", IncomingFile: incoming,
	}}, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := db.Files[filePath]
	if entry == nil || len(entry.Alternatives) != 2 {
		t.Fatalf("expected two alternatives for %s, got %#v", filePath, entry)
	}
	for _, alt := range entry.Alternatives {
		if alt.State == StateStashed && !slices.Equal(alt.Owners, []string{"demo"}) {
			t.Fatalf("stashed original owned by %v, want [demo]", alt.Owners)
		}
	}
}

func TestRemoveObsoleteFilesDoesNotTruncateSpacePath(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	oldInstalled := Installed
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	globalFileOwnershipCache = fileOwnershipCache{}
	t.Cleanup(func() {
		Installed = oldInstalled
		globalFileOwnershipCache = fileOwnershipCache{}
	})

	installedPkg := filepath.Join(Installed, "demo")
	staging := filepath.Join(tmp, "staging")
	stagingPkg := filepath.Join(staging, "var", "db", "hokuto", "installed", "demo")
	if err := os.MkdirAll(installedPkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stagingPkg, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := "/usr/share/My App/file.txt  abc123\n"
	if err := os.WriteFile(filepath.Join(installedPkg, "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingPkg, "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	truncatedPath := filepath.Join(root, "usr", "share", "My")
	if err := os.MkdirAll(filepath.Dir(truncatedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncatedPath, []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}

	obsolete, err := removeObsoleteFiles("demo", staging, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(obsolete) != 0 {
		t.Fatalf("space-containing manifest path was truncated: %v", obsolete)
	}
}

func TestRemoveObsoleteFilesPreservesAnotherPackagesActiveAlternative(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	oldInstalled := Installed
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	globalFileOwnershipCache = fileOwnershipCache{}
	t.Cleanup(func() {
		Installed = oldInstalled
		globalFileOwnershipCache = fileOwnershipCache{}
	})

	const path = "/usr/include/shared.h"
	for _, pkgName := range []string{"provider-a", "provider-b"} {
		pkgDir := filepath.Join(Installed, pkgName)
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "manifest"), []byte(path+" "+hashString(pkgName)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	diskPath := filepath.Join(root, strings.TrimPrefix(path, "/"))
	if err := os.MkdirAll(filepath.Dir(diskPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diskPath, []byte("provider-b"), 0o644); err != nil {
		t.Fatal(err)
	}

	staging := filepath.Join(tmp, "staging")
	stagingPkg := filepath.Join(staging, "var", "db", "hokuto", "installed", "provider-a")
	if err := os.MkdirAll(stagingPkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingPkg, "manifest"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	obsolete, err := removeObsoleteFiles("provider-a", staging, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(obsolete) != 0 {
		t.Fatalf("another package's active alternative was scheduled for deletion: %v", obsolete)
	}
}

func TestGetBaseRepoPathFindsContainingWorktree(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "arbitrary", "layout", "project")
	packages := filepath.Join(repo, "collections", "core")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(packages, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := getBaseRepoPath(packages); got != repo {
		t.Fatalf("got repository root %q, want %q", got, repo)
	}
}

func TestLoadConfigReportsReadErrors(t *testing.T) {
	_, err := loadConfig(t.TempDir())
	if err == nil {
		t.Fatal("expected reading a directory as configuration to fail")
	}
}

func TestRemoteUpdateDependencyPlanExcludesTarget(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "dependency", "")
	index := []RepoEntry{
		{Name: "target", Version: "2", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: repoEntryMetadataVersion, Depends: []string{"dependency"}},
		{Name: "dependency", Version: "1", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: repoEntryMetadataVersion},
	}
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	plan, err := remoteUpdateDependencyPlan("target", cfg, index)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan, ","); got != "dependency" {
		t.Fatalf("unexpected dependency plan %q", got)
	}
}
