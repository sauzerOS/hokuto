package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withTempEquivalents(t *testing.T, content string) (repo, installed string) {
	t.Helper()
	oldRepoPaths := repoPaths
	oldInstalled := Installed
	repo = filepath.Join(t.TempDir(), "repo")
	installed = filepath.Join(t.TempDir(), "installed")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		if err := os.WriteFile(filepath.Join(repo, equivalentsFile), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repoPaths = repo
	Installed = installed
	invalidatePackageEquivalentCache()
	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		Installed = oldInstalled
		invalidatePackageEquivalentCache()
	})
	return repo, installed
}

func TestParsePackageEquivalentPairsRejectsInvalidMappings(t *testing.T) {
	if _, err := parsePackageEquivalentPairs([]byte("same same\n"), "test"); err == nil {
		t.Fatal("expected self-equivalence to be rejected")
	}
	if _, err := parsePackageEquivalentPairs([]byte("one two three\n"), "test"); err == nil {
		t.Fatal("expected mappings with more than two fields to be rejected")
	}
}

func TestSourceDependenciesExpandToPreferredEquivalent(t *testing.T) {
	repo, installed := withTempEquivalents(t, "kcoreaddons sonic-frameworks-core-addons\nkio sonic-frameworks-io\n")
	consumerDir := filepath.Join(repo, "sonic-frameworks-io")
	if err := os.MkdirAll(consumerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(consumerDir, "depends"), []byte("kcoreaddons\nkcoreaddons>=6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(installed, "sonic-frameworks-core-addons"), 0o755); err != nil {
		t.Fatal(err)
	}

	deps, err := parseDependsFile(consumerDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := deps[0].Alternatives, []string{"sonic-frameworks-core-addons", "kcoreaddons"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected equivalent preference: got %v want %v", got, want)
	}
	if len(deps[1].Alternatives) != 0 {
		t.Fatalf("version-constrained dependency must remain exact: %+v", deps[1])
	}
	resolved, err := resolveAlternativeDep(deps[0], true, &Config{Values: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "sonic-frameworks-core-addons" {
		t.Fatalf("expected installed Sonic equivalent, got %s", resolved)
	}
	alternativeDepCache[alternativeDepCacheKey(deps[0])] = "kcoreaddons"
	t.Cleanup(func() { alternativeDepCache = make(map[string]string) })
	if cached, ok := cachedAlternativeDep(deps[0]); !ok || cached != "sonic-frameworks-core-addons" {
		t.Fatalf("installed equivalent must override stale cached provider, got %q ok=%v", cached, ok)
	}
}

func TestGenerateDependsUsesEquivalentLibraryAlternative(t *testing.T) {
	repo, _ := withTempEquivalents(t, "kcoreaddons sonic-frameworks-core-addons\nkio sonic-frameworks-io\n")
	outputDir := t.TempDir()
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	pkgDir := filepath.Join(repo, "sonic-frameworks-io")
	targetDir := filepath.Join(dbRoot, "sonic-frameworks-io")
	providerDir := filepath.Join(dbRoot, "kcoreaddons")
	for _, dir := range []string{pkgDir, targetDir, providerDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libKF6CoreAddons.so.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "manifest"), []byte("/usr/lib/libKF6CoreAddons.so.6 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldInstalled := Installed
	Installed = dbRoot
	t.Cleanup(func() { Installed = oldInstalled })
	if err := generateDepends("sonic-frameworks-io", pkgDir, outputDir, outputDir, &Executor{Context: context.Background()}, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "sonic-frameworks-core-addons | kcoreaddons\n"; got != want {
		t.Fatalf("unexpected generated dependency: got %q want %q", got, want)
	}
}

func TestPackageEquivalentMetadataSupportsRemoteOnlyConflictDetection(t *testing.T) {
	_, installed := withTempEquivalents(t, "")
	if err := os.MkdirAll(filepath.Join(installed, "kcoreaddons"), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, equivalentsFile), []byte("kcoreaddons sonic-frameworks-core-addons\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conflicts, err := stagedPackageEquivalentConflicts(staged, "sonic-frameworks-core-addons")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(conflicts, []string{"kcoreaddons"}) {
		t.Fatalf("unexpected installed equivalent conflicts: %v", conflicts)
	}
}

func TestInstalledLegacyDependencyKeepsEquivalentProvider(t *testing.T) {
	_, installed := withTempEquivalents(t, "kcoreaddons sonic-frameworks-core-addons\n")
	consumerDir := filepath.Join(installed, "consumer")
	providerDir := filepath.Join(installed, "sonic-frameworks-core-addons")
	for _, dir := range []string{consumerDir, providerDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(consumerDir, "depends"), []byte("kcoreaddons\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invalidatePackageEquivalentCache()

	deps, err := getInstalledDeps("consumer")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(deps, []string{"sonic-frameworks-core-addons"}) {
		t.Fatalf("legacy dependency should retain its installed equivalent provider, got %v", deps)
	}
}

func TestEquivalentReplacementRemovesOldPackageAndTransfersRoots(t *testing.T) {
	hRoot := t.TempDir()
	installed := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	oldInstalled := Installed
	oldRootDir := rootDir
	oldWorldFile := WorldFile
	oldWorldMakeFile := WorldMakeFile
	Installed = installed
	rootDir = hRoot
	WorldFile = filepath.Join(hRoot, "var", "db", "hokuto", "world")
	WorldMakeFile = filepath.Join(hRoot, "var", "db", "hokuto", "world_make")
	t.Cleanup(func() {
		Installed = oldInstalled
		rootDir = oldRootDir
		WorldFile = oldWorldFile
		WorldMakeFile = oldWorldMakeFile
		invalidatePackageEquivalentCache()
	})

	oldMetadata := filepath.Join(installed, "kcoreaddons")
	if err := os.MkdirAll(oldMetadata, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldMetadata, "manifest"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WorldFile, []byte("kcoreaddons\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WorldMakeFile, []byte("kcoreaddons\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged := t.TempDir()
	if err := os.WriteFile(filepath.Join(staged, equivalentsFile), []byte("kcoreaddons sonic-frameworks-core-addons\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	transferWorld, transferMake, err := removeInstalledEquivalentConflicts(
		staged,
		"sonic-frameworks-core-addons",
		&Config{Values: map[string]string{"HOKUTO_ROOT": hRoot}},
		&Executor{Context: context.Background()},
		true,
		os.Stdout,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !transferWorld || !transferMake {
		t.Fatalf("expected both roots to transfer, got world=%v make=%v", transferWorld, transferMake)
	}
	if _, err := os.Stat(oldMetadata); !os.IsNotExist(err) {
		t.Fatalf("old equivalent metadata was not removed: %v", err)
	}
	if packageListedInWorld(WorldFile, "kcoreaddons") || packageListedInWorld(WorldMakeFile, "kcoreaddons") {
		t.Fatal("old equivalent remained in a world file")
	}
}
