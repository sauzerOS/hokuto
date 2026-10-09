package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
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

func withTempDependencyEquivalents(t *testing.T, repo, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, equivalentsFile), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	invalidatePackageEquivalentCache()
	alternativeDepCache = make(map[string]string)
	t.Cleanup(func() {
		invalidatePackageEquivalentCache()
		alternativeDepCache = make(map[string]string)
	})
}

// Binary kcmutils (from the mirror index) asked for plain kcoreaddons while
// the sonic packages of the same run had chosen sonic-frameworks-core-addons:
// both were installed and conflicted. Archive dependencies now get the same
// equivalence alternatives as recipe dependencies.
func TestBinaryDependenciesExpandEquivalents(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	withTempDependencyEquivalents(t, repo, "kcoreaddons sonic-frameworks-core-addons\n")
	writeTestPackage(t, repo, "kcoreaddons", "")
	writeTestPackage(t, repo, "sonic-frameworks-core-addons", "")
	index := []RepoEntry{{Name: "kcmutils", Version: "6.1", Revision: "1", Arch: "x86_64",
		Variant: GetSystemVariantForPackage(cfg, "kcmutils"), MetadataVersion: repoEntryMetadataVersion,
		Depends: []string{"kcoreaddons", "glibc"}}}

	deps, found, err := resolveBinaryDependenciesFromArchive("kcmutils", cfg, index, true)
	if err != nil || !found {
		t.Fatalf("deps: found=%v err=%v", found, err)
	}
	if want := []string{"kcoreaddons", "sonic-frameworks-core-addons"}; !reflect.DeepEqual(deps[0].Alternatives, want) {
		t.Fatalf("binary dependency not expanded: %+v", deps[0])
	}
	if !reflect.DeepEqual(index[0].Depends, []string{"kcoreaddons", "glibc"}) {
		t.Fatalf("index entry changed: %v", index[0].Depends)
	}
	// A choice made earlier in the run (by a sonic package) holds.
	alternativeDepCache[alternativeDepCacheKey(deps[0])] = "sonic-frameworks-core-addons"
	if got, err := resolveAlternativeDep(deps[0], true, cfg, "kcmutils"); err != nil || got != "sonic-frameworks-core-addons" {
		t.Fatalf("resolved %q, %v", got, err)
	}
}

// A sonic package that pulls in a KDE framework (kcmutils) before naming its
// own core-addons dependency keeps its choice: its equivalences are settled
// before its dependencies are explored.
func TestDependencyListSettlesOwnEquivalentsFirst(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	withTempDependencyEquivalents(t, repo, "kcoreaddons sonic-frameworks-core-addons\nplasma-pa sonic-audio-applet-pulse\n")
	writeTestPackage(t, repo, "kcoreaddons", "")
	writeTestPackage(t, repo, "sonic-frameworks-core-addons", "")
	writeTestPackage(t, repo, "kcmutils", "kcoreaddons\n")
	writeTestPackage(t, repo, "sonic-audio-applet-pulse", "kcmutils\nkcoreaddons\n")

	deps, err := parsePackageDependsFile(filepath.Join(repo, "sonic-audio-applet-pulse"), "sonic-audio-applet-pulse")
	if err != nil {
		t.Fatal(err)
	}
	var plan []string
	if err := resolveDependencyList("sonic-audio-applet-pulse", deps, map[string]bool{}, &plan, false, true, cfg, nil, false); err != nil {
		t.Fatal(err)
	}
	has := func(name string) bool {
		for _, p := range plan {
			if p == name {
				return true
			}
		}
		return false
	}
	if !has("sonic-frameworks-core-addons") || has("kcoreaddons") {
		t.Fatalf("plan must use the sonic choice only: %v", plan)
	}
}

// hokuto-builder rebuild of the sonic packages: binary kcmutils records a
// plain kcoreaddons dependency, which resolveMissingDeps used to plan as is,
// next to the sonic-frameworks-core-addons the sonic package chose.
func TestMissingDepsRecordedBinaryDependencyFollowsEquivalentChoice(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	withTempDependencyEquivalents(t, repo, "kcoreaddons sonic-frameworks-core-addons\nplasma-pa sonic-audio-applet-pulse\n")
	tarballDependencyCache = sync.Map{}
	t.Cleanup(func() { tarballDependencyCache = sync.Map{} })

	writeTestPackage(t, repo, "kcoreaddons", "")
	writeTestPackage(t, repo, "sonic-frameworks-core-addons", "")
	writeTestPackage(t, repo, "kcmutils", "") // the recipe leaves it to libdeps
	writeTestPackage(t, repo, "sonic-audio-applet-pulse", "kcmutils\nkcoreaddons\n")
	variant := GetSystemVariantForPackage(cfg, "kcmutils")
	writeTestBinaryTarballWithDepends(t, filepath.Join(BinDir, StandardizeRemoteName("kcmutils", "1.0", "1", "x86_64", variant)),
		"kcmutils", "1.0", "1", "kcoreaddons\n")
	writeCachedTestBinary(t, cfg, "kcoreaddons")
	writeCachedTestBinary(t, cfg, "sonic-frameworks-core-addons")

	var missing []string
	if err := resolveMissingDeps("sonic-audio-applet-pulse", map[string]bool{}, &missing,
		map[string]bool{"sonic-audio-applet-pulse": true}, cfg, true); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(missing, ",")
	if !strings.Contains(got, "sonic-frameworks-core-addons") || strings.Contains(got, "kcoreaddons,") || strings.HasSuffix(got, "kcoreaddons") {
		t.Fatalf("missing deps must use the sonic choice only: %s", got)
	}
}

// A package's equivalents metadata is published in its index entry.
func TestIndexEntryRecordsEquivalents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sonic-frameworks-core-addons-6.1-1-x86_64-optimized.tar.zst")
	writeTestArchive(t, path, map[string]string{
		"var/db/hokuto/installed/sonic-frameworks-core-addons/pkginfo":     "name=sonic-frameworks-core-addons\nversion=6.1\nrevision=1\narch=x86_64\ngeneric=0\nmultilib=0\n",
		"var/db/hokuto/installed/sonic-frameworks-core-addons/equivalents": "kcoreaddons sonic-frameworks-core-addons\n",
	}, nil)
	entry, err := ReadPackageMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Equivalents != "kcoreaddons sonic-frameworks-core-addons" {
		t.Fatalf("equivalents not indexed: %q", entry.Equivalents)
	}
}

// A binary-only system (no recipe repositories) learns the pairs from the
// remote index: installing sonic-desktop asked to choose kcoreaddons or
// sonic-frameworks-core-addons for every KDE framework it pulled in.
func TestRemoteIndexEquivalentsAvoidPromptsAndPreferReplacement(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t) // repositories without an equivalents file
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	variant := GetSystemVariantForPackage(cfg, "kcoreaddons")
	oldIndex, oldLoaded := GlobalRemoteIndex, GlobalRemoteIndexLoaded
	t.Cleanup(func() {
		GlobalRemoteIndexMu.Lock()
		GlobalRemoteIndex, GlobalRemoteIndexLoaded = oldIndex, oldLoaded
		GlobalRemoteIndexMu.Unlock()
		preferEquivalentReplacements.Store(false)
		alternativeDepCache = make(map[string]string)
		invalidatePackageEquivalentCache()
	})
	alternativeDepCache = make(map[string]string)
	invalidatePackageEquivalentCache()
	pair := "kcoreaddons sonic-frameworks-core-addons"
	setLoadedRemoteIndex([]RepoEntry{
		{Name: "kcoreaddons", Version: "6.1", Revision: "1", Arch: "x86_64", Variant: variant, MetadataVersion: repoEntryMetadataVersion, Equivalents: pair},
		{Name: "sonic-frameworks-core-addons", Version: "6.1", Revision: "1", Arch: "x86_64", Variant: variant, MetadataVersion: repoEntryMetadataVersion, Equivalents: pair},
		{Name: "sonic-workspace", Version: "6.7", Revision: "1", Arch: "x86_64", Variant: variant, MetadataVersion: repoEntryMetadataVersion},
	})

	// As a published KDE package records it: KDE side first.
	dep := DepSpec{Name: "kcoreaddons", Alternatives: []string{"kcoreaddons", "sonic-frameworks-core-addons"}}
	if !isPackageEquivalentAlternative(dep) {
		t.Fatal("the pair published in the index must be known")
	}
	// yes=false: an unknown pair would prompt here and fail the test.
	if got, err := resolveAlternativeDep(dep, false, cfg, "kcmutils"); err != nil || got != "kcoreaddons" {
		t.Fatalf("without a sonic install: got %q, %v", got, err)
	}

	alternativeDepCache = make(map[string]string)
	preferEquivalentReplacementsFor([]string{"sonic-desktop", "sonic-frameworks-core-addons"})
	if !preferEquivalentReplacements.Load() {
		t.Fatal("requesting a replacement-side package must prefer replacements")
	}
	if got, err := resolveAlternativeDep(dep, false, cfg, "kcmutils"); err != nil || got != "sonic-frameworks-core-addons" {
		t.Fatalf("installing sonic: got %q, %v", got, err)
	}
}

// sauzeros is one git repository split into HOKUTO_PATH entries
// (sauzeros/core, sauzeros/extra); its equivalents file is at the root.
func TestEquivalentsReadFromRepositoryRootAboveHokutoPath(t *testing.T) {
	_, _ = withTempEquivalents(t, "")
	root := t.TempDir()
	for _, dir := range []string{".git", "core", "extra"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, equivalentsFile), []byte("xorg-server xlibre\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repoPaths = filepath.Join(root, "core") + ":" + filepath.Join(root, "extra")
	invalidatePackageEquivalentCache()

	data, err := packageEquivalentMetadata("xorg-server")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "xorg-server xlibre\n" {
		t.Fatalf("metadata for xorg-server = %q, want the pair from the repository root", data)
	}
}
