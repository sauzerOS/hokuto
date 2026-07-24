package hokuto

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOtherActiveHokutoBuildSessions(t *testing.T) {
	oldRoot := rootDir
	rootDir = t.TempDir()
	t.Cleanup(func() { rootDir = oldRoot })

	sessionDir := hokutoBuildSessionDir()
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(sessionDir)) })

	endSession := registerHokutoBuildSession()
	t.Cleanup(endSession)
	if active := otherActiveHokutoBuildSessions(); len(active) != 0 {
		t.Fatalf("current process session should not count as another active build, got %v", active)
	}

	stalePath := filepath.Join(sessionDir, "99999999-1.session")
	if err := os.WriteFile(stalePath, []byte("pid=99999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if active := otherActiveHokutoBuildSessions(); len(active) != 0 {
		t.Fatalf("stale session should not count as active, got %v", active)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale session marker was not removed: %v", err)
	}

	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep command unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	activePath := filepath.Join(sessionDir, strconv.Itoa(cmd.Process.Pid)+"-1.session")
	if err := os.WriteFile(activePath, []byte("pid="+joinPIDs([]int{cmd.Process.Pid})+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if active := otherActiveHokutoBuildSessions(); len(active) != 1 || active[0] != cmd.Process.Pid {
		t.Fatalf("live child session should count as active, got %v want %d", active, cmd.Process.Pid)
	}
}

func withTempDependencyRepo(t *testing.T) (*Config, string) {
	t.Helper()

	oldRepoPaths := repoPaths
	oldInstalled := Installed
	oldBinDir := BinDir
	oldVersionedPkgDirs := versionedPkgDirs
	oldVersionedPkgBaseNames := versionedPkgBaseNames
	oldVersionedPkgVersions := versionedPkgVersions
	oldRootDir := rootDir

	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	installed := filepath.Join(tmp, "installed")
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	repoPaths = repo
	Installed = installed
	BinDir = binDir
	versionedPkgDirs = make(map[string]string)
	versionedPkgBaseNames = make(map[string]string)
	versionedPkgVersions = make(map[string]string)

	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		Installed = oldInstalled
		BinDir = oldBinDir
		versionedPkgDirs = oldVersionedPkgDirs
		versionedPkgBaseNames = oldVersionedPkgBaseNames
		versionedPkgVersions = oldVersionedPkgVersions
		rootDir = oldRootDir
	})

	return &Config{Values: map[string]string{}}, repo
}

func writeTestPackage(t *testing.T, repo, name, depends string) {
	t.Helper()

	pkgDir := filepath.Join(repo, name)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("1.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if depends != "" {
		if err := os.WriteFile(filepath.Join(pkgDir, "depends"), []byte(depends), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeInstalledTestPackage(t *testing.T, name string) {
	t.Helper()

	pkgDir := filepath.Join(Installed, name)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("1.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeInstalledTestPackageWithDepends(t *testing.T, name, depends string) {
	t.Helper()

	writeInstalledTestPackage(t, name)
	if depends != "" {
		if err := os.WriteFile(filepath.Join(Installed, name, "depends"), []byte(depends), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveBinaryDependenciesUsesSplitDependsWithoutSourcePackage(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)

	writeTestPackage(t, repo, "gcc-libs", "")
	writeTestPackage(t, repo, "glibc", "")
	writeTestPackage(t, repo, "llvm", "")
	if err := os.WriteFile(filepath.Join(repo, "llvm", "depends.llvm-libs"), []byte("gcc-libs\nglibc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var plan []string
	visited := make(map[string]bool)
	if err := resolveBinaryDependencies("llvm-libs", visited, &plan, false, true, cfg, nil, false); err != nil {
		t.Fatal(err)
	}

	for _, pkgName := range plan {
		if pkgName == "llvm" {
			t.Fatalf("split package install plan should not include source package llvm: %v", plan)
		}
	}
	want := []string{"gcc-libs", "glibc", "llvm-libs"}
	if strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected install plan: got %v want %v", plan, want)
	}
}

func TestResolveBinaryDependenciesExpandsMetaPackage(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)

	metaDir := filepath.Join(repo, ".hokuto")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "metapackages.toml"), []byte(`
[minimal-chroot]
description = "Small chroot profile"
depends = [
  "glibc",
  "bash",
]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestPackage(t, repo, "glibc", "")
	writeTestPackage(t, repo, "bash", "glibc\n")

	var plan []string
	visited := make(map[string]bool)
	if err := resolveBinaryDependencies("minimal-chroot", visited, &plan, false, true, cfg, nil, false); err != nil {
		t.Fatal(err)
	}

	want := []string{"glibc", "bash"}
	if strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected install plan: got %v want %v", plan, want)
	}
}

func TestCollectMetaPackageMissingBinaryTargetsIncludesOptionalDependencies(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "alpha", "delta\nepsilon optional\n")
	writeTestPackage(t, repo, "beta", "")
	writeTestPackage(t, repo, "gamma", "")
	writeTestPackage(t, repo, "delta", "")
	writeTestPackage(t, repo, "epsilon", "")
	for _, name := range []string{"alpha", "beta"} {
		path := filepath.Join(BinDir, StandardizeRemoteName(name, "1.0", "1", "x86_64", "optimized"))
		writeTestBinaryTarball(t, path, name, "1.0", "1")
	}
	meta := MetaPackage{
		Name: "desktop",
		Depends: []DepSpec{
			{Name: "alpha"},
			{Name: "beta", Optional: true},
		},
		Suggests: []DepSpec{{Name: "gamma", Suggest: true}},
	}
	targets, _, err := collectMetaPackageMissingBinaryTargets(meta, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"delta", "epsilon", "gamma"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected missing binary targets: got %v want %v", targets, want)
	}
}

func TestParseMetaPackageSuggestions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metapackages.toml")
	manifest := `
[desktop]
depends = ["plasma-workspace"]
suggests = [
  "kio-fuse",
  "discover suggest Graphical software management",
]
`
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	metas, err := parseMetaPackageFile(path)
	if err != nil {
		t.Fatal(err)
	}
	meta := metas["desktop"]
	if len(meta.Suggests) != 2 {
		t.Fatalf("expected two suggestions, got %+v", meta.Suggests)
	}
	if !meta.Suggests[0].Suggest || meta.Suggests[0].Name != "kio-fuse" {
		t.Fatalf("unexpected simple suggestion: %+v", meta.Suggests[0])
	}
	if !meta.Suggests[1].Suggest || meta.Suggests[1].Name != "discover" || meta.Suggests[1].SuggestText != "Graphical software management" {
		t.Fatalf("unexpected described suggestion: %+v", meta.Suggests[1])
	}
	lines := metaPackageSuggestLines(meta)
	if len(lines) != 2 || lines[0] != "kio-fuse suggest" || lines[1] != "discover suggest Graphical software management" {
		t.Fatalf("unexpected serialized suggestions: %v", lines)
	}
}

func TestResolveBinaryDependenciesFindsMetaPackageInRepoParent(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	parent := filepath.Dir(repo)
	oldRepoPaths := repoPaths
	repoPaths = repo
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	metaDir := filepath.Join(parent, ".hokuto")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metaDir, "metapackages.toml"), []byte(`
[gcc-libs]
description = "Runtime libraries shipped by GCC"
depends = [
  "libgcc",
  "libstdc++",
]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestPackage(t, repo, "libgcc", "")
	writeTestPackage(t, repo, "libstdc++", "")

	var plan []string
	visited := make(map[string]bool)
	if err := resolveBinaryDependencies("gcc-libs", visited, &plan, false, true, cfg, nil, false); err != nil {
		t.Fatal(err)
	}

	want := []string{"libgcc", "libstdc++"}
	if strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected install plan: got %v want %v", plan, want)
	}
}

func TestResolveBinaryDependenciesExpandsRemoteMetaPackage(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "libgcc", "")
	writeTestPackage(t, repo, "libstdc++", "")

	remoteIndex := []RepoEntry{
		{
			Name:        "gcc-libs",
			Type:        "meta",
			Version:     "0",
			Revision:    "0",
			Arch:        "meta",
			Variant:     "meta",
			Description: "Runtime libraries shipped by GCC",
			Depends:     []string{"libgcc", "libstdc++"},
		},
	}

	var plan []string
	visited := make(map[string]bool)
	if err := resolveBinaryDependencies("gcc-libs", visited, &plan, false, true, cfg, remoteIndex, true); err != nil {
		t.Fatal(err)
	}

	want := []string{"libgcc", "libstdc++"}
	if strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected install plan: got %v want %v", plan, want)
	}
}

func TestResolveBinaryDependenciesReportsMissingRemoteIndexEntry(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"

	remoteIndex := []RepoEntry{{
		Name:     "other-package",
		Version:  "1.0",
		Revision: "1",
		Arch:     "x86_64",
		Variant:  "optimized",
	}}

	var plan []string
	err := resolveBinaryDependencies("remote-only", make(map[string]bool), &plan, false, true, cfg, remoteIndex, true)
	if err == nil {
		t.Fatal("expected missing remote package to fail dependency resolution")
	}
	want := "package is not available in the remote index for x86_64 (optimized), and source not found in HOKUTO_PATH"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPackageSuggestionsSkipsAlternativeGroupWhenProviderInstalled(t *testing.T) {
	oldInstalled := Installed
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	t.Cleanup(func() { Installed = oldInstalled })

	for _, dir := range []string{
		filepath.Join(Installed, "mesa"),
		filepath.Join(Installed, "vulkan-radeon"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	line := "nvidia-utils | vulkan-radeon | vulkan-virtio | vulkan-swrast | vulkan-broadcom suggest vulkan renderer\n"
	if err := os.WriteFile(filepath.Join(Installed, "mesa", "suggests"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Installed, "vulkan-radeon", "version"), []byte("1.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := readPackageSuggestions("mesa", root); len(got) != 0 {
		t.Fatalf("expected installed alternative provider to satisfy suggestion group, got %#v", got)
	}

	if err := os.RemoveAll(filepath.Join(Installed, "vulkan-radeon")); err != nil {
		t.Fatal(err)
	}
	got := readPackageSuggestions("mesa", root)
	if len(got) != 1 {
		t.Fatalf("expected one missing suggestion group, got %#v", got)
	}
	wantAlts := []string{"nvidia-utils", "vulkan-radeon", "vulkan-virtio", "vulkan-swrast", "vulkan-broadcom"}
	if strings.Join(got[0].Alternates, ",") != strings.Join(wantAlts, ",") {
		t.Fatalf("unexpected suggestion alternatives: got %v want %v", got[0].Alternates, wantAlts)
	}
	if got[0].Dependency != strings.Join(wantAlts, " | ") || got[0].Text != "vulkan renderer" {
		t.Fatalf("unexpected suggestion metadata: %#v", got[0])
	}
}

func writeCachedTestBinary(t *testing.T, cfg *Config, name string) {
	t.Helper()

	outputName := getOutputPackageName(name, cfg)
	arch := GetSystemArchForPackage(cfg, name)
	variant := GetSystemVariantForPackage(cfg, name)
	path := filepath.Join(BinDir, StandardizeRemoteName(outputName, "1.0", "1", arch, variant))
	if err := os.WriteFile(path, []byte("test binary"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindCachedVersionedBinaryTarballMatchesPackageMajor(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"

	matching := filepath.Join(BinDir, StandardizeRemoteName("webrtc-audio-processing", "1.3", "2", "x86_64", "optimized"))
	newerRevision := filepath.Join(BinDir, StandardizeRemoteName("webrtc-audio-processing", "1.3", "3", "x86_64", "optimized"))
	wrongMajor := filepath.Join(BinDir, StandardizeRemoteName("webrtc-audio-processing", "2.0", "1", "x86_64", "optimized"))
	writeTestBinaryTarball(t, matching, "webrtc-audio-processing", "1.3", "2")
	writeTestBinaryTarball(t, newerRevision, "webrtc-audio-processing", "1.3", "3")
	writeTestBinaryTarball(t, wrongMajor, "webrtc-audio-processing", "2.0", "1")

	got, ok := findCachedVersionedBinaryTarball("webrtc-audio-processing-1", cfg)
	if !ok {
		t.Fatal("expected versioned cached tarball to be found")
	}
	if got != newerRevision {
		t.Fatalf("expected newest matching revision %s, got %s", newerRevision, got)
	}
}

func TestAvailableBinaryPackageTarballPrefersCachedVersionedBinary(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "webrtc-audio-processing", "")

	cached := filepath.Join(BinDir, StandardizeRemoteName("webrtc-audio-processing", "1.3", "2", "x86_64", "optimized"))
	writeTestBinaryTarball(t, cached, "webrtc-audio-processing", "1.3", "2")

	installName, tarballPath, ok, err := availableBinaryPackageTarball("webrtc-audio-processing-1", cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cached versioned binary to be available")
	}
	if installName != "webrtc-audio-processing-1" {
		t.Fatalf("expected install name webrtc-audio-processing-1, got %s", installName)
	}
	if tarballPath != cached {
		t.Fatalf("expected tarball %s, got %s", cached, tarballPath)
	}
}

func TestGetRepoVersionRejectsMismatchedVersionedPackageMajor(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "webrtc-audio-processing", "")
	if err := os.WriteFile(filepath.Join(repo, "webrtc-audio-processing", "version"), []byte("2.1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := getRepoVersion2("webrtc-audio-processing-1"); err == nil {
		t.Fatal("expected pkg-1 to reject current major-2 source metadata")
	}

	historical := filepath.Join(t.TempDir(), "webrtc-audio-processing-1")
	if err := os.MkdirAll(historical, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(historical, "version"), []byte("1.3 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	versionedPkgDirs["webrtc-audio-processing-1"] = historical
	version, revision, err := getRepoVersion2("webrtc-audio-processing-1")
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.3" || revision != "2" {
		t.Fatalf("unexpected historical version: %s-%s", version, revision)
	}
}

func TestGetRemotePackageEntryFiltersVersionedPackageMajor(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	index := []RepoEntry{
		{Name: "webrtc-audio-processing", Version: "1.3", Revision: "2", Arch: "x86_64", Variant: "optimized"},
		{Name: "webrtc-audio-processing", Version: "2.1", Revision: "1", Arch: "x86_64", Variant: "optimized"},
	}

	entry, err := GetRemotePackageEntry("webrtc-audio-processing-1", cfg, index)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Version != "1.3" || entry.Revision != "2" {
		t.Fatalf("expected major-1 remote entry, got %+v", entry)
	}
	if _, err := GetRemotePackageEntry("webrtc-audio-processing-1", cfg, index[1:]); err == nil {
		t.Fatal("expected a remote index containing only major 2 to reject pkg-1")
	}
}

func TestGetRemotePackageEntryHonorsPreparedExactVersion(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	registerParallelPackageName("java-openjdk-17", "java-openjdk")
	registerParallelPackageVersion("java-openjdk-17", "17.0.20+7")
	index := []RepoEntry{
		{Name: "java-openjdk", Version: "17.0.20+7", Revision: "1", Arch: "x86_64", Variant: "optimized"},
		{Name: "java-openjdk", Version: "17.0.21+9", Revision: "1", Arch: "x86_64", Variant: "optimized"},
	}

	entry, err := GetRemotePackageEntry("java-openjdk-17", cfg, index)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Version != "17.0.20+7" {
		t.Fatalf("exact prepared version drifted to %s", entry.Version)
	}
}

func TestVersionSatisfiesMajorWildcardWithoutDot(t *testing.T) {
	if !versionSatisfies("17.0.20+7", "==", "17*") {
		t.Fatal("expected 17* to match a 17.x release")
	}
	if versionSatisfies("21.0.1", "==", "17*") {
		t.Fatal("expected 17* to reject a 21.x release")
	}
}

func TestPrepareVersionedPackageMajorUsesHistoricalSource(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	oldTmpDir := HokutoTmpDir
	HokutoTmpDir = t.TempDir()
	t.Cleanup(func() { HokutoTmpDir = oldTmpDir })

	pkgDir := filepath.Join(repo, "webrtc-audio-processing")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
	}
	git("init", "-q")
	git("config", "user.name", "Hokuto Test")
	git("config", "user.email", "hokuto@example.invalid")
	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("1.3 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	git("add", "webrtc-audio-processing")
	git("commit", "-q", "-m", "version 1.3")
	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("2.1 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "webrtc-audio-processing/version")
	git("commit", "-q", "-m", "version 2.1")

	resolved, err := prepareVersionedPackageMajor("webrtc-audio-processing-1")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "webrtc-audio-processing-1" {
		t.Fatalf("unexpected resolved name: %s", resolved)
	}
	version, revision, err := getRepoVersion2(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.3" || revision != "2" {
		t.Fatalf("expected historical 1.3-2 source, got %s-%s", version, revision)
	}
}

func TestParseAlternativeDependencyMergesTrailingFlags(t *testing.T) {
	deps, err := parseDependsData([]byte("go-bin | go make\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected one dependency, got %d", len(deps))
	}
	dep := deps[0]
	if !dep.Make {
		t.Fatalf("expected trailing make flag to apply to alternative dependency: %+v", dep)
	}
	if len(dep.Alternatives) != 2 || dep.Alternatives[0] != "go-bin" || dep.Alternatives[1] != "go" {
		t.Fatalf("unexpected alternatives: %+v", dep.Alternatives)
	}
}

func TestResolveAlternativeDependencyFindsCachedSplitBinary(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	path := filepath.Join(BinDir, StandardizeRemoteName("qt-multimedia-ffmpeg", "6.11.1", "1", "x86_64", "optimized"))
	writeTestBinaryTarball(t, path, "qt-multimedia-ffmpeg", "6.11.1", "1")

	alternativeDepCache = make(map[string]string)
	t.Cleanup(func() { alternativeDepCache = make(map[string]string) })
	dep := DepSpec{Alternatives: []string{"qt-multimedia-ffmpeg", "qt-multimedia-gstreamer"}}
	resolved, err := resolveAlternativeDep(dep, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "qt-multimedia-ffmpeg" {
		t.Fatalf("expected cached split binary alternative, got %q", resolved)
	}
}

func TestCollectAvailableBinaryDependenciesUsesChosenAlternative(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "lazyssh", "go | go-bin make\n")
	writeTestPackage(t, repo, "go", "")
	writeTestPackage(t, repo, "go-bin", "")
	writeCachedTestBinary(t, cfg, "go")
	writeCachedTestBinary(t, cfg, "go-bin")

	alternativeDepCache = map[string]string{
		alternativeDepCacheKey(DepSpec{Alternatives: []string{"go", "go-bin"}}): "go-bin",
	}
	t.Cleanup(func() {
		alternativeDepCache = make(map[string]string)
	})

	deps := collectAvailableBinaryDependenciesForPlan(&BuildPlan{Order: []string{"lazyssh"}}, cfg, true)
	if len(deps) != 1 {
		t.Fatalf("expected one binary dependency, got %v", deps)
	}
	if deps[0].Name != "go-bin" {
		t.Fatalf("expected selected alternative go-bin, got %s", deps[0].Name)
	}
	if !deps[0].Make {
		t.Fatalf("expected selected alternative to remain a make dependency: %+v", deps[0])
	}
}

func TestResolveMissingDepsIncludesOptionalDependenciesForTarget(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "optional-feature optional\n")
	writeTestPackage(t, repo, "optional-feature", "")

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}

	if !containsString(missing, "optional-feature") {
		t.Fatalf("expected target optional dependency to be included, missing deps: %v", missing)
	}
}

func TestResolveMissingDepsRepairsDependenciesOfInstalledPackage(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "krb5\n")
	writeTestPackage(t, repo, "krb5", "e2fsprogs\nkeyutils\n")
	writeTestPackage(t, repo, "e2fsprogs", "")
	writeTestPackage(t, repo, "keyutils", "")
	if err := os.MkdirAll(filepath.Join(Installed, "krb5"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Installed, "krb5", "version"), []byte("1.22 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"e2fsprogs", "keyutils", "target"} {
		if !containsString(missing, name) {
			t.Fatalf("expected %s in repair plan, got %v", name, missing)
		}
	}
	if containsString(missing, "krb5") {
		t.Fatalf("installed package itself must not be scheduled: %v", missing)
	}
}

func TestResolveMissingDepsSkipsOptionalDependenciesForDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "regular-dep\n")
	writeTestPackage(t, repo, "regular-dep", "optional-feature optional\n")
	writeTestPackage(t, repo, "optional-feature", "")

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}

	if containsString(missing, "optional-feature") {
		t.Fatalf("dependency optional dependency should not be required, missing deps: %v", missing)
	}
}

func TestResolveBuildPlanIncludesOptionalDependenciesForTarget(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "optional-feature optional\n")
	writeTestPackage(t, repo, "optional-feature", "")

	plan, err := resolveBuildPlan([]string{"target"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.Order) != 2 || plan.Order[0] != "optional-feature" || plan.Order[1] != "target" {
		t.Fatalf("expected target optional dependency in build order, got %v", plan.Order)
	}
	if !containsString(plan.PostRebuilds["target"], "optional-feature") {
		t.Fatalf("expected target optional dependency to schedule inline rebuild, got %v", plan.PostRebuilds)
	}
}

func TestResolveBuildPlanSkipsOptionalDependenciesForDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "regular-dep\n")
	writeTestPackage(t, repo, "regular-dep", "optional-feature optional\n")
	writeTestPackage(t, repo, "optional-feature", "")

	plan, err := resolveBuildPlan([]string{"target"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	if containsString(plan.Order, "optional-feature") {
		t.Fatalf("dependency optional dependency should not be in build order, got %v", plan.Order)
	}
}

func TestResolveBuildPlanIncludesOptionalDependenciesForSourceBuiltDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "source-dep\n")
	writeTestPackage(t, repo, "source-dep", "optional-feature optional\n")
	writeTestPackage(t, repo, "optional-feature", "")

	plan, err := resolveBuildPlan([]string{"target", "source-dep"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !containsString(plan.Order, "optional-feature") {
		t.Fatalf("expected optional dependency for source-built dependency in build order, got %v", plan.Order)
	}
	if !containsString(plan.PostRebuilds["source-dep"], "optional-feature") {
		t.Fatalf("expected source-built dependency optional dep to schedule inline rebuild, got %v", plan.PostRebuilds)
	}
}

func TestPlannedBuildDisplayOrderFollowsExecutorOrderForOptionalCycle(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "cmake", "curl\n")
	writeTestPackage(t, repo, "curl", "brotli optional\n")
	writeTestPackage(t, repo, "brotli", "cmake make\n")

	plan, err := resolveBuildPlan([]string{"cmake", "curl"}, map[string]bool{"cmake": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := plannedBuildDisplayOrder(plan, cfg, true)
	want := []string{"curl", "cmake", "brotli", "curl (rebuild for brotli)"}
	if len(got) != len(want) {
		t.Fatalf("unexpected display order length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected display order: got %v want %v", got, want)
		}
	}
}

func TestOptionalSplitMakeDependencyTriggersSourceInstallBeforeRebuild(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_MULTILIB"] = "1"
	writeTestPackage(t, repo, "cmake", "curl\n")
	writeTestPackage(t, repo, "curl", "brotli optional\nlib32-brotli make optional\n")
	writeTestPackage(t, repo, "brotli", "cmake make\n")

	plan, err := resolveBuildPlan([]string{"cmake", "curl"}, map[string]bool{"cmake": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !containsString(plan.PostRebuilds["curl"], "brotli") {
		t.Fatalf("expected brotli to schedule curl rebuild, got %v", plan.PostRebuilds)
	}
	if !containsString(plan.PostRebuilds["curl"], "lib32-brotli") {
		t.Fatalf("expected lib32-brotli to be preserved for curl rebuild, got %v", plan.PostRebuilds)
	}

	splitDepsBySource := make(map[string][]string)
	addPostRebuildSplitDependencies(plan, splitDepsBySource)
	if !containsString(splitDepsBySource["brotli"], "lib32-brotli") {
		t.Fatalf("expected brotli build to install lib32-brotli before rebuild, got %v", splitDepsBySource)
	}

	got := plannedBuildDisplayOrder(plan, cfg, true)
	want := []string{"curl", "cmake", "brotli", "curl (rebuild for brotli,lib32-brotli)"}
	if len(got) != len(want) {
		t.Fatalf("unexpected display order length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected display order: got %v want %v", got, want)
		}
	}
}

func TestPlannedBuildDisplayOrderTreatsAvailableBinaryDepAsReady(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "binary-tool make\n")
	writeTestPackage(t, repo, "ready", "")
	writeTestPackage(t, repo, "binary-tool", "")

	tarball := filepath.Join(BinDir, StandardizeRemoteName("binary-tool", "1.0", "1", "x86_64", "optimized"))
	if err := os.WriteFile(tarball, []byte("cached binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := &BuildPlan{Order: []string{"target", "ready"}}
	got := plannedBuildDisplayOrder(plan, cfg, true)
	want := []string{"target", "ready"}
	if len(got) != len(want) {
		t.Fatalf("unexpected display order length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected display order: got %v want %v", got, want)
		}
	}
}

func TestResolveMissingDepsResolvesRuntimeDepsForAvailableBinaryDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "binary-dep\n")
	writeTestPackage(t, repo, "binary-dep", "deep-dep\nmake-dep make\n")
	writeTestPackage(t, repo, "deep-dep", "")
	writeTestPackage(t, repo, "make-dep", "")

	tarball := filepath.Join(BinDir, StandardizeRemoteName("binary-dep", "1.0", "1", "x86_64", "optimized"))
	if err := os.WriteFile(tarball, []byte("cached binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}

	if !containsString(missing, "deep-dep") {
		t.Fatalf("expected runtime dependency of binary package to be included, got %v", missing)
	}
	if containsString(missing, "make-dep") {
		t.Fatalf("make dependency of binary package should not be required, got %v", missing)
	}
	if !containsString(missing, "binary-dep") {
		t.Fatalf("expected binary-dep to be reported missing for binary install, got %v", missing)
	}
}

func TestBinaryRuntimeDependencySpecsPreferArchiveMetadata(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "binary-dep", "recipe-build-dep make\n")

	tarball := filepath.Join(BinDir, StandardizeRemoteName("binary-dep", "1.0", "1", "x86_64", "optimized"))
	writeTestBinaryTarballWithDepends(t, tarball, "binary-dep", "1.0", "1", "generated-runtime-dep\n")

	deps, err := binaryRuntimeDependencySpecs("binary-dep", cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "generated-runtime-dep" {
		t.Fatalf("expected archive runtime metadata, got %+v", deps)
	}
}

func TestResolveBinaryDependenciesUsesRemoteArchiveDependencyClosure(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "openal", "ffmpeg make\n")
	writeTestPackage(t, repo, "ffmpeg", "")
	writeTestPackage(t, repo, "libvdpau", "")
	writeInstalledTestPackage(t, "glibc")

	remote := []RepoEntry{
		{Name: "openal", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", Depends: []string{"ffmpeg"}},
		{Name: "ffmpeg", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", Depends: []string{"libvdpau"}},
		{Name: "libvdpau", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", Depends: []string{"glibc"}},
	}

	var plan []string
	if err := resolveBinaryDependencies("openal", make(map[string]bool), &plan, false, true, cfg, remote, true); err != nil {
		t.Fatal(err)
	}
	want := []string{"libvdpau", "ffmpeg", "openal"}
	if strings.Join(plan, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected binary dependency plan: got %v want %v", plan, want)
	}
}

func TestResolveBinaryDependenciesDoesNotFetchDependencyFreeIndexedPackage(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"

	remote := []RepoEntry{{
		Name:            "dependency-free",
		Version:         "1.0",
		Revision:        "1",
		Arch:            "x86_64",
		Variant:         "optimized",
		MetadataVersion: repoEntryMetadataVersion,
	}}

	var plan []string
	if err := resolveBinaryDependencies("dependency-free", make(map[string]bool), &plan, false, true, cfg, remote, true); err != nil {
		t.Fatal(err)
	}
	if len(plan) != 1 || plan[0] != "dependency-free" {
		t.Fatalf("unexpected binary dependency plan: %v", plan)
	}
}

func TestRuntimeOnlyAndSuggestDepsDoNotAffectSourceBuildGraph(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "build-dep\nruntime-dep runtime\nsuggested-dep suggest\n")
	writeTestPackage(t, repo, "build-dep", "")
	writeTestPackage(t, repo, "runtime-dep", "")
	writeTestPackage(t, repo, "suggested-dep", "")

	plan, err := resolveBuildPlan([]string{"target"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if containsString(plan.Order, "runtime-dep") {
		t.Fatalf("runtime-only dependency should not be in source build order, got %v", plan.Order)
	}
	if containsString(plan.Order, "suggested-dep") {
		t.Fatalf("suggested dependency should not be in source build order, got %v", plan.Order)
	}
	if !containsString(plan.Order, "build-dep") {
		t.Fatalf("regular dependency should remain in source build order, got %v", plan.Order)
	}

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}
	if containsString(missing, "runtime-dep") {
		t.Fatalf("runtime-only dependency should not be a source build prerequisite, got %v", missing)
	}
	if containsString(missing, "suggested-dep") {
		t.Fatalf("suggested dependency should not be a source build prerequisite, got %v", missing)
	}
}

func TestResolveMissingDepsIncludesMakeDepsForSourceFallback(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "glib", "meson make\n")
	writeTestPackage(t, repo, "meson", "")

	var missing []string
	if err := resolveMissingDeps("glib", map[string]bool{}, &missing, map[string]bool{"glib": true}, cfg, true); err != nil {
		t.Fatal(err)
	}
	if !containsString(missing, "meson") {
		t.Fatalf("expected source build prerequisite meson to be included, got %v", missing)
	}
}

func TestRequiredDevelPackageDetectionIncludesCrossOutputName(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_CROSS_SYSTEM"] = "1"
	cfg.Values["HOKUTO_CROSS_ARCH"] = "arm64"

	if !isRequiredDevelPackage("gcc", cfg) {
		t.Fatal("expected gcc to be recognized as a required devel package")
	}
	if !isRequiredDevelPackage("aarch64-gcc", cfg) {
		t.Fatal("expected cross output package name to be recognized as a required devel package")
	}
	if isRequiredDevelPackage("glib", cfg) {
		t.Fatal("did not expect normal package to be recognized as a required devel package")
	}
}

func TestSplitDependencySourceDiscoveredFromDependsSubpackage(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "systemd", "")
	if err := os.WriteFile(filepath.Join(repo, "systemd", "depends.systemd-libs"), []byte("libcap\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	source, ok := findSplitDependencySource("systemd-libs")
	if !ok || source != "systemd" {
		t.Fatalf("expected systemd-libs source to be systemd, got %q ok=%v", source, ok)
	}
}

func TestResolveBuildPlanUsesSplitDependencySource(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "systemd-libs\n")
	writeTestPackage(t, repo, "systemd", "")
	if err := os.WriteFile(filepath.Join(repo, "systemd", "depends.systemd-libs"), []byte("libcap\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeTestPackage(t, repo, "libcap", "")

	plan, err := resolveBuildPlan([]string{"target"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(plan.Order, "systemd") {
		t.Fatalf("expected systemd source to be scheduled for systemd-libs, got %v", plan.Order)
	}
}

func TestCollectSplitDependenciesForPlanMapsSourceOutputs(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "consumer", "systemd-libs\n")
	writeTestPackage(t, repo, "systemd", "")
	if err := os.WriteFile(filepath.Join(repo, "systemd", "depends.systemd-libs"), []byte("libcap\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := &BuildPlan{Order: []string{"systemd", "consumer"}}
	splitDeps := collectSplitDependenciesForPlan(plan, cfg)
	if !containsString(splitDeps["systemd"], "systemd-libs") {
		t.Fatalf("expected systemd to provide systemd-libs, got %v", splitDeps)
	}
}

func TestParallelCanBuildWaitsForSplitSource(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "consumer", "systemd-libs\n")
	writeTestPackage(t, repo, "systemd", "")
	if err := os.WriteFile(filepath.Join(repo, "systemd", "depends.systemd-libs"), []byte("libcap\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pm := &ParallelManager{
		Config:            cfg,
		BuildPlan:         &BuildPlan{Order: []string{"systemd", "consumer"}},
		Pending:           []string{"systemd", "consumer"},
		Running:           make(map[string]time.Time),
		Completed:         make(map[string]bool),
		Available:         make(map[string]bool),
		Failed:            make(map[string]error),
		SplitDepsBySource: map[string][]string{"systemd": {"systemd-libs"}},
	}

	if pm.canBuild("consumer") {
		t.Fatal("consumer should wait until systemd-libs is available from systemd")
	}
	pm.Completed["systemd"] = true
	pm.Available["systemd-libs"] = true
	if !pm.canBuild("consumer") {
		t.Fatal("consumer should build after systemd-libs is available")
	}
}

func TestRuntimeOnlyDepsRemainHardDepsForBinaryInstall(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "binary-pkg", "hard-dep\nruntime-dep runtime\nsuggested-dep suggest\nmake-dep make\n")
	writeTestPackage(t, repo, "hard-dep", "")
	writeTestPackage(t, repo, "runtime-dep", "")
	writeTestPackage(t, repo, "suggested-dep", "")
	writeTestPackage(t, repo, "make-dep", "")

	deps, err := binaryRuntimeDependencySpecs("binary-pkg", cfg, true)
	if err != nil {
		t.Fatal(err)
	}

	var plan []string
	if err := resolveDependencyList("binary-pkg", deps, map[string]bool{}, &plan, false, true, cfg, nil, false); err != nil {
		t.Fatal(err)
	}
	if !containsString(plan, "runtime-dep") {
		t.Fatalf("runtime-only dependency should be installed for binary packages, got %v", plan)
	}
	if !containsString(plan, "hard-dep") {
		t.Fatalf("regular hard dependency should be installed for binary packages, got %v", plan)
	}
	if containsString(plan, "suggested-dep") {
		t.Fatalf("suggested dependency should not be installed automatically, got %v", plan)
	}
	if containsString(plan, "make-dep") {
		t.Fatalf("make dependency should not be installed for binary packages, got %v", plan)
	}
}

func TestSuggestDependencyTextIsParsed(t *testing.T) {
	deps, err := parseDependsData([]byte("pulseaudio suggest ALSA support\npipewire>=1.0 suggest \"PipeWire backend\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	if !deps[0].Suggest || deps[0].SuggestText != "ALSA support" {
		t.Fatalf("expected pulseaudio suggest text, got %+v", deps[0])
	}
	if !deps[1].Suggest || deps[1].SuggestText != "PipeWire backend" {
		t.Fatalf("expected quoted pipewire suggest text, got %+v", deps[1])
	}
}

func TestFlushPackageSuggestionsPrintsSummaryWithText(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	_ = cfg

	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")

	writeInstalledTestPackage(t, "media-player")
	pkgDir := filepath.Join(Installed, "media-player")
	if err := os.WriteFile(filepath.Join(pkgDir, "suggests"), []byte("alsa-lib suggest ALSA support\njack2 suggest JACK output\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	packageSuggestions.Lock()
	packageSuggestions.items = make(map[string]map[string]packageSuggestion)
	packageSuggestions.Unlock()

	collectPackageSuggestions("media-player", rootDir)

	var out bytes.Buffer
	flushPackageSuggestions(&out, nil, false, false, false)
	got := out.String()
	if !strings.Contains(got, "Suggested optional runtime dependencies:") {
		t.Fatalf("expected summary heading, got %q", got)
	}
	if !strings.Contains(got, "media-player:") {
		t.Fatalf("expected package grouping, got %q", got)
	}
	if !strings.Contains(got, "alsa-lib - ALSA support") {
		t.Fatalf("expected suggestion text, got %q", got)
	}
	if !strings.Contains(got, "jack2 - JACK output") {
		t.Fatalf("expected second suggestion text, got %q", got)
	}
}

func TestFlushPackageSuggestionsSkipsUninstalledOwnerPackage(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	_ = cfg

	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")

	pkgDir := filepath.Join(Installed, "temporary-dep")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "suggests"), []byte("qt-svg suggest QtQuickVectorImage and svgtoqml\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	packageSuggestions.Lock()
	packageSuggestions.items = make(map[string]map[string]packageSuggestion)
	packageSuggestions.Unlock()

	collectPackageSuggestions("temporary-dep", rootDir)
	if err := os.RemoveAll(pkgDir); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	flushPackageSuggestions(&out, nil, false, false, false)
	if got := out.String(); got != "" {
		t.Fatalf("did not expect suggestions for uninstalled package, got %q", got)
	}
}

func TestFlushPackageSuggestionsSkipsAlreadyInstalledPromptInstall(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)

	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	writeInstalledTestPackage(t, "alsa-lib")
	writeInstalledTestPackage(t, "media-player")

	pkgDir := filepath.Join(Installed, "media-player")
	if err := os.WriteFile(filepath.Join(pkgDir, "suggests"), []byte("alsa-lib suggest ALSA support\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	packageSuggestions.Lock()
	packageSuggestions.items = make(map[string]map[string]packageSuggestion)
	packageSuggestions.Unlock()

	collectPackageSuggestions("media-player", rootDir)
	GlobalAssumeYes = true
	defer func() { GlobalAssumeYes = false }()

	var out bytes.Buffer
	flushPackageSuggestions(&out, cfg, true, true, true)
	if strings.Contains(out.String(), "Installing suggested dependency") {
		t.Fatalf("did not expect already-installed suggestion to be installed, got %q", out.String())
	}
}

func TestFlushPackageSuggestionsRechecksTemporaryInstalledDependency(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	_ = cfg

	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	writeInstalledTestPackage(t, "temporary-build-dep")
	writeInstalledTestPackage(t, "media-player")

	pkgDir := filepath.Join(Installed, "media-player")
	if err := os.WriteFile(filepath.Join(pkgDir, "suggests"), []byte("temporary-build-dep suggest Optional backend\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	discardPackageSuggestions()
	collectPackageSuggestions("media-player", rootDir)
	if err := os.RemoveAll(filepath.Join(Installed, "temporary-build-dep")); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	flushPackageSuggestions(&out, nil, false, false, false)
	if !strings.Contains(out.String(), "temporary-build-dep - Optional backend") {
		t.Fatalf("expected suggestion to be rechecked after temporary dependency cleanup, got %q", out.String())
	}
}

func TestBootstrapInstallSkipsRuntimeDependencyAutoInstall(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root
	cfg.Values["HOKUTO_BOOTSTRAP"] = "1"

	writeInstalledTestPackageWithDepends(t, "bootstrap-pkg", "missing-runtime-dep\n")

	if err := installMissingPackageRuntimeDependencies("bootstrap-pkg", cfg, nil, true, true); err != nil {
		t.Fatalf("bootstrap mode should not auto-install runtime dependencies: %v", err)
	}
}

func TestRuntimeDependencyAutoInstallSkipsInProgressDependency(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root

	writeInstalledTestPackageWithDepends(t, "lib32-systemd", "lib32-dbus\n")
	runtimeDependencyInstallInProgress.Store("lib32-dbus", true)
	defer runtimeDependencyInstallInProgress.Delete("lib32-dbus")

	if err := installMissingPackageRuntimeDependencies("lib32-systemd", cfg, nil, true, true); err != nil {
		t.Fatalf("in-progress runtime dependency should be skipped, got %v", err)
	}
}

func TestEnsurePackageInstalledSkipsInProgressDependency(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	runtimeDependencyInstallInProgress.Store("lib32-dbus", true)
	defer runtimeDependencyInstallInProgress.Delete("lib32-dbus")

	installed, err := ensurePackageInstalledWithSeen("lib32-dbus", cfg, true, nil)
	if err != nil {
		t.Fatalf("in-progress package install should be skipped, got %v", err)
	}
	if installed {
		t.Fatal("in-progress package should not report a new install")
	}
}

func TestRuntimeDependencyAutoInstallCanBeSuppressed(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root

	writeInstalledTestPackageWithDepends(t, "lib32-dbus", "lib32-systemd\n")
	suppressRuntimeDependencyAutoInstall.Add(1)
	defer suppressRuntimeDependencyAutoInstall.Add(-1)

	if err := installMissingPackageRuntimeDependencies("lib32-dbus", cfg, nil, true, true); err != nil {
		t.Fatalf("suppressed runtime dependency should be skipped, got %v", err)
	}
}

func TestBuildSkipsRuntimeDependencyWithoutBinary(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root

	writeTestPackage(t, repo, "mesa", "")
	writeInstalledTestPackageWithDepends(t, "libglvnd", "mesa runtime\n")
	defer binaryOnlyRuntimeDependencyInstallScope()()

	if err := installMissingPackageRuntimeDependencies("libglvnd", cfg, nil, true, true); err != nil {
		t.Fatalf("missing runtime-only binary should be skipped during a build: %v", err)
	}
	if isPackageInstalled("mesa") {
		t.Fatal("runtime-only dependency without a binary must not be built or installed")
	}
}

func TestEnsureDevelPackagesRequiresBinaryAvailability(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)

	_, err := ensureDevelPackagesInstalled(cfg, false, true)
	if err == nil {
		t.Fatal("expected missing devel binary to fail clearly")
	}
	if !strings.Contains(err.Error(), "required devel package") {
		t.Fatalf("expected required devel package error, got %v", err)
	}
}

func TestBinaryRuntimeDependencySpecsIncludeOnlyRuntimeDeps(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "meson", "python\nninja\npkgconf make\n")

	deps, err := binaryRuntimeDependencySpecs("meson", cfg, true)
	if err != nil {
		t.Fatal(err)
	}

	var runtimeDeps []string
	for _, dep := range deps {
		if dep.Make || dep.Optional || dep.Rebuild {
			continue
		}
		runtimeDeps = append(runtimeDeps, dep.Name)
	}

	if !containsString(runtimeDeps, "ninja") {
		t.Fatalf("expected ninja runtime dependency for meson, got %v", runtimeDeps)
	}
	if containsString(runtimeDeps, "pkgconf") {
		t.Fatalf("make dependency should not be treated as runtime dependency, got %v", runtimeDeps)
	}
}

func TestParallelPlanCollectsAvailableSplitMakeDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_MULTILIB"] = "1"
	writeTestPackage(t, repo, "nss", "nspr\nlib32-nspr make\n")
	writeTestPackage(t, repo, "nspr", "")

	tarball := filepath.Join(BinDir, StandardizeRemoteName("lib32-nspr", "4.39", "1", "x86_64", "optimized"))
	writeTestBinaryTarball(t, tarball, "lib32-nspr", "4.39", "1")

	plan := &BuildPlan{Order: []string{"nss"}}
	deps := collectAvailableBinaryDependenciesForPlan(plan, cfg, true)

	if len(deps) != 1 {
		t.Fatalf("expected one available binary dependency, got %v", deps)
	}
	if deps[0].Name != "lib32-nspr" || !deps[0].Make {
		t.Fatalf("expected lib32-nspr make dependency, got %+v", deps[0])
	}
}

func TestPrepareUpdateBuildPlanPreservesLib32OptionalSplitDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_MULTILIB"] = "1"
	writeTestPackage(t, repo, "curl", "brotli optional\nlib32-brotli make optional\n")
	writeTestPackage(t, repo, "brotli", "")

	plan, err := resolveBuildPlan([]string{"curl"}, map[string]bool{"curl": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	manual := map[string][]string{"curl": {"brotli"}}
	splitDeps := prepareUpdateBuildPlan(plan, plan.Order, manual, cfg)

	if !containsString(splitDeps["brotli"], "lib32-brotli") {
		t.Fatalf("expected update plan to install lib32-brotli from brotli, got %v", splitDeps)
	}
	if !containsString(plan.PostRebuilds["curl"], "lib32-brotli") {
		t.Fatalf("expected update plan to retain optional rebuild metadata, got %v", plan.PostRebuilds)
	}
	if len(plan.ManualPrereqs["curl"]) != 1 || plan.ManualPrereqs["curl"][0] != "brotli" {
		t.Fatalf("manual prerequisites were not retained: %v", plan.ManualPrereqs)
	}
}

func TestTemporaryUpdatePackagesKeepsRequestedAndPreexistingPackages(t *testing.T) {
	before := map[string]bool{"existing": true}
	after := map[string]bool{"existing": true, "target": true, "build-dep": true, "lib32-build-dep": true}
	requested := map[string]bool{"target": true}

	got := temporaryUpdatePackages(before, after, requested)
	want := []string{"build-dep", "lib32-build-dep"}
	if len(got) != len(want) {
		t.Fatalf("unexpected temporary packages: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected temporary packages: got %v want %v", got, want)
		}
	}
}

func TestMissingRepositoryBinaryPackagesChecksSplitOutputs(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "alpha", "")
	if err := os.WriteFile(filepath.Join(repo, "alpha", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "alpha", "depends.alpha-tools"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeTestPackage(t, repo, "beta", "")
	if err := os.WriteFile(filepath.Join(repo, "beta", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	betaTarball := filepath.Join(BinDir, StandardizeRemoteName("beta", "1.0", "1", "x86_64", "optimized"))
	if err := os.WriteFile(betaTarball, []byte("cached"), 0o644); err != nil {
		t.Fatal(err)
	}

	remote := []RepoEntry{{Name: "alpha", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized"}}
	missing, err := missingRepositoryBinaryPackages(cfg, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || len(missing["alpha"]) != 1 || missing["alpha"][0] != "alpha-tools" {
		t.Fatalf("expected only alpha's missing split output, got %v", missing)
	}
}

func TestRequestedInstalledSplitPackageResolvesToRepositorySource(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "cups", "")
	if err := os.WriteFile(filepath.Join(repo, "cups", "depends.libcups"), []byte("glibc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	installedSplit := filepath.Join(Installed, "libcups")
	if err := os.MkdirAll(filepath.Join(installedSplit, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installedSplit, "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	source, split, err := resolveRequestedBuildTarget("libcups")
	if err != nil {
		t.Fatal(err)
	}
	if !split || source != "cups" {
		t.Fatalf("expected installed libcups target to resolve to cups split source, got source=%q split=%v", source, split)
	}
}

func TestRepositoryBinaryStatusesRetainsPreviousRelease(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "alpha", "")
	if err := os.WriteFile(filepath.Join(repo, "alpha", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "alpha", "version"), []byte("2.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	remote := []RepoEntry{{Name: "alpha", Version: "1.5", Revision: "1", Arch: "x86_64", Variant: "optimized"}}
	statuses, err := repositoryBinaryStatuses(cfg, remote)
	if err != nil {
		t.Fatal(err)
	}
	status, ok := statuses["alpha"]
	if !ok {
		t.Fatalf("expected alpha to need a current binary, got %v", statuses)
	}
	if status.PreviousVersion != "1.5" || status.PreviousRev != "1" {
		t.Fatalf("unexpected previous release: %+v", status)
	}
	if got := binaryVersionTransition(status, "2.0", "1"); got != "1.5 -> 2.0" {
		t.Fatalf("unexpected version transition: %q", got)
	}
}

func TestBinaryVersionTransitionShowsRevisionUpdate(t *testing.T) {
	status := repositoryBinaryStatus{PreviousVersion: "1.5", PreviousRev: "1"}
	if got := binaryVersionTransition(status, "1.5", "2"); got != "1.5-1 -> 1.5-2" {
		t.Fatalf("unexpected revision transition: %q", got)
	}
}

func TestScanInstalledPackageIntegrityFindsMissingManifestPaths(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root

	pkgDir := filepath.Join(Installed, "example")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "present"), []byte("ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-target", filepath.Join(root, "usr", "bin", "present-link")); err != nil {
		t.Fatal(err)
	}
	manifest := "/usr/\n/usr/bin/\n/usr/bin/present abc123\n/usr/bin/present-link 000000\n/usr/bin/missing def456\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	issues, err := scanInstalledPackageIntegrity("example", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 1 || issues[0].Package != "example" {
		t.Fatalf("expected one affected package, got %+v", issues)
	}
	if len(issues[0].Missing) != 1 || issues[0].Missing[0] != "/usr/bin/missing" {
		t.Fatalf("unexpected missing paths: %v", issues[0].Missing)
	}
}

func TestParallelBuildMarksSplitOutputsAvailable(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_MULTILIB"] = "1"
	writeTestPackage(t, repo, "libxcb", "")
	writeTestPackage(t, repo, "libx11", "lib32-libxcb make\n")

	splitDepsBySource := map[string][]string{
		"libxcb": {"lib32-libxcb"},
	}
	plan := &BuildPlan{
		Order:             []string{"libxcb", "libx11"},
		SkippedPackages:   make(map[string]string),
		RebuildPackages:   make(map[string]bool),
		PostRebuilds:      make(map[string][]string),
		PostBuildRebuilds: make(map[string][]string),
	}
	pm := &ParallelManager{
		MaxJobs:           2,
		Config:            cfg,
		BuildPlan:         plan,
		Pending:           append([]string(nil), plan.Order...),
		Running:           make(map[string]time.Time),
		Completed:         make(map[string]bool),
		Available:         make(map[string]bool),
		Failed:            make(map[string]error),
		LogFiles:          make(map[string]*os.File),
		SplitDepsBySource: splitDepsBySource,
		resultChan:        make(chan buildResult, 2),
		promptPause:       make(chan bool),
		promptAck:         make(chan struct{}),
		AutoYes:           true,
	}
	pm.Builder = func(string, *Config, *Executor, BuildOptions) (time.Duration, error) {
		return time.Millisecond, nil
	}
	pm.Installer = func(pkg string, _ io.Writer) (parallelInstallResult, error) {
		available := []string{pkg}
		available = append(available, splitDepsBySource[pkg]...)
		return parallelInstallResult{Available: available}, nil
	}

	if err := pm.Run(); err != nil {
		t.Fatalf("parallel build should wait for split output availability: %v", err)
	}
	if !pm.Completed["libx11"] {
		t.Fatalf("expected libx11 to build after libxcb provided lib32-libxcb; completed=%v", pm.Completed)
	}
	if !pm.Available["lib32-libxcb"] {
		t.Fatalf("expected lib32-libxcb to be marked available; available=%v", pm.Available)
	}
}

func TestPrepareDependencyProgressLogOutputTerminatesActiveLine(t *testing.T) {
	oldStderr := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writePipe
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = readPipe.Close()
		_ = writePipe.Close()
	})

	bar := newDependencyInstallProgress(2, "Installing Build Dependencies", true)
	deactivate := activateDependencyInstallProgress(bar)
	describeDependencyInstallProgress(bar, "wget")
	if err := bar.Add(1); err != nil {
		t.Fatal(err)
	}
	prepareDependencyProgressLogOutput()
	deactivate()

	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = oldStderr
	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(output, []byte("\n")) {
		t.Fatalf("active dependency progress line was not terminated: %q", output)
	}
}

func TestParallelBuildRecoversSplitMappingsOmittedByEarlyBinaryCheck(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_MULTILIB"] = "1"
	writeTestPackage(t, repo, "fluidsynth", "")
	writeTestPackage(t, repo, "sdl2-compat", "")
	writeTestPackage(t, repo, "openal", "lib32-fluidsynth make\n")
	writeTestPackage(t, repo, "mpg123", "lib32-sdl2-compat make\n")
	for pkg, split := range map[string]string{
		"fluidsynth":  "lib32-fluidsynth",
		"sdl2-compat": "lib32-sdl2-compat",
	} {
		if err := os.WriteFile(filepath.Join(repo, pkg, "depends."+split), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	plan := &BuildPlan{
		Order:             []string{"fluidsynth", "sdl2-compat", "openal", "mpg123"},
		SkippedPackages:   make(map[string]string),
		RebuildPackages:   make(map[string]bool),
		PostRebuilds:      make(map[string][]string),
		PostBuildRebuilds: make(map[string][]string),
	}
	// This starts empty to model the early dependency pass accepting already
	// available split binaries without recording their source relationship.
	splitDepsBySource := make(map[string][]string)
	addPlanSplitDependencies(plan, splitDepsBySource, cfg)

	pm := &ParallelManager{
		MaxJobs:           4,
		Config:            cfg,
		BuildPlan:         plan,
		Pending:           append([]string(nil), plan.Order...),
		Running:           make(map[string]time.Time),
		Completed:         make(map[string]bool),
		Available:         make(map[string]bool),
		Failed:            make(map[string]error),
		LogFiles:          make(map[string]*os.File),
		SplitDepsBySource: splitDepsBySource,
		resultChan:        make(chan buildResult, 4),
		promptPause:       make(chan bool),
		promptAck:         make(chan struct{}),
		AutoYes:           true,
	}
	pm.Builder = func(string, *Config, *Executor, BuildOptions) (time.Duration, error) {
		return time.Millisecond, nil
	}
	pm.Installer = func(pkg string, _ io.Writer) (parallelInstallResult, error) {
		available := append([]string{pkg}, splitDepsBySource[pkg]...)
		return parallelInstallResult{Available: available}, nil
	}

	if err := pm.Run(); err != nil {
		t.Fatalf("parallel build should publish split outputs recovered from the final plan: %v", err)
	}
	for _, pkg := range []string{"openal", "mpg123"} {
		if !pm.Completed[pkg] {
			t.Fatalf("expected %s to build after its split dependency became available; completed=%v available=%v", pkg, pm.Completed, pm.Available)
		}
	}
}

func TestParallelBuildRunsReadyOptionalRebuild(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "systemd", "")
	writeTestPackage(t, repo, "btrfs-progs", "")
	writeTestPackage(t, repo, "cryptsetup", "")
	writeTestPackage(t, repo, "shadow", "")

	plan := &BuildPlan{
		Order:             []string{"systemd", "btrfs-progs", "cryptsetup", "shadow"},
		SkippedPackages:   make(map[string]string),
		RebuildPackages:   make(map[string]bool),
		PostRebuilds:      map[string][]string{"systemd": {"btrfs-progs", "cryptsetup", "shadow"}},
		PostBuildRebuilds: make(map[string][]string),
	}
	pm := &ParallelManager{
		MaxJobs:     1,
		Config:      cfg,
		BuildPlan:   plan,
		Pending:     append([]string(nil), plan.Order...),
		Running:     make(map[string]time.Time),
		Completed:   make(map[string]bool),
		Available:   make(map[string]bool),
		Failed:      make(map[string]error),
		LogFiles:    make(map[string]*os.File),
		resultChan:  make(chan buildResult, 1),
		promptPause: make(chan bool),
		promptAck:   make(chan struct{}),
		AutoYes:     true,
	}
	buildCounts := make(map[string]int)
	pm.Builder = func(pkg string, _ *Config, _ *Executor, _ BuildOptions) (time.Duration, error) {
		buildCounts[pkg]++
		return time.Millisecond, nil
	}
	pm.Installer = func(pkg string, _ io.Writer) (parallelInstallResult, error) {
		return parallelInstallResult{Available: []string{pkg}}, nil
	}

	if err := pm.Run(); err != nil {
		t.Fatalf("parallel build should run optional rebuild after deps are available: %v", err)
	}
	if buildCounts["systemd"] != 2 {
		t.Fatalf("expected systemd to build once and rebuild once, counts=%v", buildCounts)
	}
	if len(plan.PostRebuilds) != 0 {
		t.Fatalf("expected post rebuild to be consumed, got %v", plan.PostRebuilds)
	}
}

func TestParallelBuildDefersUserRequestedLeafInstall(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "sabnzbd", "")

	pm := &ParallelManager{
		Config:            cfg,
		BuildPlan:         &BuildPlan{Order: []string{"sabnzbd"}, PostBuildRebuilds: make(map[string][]string)},
		Pending:           nil,
		Running:           make(map[string]time.Time),
		UserRequested:     map[string]bool{"sabnzbd": true},
		AutoInstall:       false,
		SplitDepsBySource: make(map[string][]string),
	}

	if !pm.shouldDeferInstallLocked("sabnzbd") {
		t.Fatal("expected user-requested leaf package to defer installation")
	}
}

func TestParallelBuildInstallsUserRequestedDependencyImmediately(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "libfoo", "")
	writeTestPackage(t, repo, "app", "libfoo\n")

	pm := &ParallelManager{
		Config:            cfg,
		BuildPlan:         &BuildPlan{Order: []string{"libfoo", "app"}, PostBuildRebuilds: make(map[string][]string)},
		Pending:           []string{"app"},
		Running:           make(map[string]time.Time),
		UserRequested:     map[string]bool{"libfoo": true, "app": true},
		AutoInstall:       false,
		SplitDepsBySource: make(map[string][]string),
	}

	if pm.shouldDeferInstallLocked("libfoo") {
		t.Fatal("expected user-requested package needed by another build to install immediately")
	}
}

func TestAcceptedBinaryBuildDepIsNotOfferedRepeatedly(t *testing.T) {
	declined := make(map[string]bool)
	declined["binary-dep"] = true

	plan := &BuildPlan{
		Order:             []string{"binary-dep", "target"},
		SkippedPackages:   make(map[string]string),
		RebuildPackages:   make(map[string]bool),
		PostRebuilds:      make(map[string][]string),
		PostBuildRebuilds: make(map[string][]string),
	}

	installed, err := installAvailableBinaryBuildDeps(plan, map[string]bool{"target": true}, declined, &Config{Values: map[string]string{}}, func(string) {}, true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if installed {
		t.Fatal("previously accepted binary dependency should not be offered again")
	}
}

func TestPackageHasSelfBuildDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "python-build", "python-build make\n")
	writeTestPackage(t, repo, "normal", "normal runtime\n")
	writeTestPackage(t, repo, "java-openjdk-17", "java-openjdk==17* make\n")
	if err := os.WriteFile(filepath.Join(repo, "java-openjdk-17", "version"), []byte("17.0.20+7 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	registerParallelPackageName("java-openjdk-17", "java-openjdk")
	registerParallelPackageVersion("java-openjdk-17", "17.0.20+7")

	if !packageHasSelfBuildDependency("python-build", cfg) {
		t.Fatal("expected python-build make self-edge to require binary bootstrapping")
	}
	if !packageHasSelfBuildDependency("java-openjdk-17", cfg) {
		t.Fatal("expected constrained canonical self-edge to bootstrap historical java-openjdk-17")
	}
	if packageHasSelfBuildDependency("normal", cfg) {
		t.Fatal("runtime-only self-edge must not be treated as a build bootstrap")
	}
}

func TestParallelCanBuildHistoricalPackageWithInstalledSelfBootstrap(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "java-openjdk-17", "java-openjdk==17* make\n")
	if err := os.WriteFile(filepath.Join(repo, "java-openjdk-17", "version"), []byte("17.0.20+7 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	registerParallelPackageName("java-openjdk-17", "java-openjdk")
	registerParallelPackageVersion("java-openjdk-17", "17.0.20+7")

	writeInstalledTestPackage(t, "java-openjdk-17")
	if err := os.WriteFile(filepath.Join(Installed, "java-openjdk-17", "version"), []byte("17.0.20+7 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pm := &ParallelManager{
		Config:            cfg,
		BuildPlan:         &BuildPlan{Order: []string{"java-openjdk-17"}},
		Pending:           []string{"java-openjdk-17"},
		Running:           make(map[string]time.Time),
		Completed:         make(map[string]bool),
		Available:         make(map[string]bool),
		Failed:            make(map[string]error),
		SplitDepsBySource: make(map[string][]string),
	}

	if !pm.canBuild("java-openjdk-17") {
		t.Fatal("installed java-openjdk-17 bootstrap should satisfy its pending constrained self dependency")
	}
}

func TestDependencyBinaryAvailableUsesCurrentVersionVariantFallback(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "cmake", "")

	currentGeneric := filepath.Join(BinDir, StandardizeRemoteName("cmake", "1.0", "1", "x86_64", "generic"))
	if err := os.WriteFile(currentGeneric, []byte("cached binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if !dependencyBinaryAvailable("cmake", cfg, true) {
		t.Fatal("expected current generic tarball to satisfy optimized local binary lookup")
	}

	if err := os.Remove(currentGeneric); err != nil {
		t.Fatal(err)
	}
	oldGeneric := filepath.Join(BinDir, StandardizeRemoteName("cmake", "0.9", "1", "x86_64", "generic"))
	if err := os.WriteFile(oldGeneric, []byte("old cached binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	if dependencyBinaryAvailable("cmake", cfg, true) {
		t.Fatal("old cached tarball should not satisfy current dependency binary lookup")
	}
}

func TestBuildDependencyFallsBackToNewestOlderBinary(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "gcc", "")
	if err := os.WriteFile(filepath.Join(repo, "gcc", "version"), []byte("15.2.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	older := filepath.Join(BinDir, StandardizeRemoteName("gcc", "14.3.0", "2", "x86_64", "optimized"))
	writeTestBinaryTarball(t, older, "gcc", "14.3.0", "2")
	oldest := filepath.Join(BinDir, StandardizeRemoteName("gcc", "13.4.0", "1", "x86_64", "optimized"))
	writeTestBinaryTarball(t, oldest, "gcc", "13.4.0", "1")

	if _, _, exact, err := availableBinaryPackageTarball("gcc", cfg, true); err != nil || exact {
		t.Fatalf("normal package lookup must remain exact: exact=%v err=%v", exact, err)
	}
	name, got, ok, err := availableBuildDependencyBinaryTarball("gcc", cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || name != "gcc" || got != older {
		t.Fatalf("expected newest older GCC binary %s, got name=%s path=%s ok=%v", older, name, got, ok)
	}
}

func TestResolveBuildPlanDoesNotRecurseIntoInstalledDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "target", "installed-dep\n")
	writeTestPackage(t, repo, "installed-dep", "deep-dep\n")
	writeTestPackage(t, repo, "deep-dep", "")
	writeInstalledTestPackage(t, "installed-dep")

	plan, err := resolveBuildPlan([]string{"target"}, map[string]bool{"target": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(plan.Order) != 1 || plan.Order[0] != "target" {
		t.Fatalf("expected installed dependency to be treated as a satisfied leaf, got %v", plan.Order)
	}
}

func TestInstalledVersionedPackageDoesNotSatisfyUnconstrainedBaseDependency(t *testing.T) {
	withTempDependencyRepo(t)
	writeInstalledTestPackage(t, "libsigc++-2")
	if err := os.WriteFile(filepath.Join(Installed, "libsigc++-2", "version"), []byte("2.12.2 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if sat := findInstalledSatisfying("libsigc++", "", ""); sat != "" {
		t.Fatalf("unconstrained libsigc++ should not be satisfied by versioned package, got %s", sat)
	}
	if sat := findInstalledSatisfying("libsigc++", "<", "3"); sat != "libsigc++-2" {
		t.Fatalf("constrained libsigc++ <3 should be satisfied by libsigc++-2, got %s", sat)
	}
}

func TestVersionedSourceSatisfiesConstrainedBuildDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "pulseaudio", "webrtc-audio-processing<2.0\n")
	writeTestPackage(t, repo, "webrtc-audio-processing-1", "")

	plan, err := resolveBuildPlan([]string{"pulseaudio"}, map[string]bool{"pulseaudio": true}, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(plan.Order, "webrtc-audio-processing-1") {
		t.Fatalf("expected versioned source package in build order, got %v", plan.Order)
	}
	if containsString(plan.Order, "webrtc-audio-processing") {
		t.Fatalf("logical dependency name should resolve to versioned source, got %v", plan.Order)
	}

	deps, err := parseDependsFile(filepath.Join(repo, "pulseaudio"))
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := resolvedBuildDependencyCandidates(deps[0], false, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != "webrtc-audio-processing-1" {
		t.Fatalf("parallel scheduler resolved candidates %v", candidates)
	}
}

func TestInstalledDependentsFindsPackagesUsingDependency(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	if err := os.MkdirAll(Installed, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Values["HOKUTO_ROOT"] = root

	writeInstalledTestPackageWithDepends(t, "libgcrypt", "")
	writeInstalledTestPackageWithDepends(t, "systemd", "libgcrypt\n")

	dependents := installedDependents("libgcrypt", cfg, nil)
	if len(dependents) != 1 || dependents[0] != "systemd" {
		t.Fatalf("expected systemd to depend on libgcrypt, got %v", dependents)
	}
}

func TestBuildPickHelperMovesFilesToSplitRoot(t *testing.T) {
	tmp := t.TempDir()
	helperDir := filepath.Join(tmp, "tools")
	outputDir := filepath.Join(tmp, "output")
	splitRoot := filepath.Join(tmp, "split")
	filePath := filepath.Join(outputDir, "usr", "lib", "libRusticlOpenCL.so")

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildHelperScripts(helperDir); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(filepath.Join(helperDir, "_pick"), "opencl-mesa", "usr/lib/libRusticlOpenCL.so")
	cmd.Dir = outputDir
	cmd.Env = append(os.Environ(),
		"HOKUTO_OUTPUT_DIR="+outputDir,
		"HOKUTO_SPLIT_DIR="+splitRoot,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("_pick failed: %v\n%s", err, out)
	}

	splitPath := filepath.Join(splitRoot, "opencl-mesa", "usr", "lib", "libRusticlOpenCL.so")
	if _, err := os.Stat(splitPath); err != nil {
		t.Fatalf("expected split payload at %s: %v", splitPath, err)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("expected original payload to be moved, stat err: %v", err)
	}
}

func TestBuildPickHelperMovesFilesFromStagedDestdir(t *testing.T) {
	tmp := t.TempDir()
	helperDir := filepath.Join(tmp, "tools")
	outputDir := filepath.Join(tmp, "output")
	stagedDir := filepath.Join(tmp, "destdir")
	splitRoot := filepath.Join(tmp, "split")

	x64File := filepath.Join(outputDir, "usr", "lib", "libfoo.so")
	lib32File := filepath.Join(stagedDir, "usr", "lib32", "libfoo.so")
	for _, p := range []string{x64File, lib32File} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(x64File, []byte("x64"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib32File, []byte("lib32"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildHelperScripts(helperDir); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(filepath.Join(helperDir, "_pick"), stagedDir, "lib32-foo", "usr/lib32/libfoo*")
	cmd.Dir = outputDir
	cmd.Env = append(os.Environ(),
		"HOKUTO_OUTPUT_DIR="+outputDir,
		"HOKUTO_SPLIT_DIR="+splitRoot,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("_pick failed: %v\n%s", err, out)
	}

	splitPath := filepath.Join(splitRoot, "lib32-foo", "usr", "lib32", "libfoo.so")
	if _, err := os.Stat(splitPath); err != nil {
		t.Fatalf("expected staged split payload at %s: %v", splitPath, err)
	}
	if _, err := os.Stat(x64File); err != nil {
		t.Fatalf("expected x64 output payload to remain in place: %v", err)
	}
	if _, err := os.Stat(lib32File); !os.IsNotExist(err) {
		t.Fatalf("expected staged payload to be moved, stat err: %v", err)
	}
}

func TestBuildPickHelperPreservesCompleteSONAMESymlinkChain(t *testing.T) {
	tmp := t.TempDir()
	helperDir := filepath.Join(tmp, "tools")
	stagedDir := filepath.Join(tmp, "destdir")
	splitRoot := filepath.Join(tmp, "split")
	libDir := filepath.Join(stagedDir, "usr", "lib32")

	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libfoo.so.0.3.0"), []byte("library"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libfoo.so.0.3.0", filepath.Join(libDir, "libfoo.so.3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libfoo.so.3", filepath.Join(libDir, "libfoo.so")); err != nil {
		t.Fatal(err)
	}
	if err := writeBuildHelperScripts(helperDir); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(filepath.Join(helperDir, "_pick"), stagedDir, "lib32-foo", "usr/lib32/libfoo.so*")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "HOKUTO_SPLIT_DIR="+splitRoot)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("_pick failed: %v\n%s", err, out)
	}

	splitLibDir := filepath.Join(splitRoot, "lib32-foo", "usr", "lib32")
	for _, name := range []string{"libfoo.so", "libfoo.so.3", "libfoo.so.0.3.0"} {
		if _, err := os.Lstat(filepath.Join(splitLibDir, name)); err != nil {
			t.Fatalf("expected %s in split package: %v", name, err)
		}
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(splitLibDir, "libfoo.so"))
	if err != nil {
		t.Fatalf("split SONAME chain is broken: %v", err)
	}
	if resolved != filepath.Join(splitLibDir, "libfoo.so.0.3.0") {
		t.Fatalf("unexpected SONAME target: %s", resolved)
	}
}

func TestCleanPackagedOutputRemovesStaticLibrariesByDefault(t *testing.T) {
	tmp := t.TempDir()
	staticLib := filepath.Join(tmp, "usr", "lib", "libfoo.a")
	sharedLib := filepath.Join(tmp, "usr", "lib", "libfoo.so")
	if err := os.MkdirAll(filepath.Dir(staticLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staticLib, []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sharedLib, []byte("shared"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanPackagedOutput(tmp, NewExecutor(context.Background()), map[string]bool{})

	if _, err := os.Stat(staticLib); !os.IsNotExist(err) {
		t.Fatalf("expected static library to be removed, stat err: %v", err)
	}
	if _, err := os.Stat(sharedLib); err != nil {
		t.Fatalf("expected shared library to remain: %v", err)
	}
}

func TestCleanPackagedOutputKeepsStaticLibrariesWhenEnabled(t *testing.T) {
	tmp := t.TempDir()
	staticLib := filepath.Join(tmp, "usr", "lib", "libfoo.a")
	if err := os.MkdirAll(filepath.Dir(staticLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staticLib, []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanPackagedOutput(tmp, NewExecutor(context.Background()), map[string]bool{"staticlibs": true})

	if _, err := os.Stat(staticLib); err != nil {
		t.Fatalf("expected static library to remain with staticlibs option: %v", err)
	}
}

func TestLoadSplitPackagePostBuildOptionsAppliesSubpackageOverrides(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "options.lib32-foo"), []byte("nostrip staticlibs nolto\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	options := loadSplitPackagePostBuildOptions(tmp, "lib32-foo", "lib32-foo", map[string]bool{})

	if !options["nostrip"] {
		t.Fatal("expected nostrip from options.lib32-foo")
	}
	if !options["staticlibs"] {
		t.Fatal("expected staticlibs from options.lib32-foo")
	}
	if options["nolto"] {
		t.Fatal("expected build-only option nolto to be ignored for split package overrides")
	}
}

func TestLoadSplitPackagePostBuildOptionsInheritsParentOptions(t *testing.T) {
	tmp := t.TempDir()
	parentOptions := map[string]bool{"binary": true, "staticlibs": true}

	options := loadSplitPackagePostBuildOptions(tmp, "lib32-foo", "lib32-foo", parentOptions)

	if !options["binary"] {
		t.Fatal("expected parent binary option to be preserved")
	}
	if !options["staticlibs"] {
		t.Fatal("expected parent staticlibs option to be preserved")
	}
}

func TestHokutoMesonHelpersRunMesonSetupWithDefaults(t *testing.T) {
	tmp := t.TempDir()
	helperDir := filepath.Join(tmp, "tools")
	fakeBin := filepath.Join(tmp, "fakebin")
	sourceDir := filepath.Join(tmp, "src")

	if err := writeBuildHelperScripts(helperDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "meson.build"), []byte("project('demo', 'c')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeMeson := filepath.Join(fakeBin, "meson")
	fakeMesonScript := `#!/bin/sh
printf '%s\n' "$@" > "$MESON_ARGS_FILE"
`
	if err := os.WriteFile(fakeMeson, []byte(fakeMesonScript), 0o755); err != nil {
		t.Fatal(err)
	}

	runHelper := func(t *testing.T, helper string, want []string) {
		t.Helper()
		argsFile := filepath.Join(tmp, helper+"-args")
		cmd := exec.Command(filepath.Join(helperDir, helper), "build", sourceDir, "-Dfoo=bar")
		cmd.Dir = tmp
		cmd.Env = append(os.Environ(),
			"PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"MESON_ARGS_FILE="+argsFile,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", helper, err, out)
		}

		data, err := os.ReadFile(argsFile)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(args) != len(want) {
			t.Fatalf("unexpected %s args length:\ngot  %v\nwant %v", helper, args, want)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Fatalf("unexpected %s args:\ngot  %v\nwant %v", helper, args, want)
			}
		}
	}

	commonPrefix := []string{
		"setup",
		"--prefix",
		"/usr",
		"--libexecdir",
	}
	commonSuffix := []string{
		"--sbindir",
		"bin",
		"--buildtype",
		"plain",
		"--wrap-mode",
		"nodownload",
	}
	commonFinal := []string{
		"-D",
		"b_pie=true",
		"-D",
		"b_ndebug=true",
		"-D",
		"python.bytecompile=1",
		"build",
		sourceDir,
		"-Dfoo=bar",
	}

	wantMeson := append(append(append([]string{}, commonPrefix...), "lib"), commonSuffix...)
	wantMeson = append(wantMeson, commonFinal...)
	runHelper(t, "hokuto-meson", wantMeson)

	wantMeson32 := append(append(append([]string{}, commonPrefix...), "lib32"), commonSuffix...)
	wantMeson32 = append(wantMeson32, "--cross-file", "lib32")
	wantMeson32 = append(wantMeson32, commonFinal...)
	runHelper(t, "hokuto-meson-32", wantMeson32)
}

func TestInstalledPackageSizeCountsManifestPayload(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	rootDir = root
	cfg.Values["HOKUTO_ROOT"] = root

	pkgDir := filepath.Join(Installed, "demo")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	payloadA := filepath.Join(root, "usr", "bin", "demo")
	payloadB := filepath.Join(root, "usr", "lib", "libdemo.so")
	for _, p := range []string{payloadA, payloadB} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(payloadA, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadB, []byte("1234567"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := "/usr/bin/demo abc\n/usr/lib/libdemo.so def\n/var/db/hokuto/installed/demo/manifest meta\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	total, counted, missing, err := installedPackageSize("demo")
	if err != nil {
		t.Fatal(err)
	}
	if total != 12 || counted != 2 || missing != 0 {
		t.Fatalf("unexpected package size total=%d counted=%d missing=%d", total, counted, missing)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
