package hokuto

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyPackageRecipeMetadataIncludesSources(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "pkg")
	installedDir := filepath.Join(tmp, "installed")

	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"version": "1.0 1\n",
		"sources": "https://example.com/source.tar.xz\n",
		"build":   "#!/bin/sh\n",
		"options": "binary\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	execCtx := &Executor{Context: context.Background(), Stdout: io.Discard, Stderr: io.Discard}
	if err := copyPackageRecipeMetadata(pkgDir, installedDir, execCtx); err != nil {
		t.Fatal(err)
	}

	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(installedDir, name))
		if err != nil {
			t.Fatalf("expected %s to be copied: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("unexpected %s contents: got %q want %q", name, string(got), want)
		}
	}
}

func TestPlannedPackageRequiresSourceBuildForSplitOutput(t *testing.T) {
	plan := &BuildPlan{RebuildPackages: map[string]bool{}}
	if plannedPackageRequiresSourceBuild("gstreamer", plan, nil, nil) {
		t.Fatal("ordinary dependency may reuse its parent binary")
	}
	if !plannedPackageRequiresSourceBuild("gstreamer", plan, map[string]bool{"gstreamer": true}, nil) {
		t.Fatal("explicitly requested source package must build from source")
	}
	if !plannedPackageRequiresSourceBuild("gstreamer", plan, nil, map[string][]string{"gstreamer": {"gst-plugins-bad"}}) {
		t.Fatal("source package required to produce a split output must build from source")
	}
}

// A recipe requested for a cross-system build is planned under the name of
// the package it produces, the one its cross dependents use, so it is built
// once (two builds of aarch64-libxv at once corrupted its archive).
func TestNormalizeCrossSystemTargets(t *testing.T) {
	repo := t.TempDir()
	for _, name := range []string{"libxv", "gstreamer"} {
		if err := os.MkdirAll(filepath.Join(repo, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name, "version"), []byte("1 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldRepoPaths := repoPaths
	repoPaths = repo
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	in := []string{"libxv", "aarch64-gstreamer", "libcups", "nvidia~linux"}
	system := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64", "HOKUTO_CROSS_SYSTEM": "1"}}
	got := normalizeCrossSystemTargets(in, system)
	want := []string{"aarch64-libxv", "aarch64-gstreamer", "libcups", "nvidia~linux"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("system targets = %v, want %v", got, want)
	}
	plain := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}}
	if got := normalizeCrossSystemTargets(in, plain); strings.Join(got, " ") != strings.Join(in, " ") {
		t.Fatalf("plain cross targets changed: %v", got)
	}
}

// A plain -cross=arm64 build needing a sysroot split (aarch64-libelf) must
// look for its generic archive, as it was published; its own native arm64
// packages stay optimized.
func TestSplitPackageIsGenericForSysrootSplits(t *testing.T) {
	plainCross := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64", "CFLAGS_ARM64": "-mcpu=cortex-a72"}}
	if !splitPackageIsGeneric("aarch64-libelf", "aarch64", plainCross, map[string]bool{}) {
		t.Fatal("aarch64-libelf looked up as optimized")
	}
	if splitPackageIsGeneric("libelf", "aarch64", plainCross, map[string]bool{}) {
		t.Fatal("native arm64 libelf looked up as generic")
	}
}
