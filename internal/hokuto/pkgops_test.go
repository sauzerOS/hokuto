package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitPackageSourceNameHonorsFilenameOverride(t *testing.T) {
	tests := []struct {
		raw      string
		override string
		want     string
	}{
		{"git+https://example.com/org/glslang.git#first", "", "glslang"},
		{"git+https://example.com/org/glslang.git#first", "glslang-first", "glslang-first"},
		{"git+https://example.com/org/glslang.git#second", "glslang-second", "glslang-second"},
	}
	for _, test := range tests {
		got, err := gitPackageSourceName(test.raw, test.override)
		if err != nil {
			t.Fatalf("gitPackageSourceName(%q, %q): %v", test.raw, test.override, err)
		}
		if got != test.want {
			t.Fatalf("gitPackageSourceName(%q, %q) = %q, want %q", test.raw, test.override, got, test.want)
		}
	}
}

func TestGitPackageSourceNameRejectsPathOverride(t *testing.T) {
	if _, err := gitPackageSourceName("git+https://example.com/org/repo.git#ref", "../repo"); err == nil {
		t.Fatal("expected path-like Git source override to be rejected")
	}
}

func TestCopyDirContentsFallbackPreservesSymlinks(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	dst := filepath.Join(tmp, "dst")

	if err := os.MkdirAll(filepath.Join(src, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "dir", "real.txt"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir/real.txt", filepath.Join(src, "link.txt")); err != nil {
		t.Fatal(err)
	}

	if err := copyDirContentsFallback(src, dst); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(dst, "link.txt")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s to be a symlink, mode is %s", linkPath, info.Mode())
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "dir/real.txt" {
		t.Fatalf("unexpected symlink target: got %q", target)
	}
}

func TestCopyDirContentsFallbackFollowsRootSymlink(t *testing.T) {
	tmp := t.TempDir()
	checkout := filepath.Join(tmp, "checkout")
	srcLink := filepath.Join(tmp, "glibc")
	dst := filepath.Join(tmp, "build")

	if err := os.MkdirAll(filepath.Join(checkout, "sysdeps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "configure"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "sysdeps", "file.c"), []byte("int main(void){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(checkout, srcLink); err != nil {
		t.Fatal(err)
	}

	if err := copyDirContentsFallback(srcLink, dst); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"configure", filepath.Join("sysdeps", "file.c")} {
		if _, err := os.Stat(filepath.Join(dst, rel)); err != nil {
			t.Fatalf("expected %s to be copied through root symlink: %v", rel, err)
		}
	}
}

func TestLibraryPathMatchesDepHonorsABI(t *testing.T) {
	elf64, ok := parseLibDepRef("elf64:libattr.so.1")
	if !ok {
		t.Fatal("failed to parse elf64 libdep")
	}
	if !libraryPathMatchesDep("/usr/lib/libattr.so.1", elf64) {
		t.Fatal("expected elf64 dependency to match /usr/lib provider")
	}
	if libraryPathMatchesDep("/usr/lib32/libattr.so.1", elf64) {
		t.Fatal("did not expect elf64 dependency to match /usr/lib32 provider")
	}

	elf32, ok := parseLibDepRef("elf32:libattr.so.1")
	if !ok {
		t.Fatal("failed to parse elf32 libdep")
	}
	if !libraryPathMatchesDep("/usr/lib32/libattr.so.1", elf32) {
		t.Fatal("expected elf32 dependency to match /usr/lib32 provider")
	}
	if libraryPathMatchesDep("/usr/lib/libattr.so.1", elf32) {
		t.Fatal("did not expect elf32 dependency to match /usr/lib provider")
	}

	legacy, ok := parseLibDepRef("libattr.so.1")
	if !ok {
		t.Fatal("failed to parse legacy libdep")
	}
	if !libraryPathMatchesDep("/usr/lib/libattr.so.1", legacy) || !libraryPathMatchesDep("/usr/lib32/libattr.so.1", legacy) {
		t.Fatal("expected legacy dependency to preserve basename-only matching")
	}
}

func TestGenerateDependsLibstdcppUsesSharedLibraryOwnerOnly(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "qt")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "qt")

	for _, dir := range []string{
		pkgDir,
		targetDir,
		filepath.Join(dbRoot, "gcc"),
		filepath.Join(dbRoot, "gcc-libs"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libstdc++.so.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "gcc", "manifest"), []byte(strings.Join([]string{
		"/usr/lib/libstdc++.a -",
		"/usr/lib/libstdc++.modules.json -",
		"/usr/lib/libstdc++exp.a -",
		"/usr/lib/libstdc++fs.a -",
		"/usr/lib32/libstdc++.a -",
		"/usr/lib32/libstdc++.modules.json -",
		"/usr/lib32/libstdc++exp.a -",
		"/usr/lib32/libstdc++fs.a -",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "gcc-libs", "manifest"), []byte("/usr/lib/libstdc++.so.6 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("qt", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "gcc-libs\n" {
		t.Fatalf("expected only gcc-libs to satisfy libstdc++.so.6, got %q", got)
	}
}

func TestGenerateDependsIgnoresBootstrapOnlyPackageProviders(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "gcc")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "gcc")

	for _, dir := range []string{
		pkgDir,
		targetDir,
		filepath.Join(dbRoot, "20-gcc-2"),
		filepath.Join(dbRoot, "gcc-libs"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libstdc++.so.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "20-gcc-2", "manifest"), []byte("/usr/lib/libstdc++.so.6 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "gcc-libs", "manifest"), []byte("/usr/lib/libstdc++.so.6 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("gcc", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "gcc-libs\n" {
		t.Fatalf("expected bootstrap-only provider to be ignored, got %q", got)
	}
}

func TestGenerateDependsCanIgnoreLibDepPackage(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "util-linux")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "util-linux")

	for _, dir := range []string{
		pkgDir,
		targetDir,
		filepath.Join(dbRoot, "python"),
		filepath.Join(dbRoot, "zlib"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libpython3.14.so.1.0\nelf64:libz.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "python", "manifest"), []byte("/usr/lib/libpython3.14.so.1.0 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "zlib", "manifest"), []byte("/usr/lib/libz.so.1 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "libdeps.ignore"), []byte("python # optional helper only\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("util-linux", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	depends := string(data)
	if strings.Contains(depends, "python") {
		t.Fatalf("ignored package dependency was written to depends: %q", depends)
	}
	if !strings.Contains(depends, "zlib\n") {
		t.Fatalf("unignored library dependency was not preserved: %q", depends)
	}
}

func TestGenerateDependsCanIgnoreRawLibDep(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "util-linux")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "util-linux")

	for _, dir := range []string{
		pkgDir,
		targetDir,
		filepath.Join(dbRoot, "python"),
		filepath.Join(dbRoot, "zlib"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libpython3.14.so.1.0\nelf64:libz.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "python", "manifest"), []byte("/usr/lib/libpython3.14.so.1.0 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbRoot, "zlib", "manifest"), []byte("/usr/lib/libz.so.1 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "libdeps.ignore"), []byte("elf64:libpython3.14.so.1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("util-linux", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	depends := string(data)
	if strings.Contains(depends, "python") {
		t.Fatalf("ignored raw library dependency resolved to package: %q", depends)
	}
	if !strings.Contains(depends, "zlib\n") {
		t.Fatalf("unignored library dependency was not preserved: %q", depends)
	}
}

func TestGenerateDependsPreservesAlternativeSuggestGroup(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "mesa")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "mesa")

	for _, dir := range []string{pkgDir, targetDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	line := "nvidia-utils | vulkan-radeon | vulkan-virtio | vulkan-swrast | vulkan-broadcom suggest vulkan renderer\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "depends"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("mesa", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "suggests"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != line {
		t.Fatalf("unexpected suggests content: got %q want %q", got, line)
	}
	if data, err := os.ReadFile(filepath.Join(targetDir, "depends")); err == nil && len(data) > 0 {
		t.Fatalf("suggest-only alternative group leaked into hard depends: %q", string(data))
	}
}

func TestGenerateDependsUsesVersionedRuntimePackageForConstraint(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "gst-plugins-bad")
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, "gst-plugins-bad")
	providerDir := filepath.Join(dbRoot, "webrtc-audio-processing-1")
	for _, dir := range []string{pkgDir, targetDir, providerDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	oldInstalled := Installed
	Installed = dbRoot
	t.Cleanup(func() { Installed = oldInstalled })
	if err := os.WriteFile(filepath.Join(pkgDir, "depends"), []byte("webrtc-audio-processing<2.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libwebrtc_audio_processing.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "version"), []byte("1.3 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "manifest"), []byte("/usr/lib/libwebrtc_audio_processing.so.1 -\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("gst-plugins-bad", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "webrtc-audio-processing-1\n"; got != want {
		t.Fatalf("unexpected generated dependencies: got %q want %q", got, want)
	}
}
