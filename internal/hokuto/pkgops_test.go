package hokuto

import (
	"archive/tar"
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ulikunitz/xz/lzma"
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

func TestPrepareSourcesPreservesURLFilenameOverride(t *testing.T) {
	for _, noExtract := range []bool{false, true} {
		name := "copy"
		if noExtract {
			name = "noextract"
		}
		t.Run(name, func(t *testing.T) {
			oldCacheDir := CacheDir
			t.Cleanup(func() { CacheDir = oldCacheDir })

			tmp := t.TempDir()
			CacheDir = filepath.Join(tmp, "cache")
			pkgDir := filepath.Join(tmp, "recipe")
			buildDir := filepath.Join(tmp, "build")
			pkgSourceDir := filepath.Join(CacheDir, "sources", "example")
			for _, dir := range []string{pkgDir, buildDir, pkgSourceDir} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}

			line := "https://example.invalid/commit/0123456789.patch -> descriptive.patch"
			if noExtract {
				line += " noextract"
			}
			if err := os.WriteFile(filepath.Join(pkgDir, "sources"), []byte(line+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pkgSourceDir, "descriptive.patch"), []byte("patch payload\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			if err := prepareSources("example", pkgDir, buildDir, &Executor{Context: context.Background()}); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(filepath.Join(buildDir, "descriptive.patch")); err != nil {
				t.Fatalf("renamed source missing: %v", err)
			} else if string(data) != "patch payload\n" {
				t.Fatalf("unexpected renamed source contents: %q", data)
			}
			if _, err := os.Stat(filepath.Join(buildDir, "0123456789.patch")); !os.IsNotExist(err) {
				t.Fatalf("URL basename should not be copied when an override is present: %v", err)
			}
		})
	}
}

func TestPrepareSourcesExtractsLZMAWithInternalFallback(t *testing.T) {
	oldCacheDir := CacheDir
	t.Cleanup(func() { CacheDir = oldCacheDir })

	tmp := t.TempDir()
	CacheDir = filepath.Join(tmp, "cache")
	pkgDir := filepath.Join(tmp, "recipe")
	buildDir := filepath.Join(tmp, "build")
	pkgSourceDir := filepath.Join(CacheDir, "sources", "example")
	for _, dir := range []string{pkgDir, buildDir, pkgSourceDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	archivePath := filepath.Join(pkgSourceDir, "source.lzma")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	lw, err := lzma.NewWriter(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	tw := tar.NewWriter(lw)
	payload := []byte("internal lzma")
	now := time.Now()
	if err := tw.WriteHeader(&tar.Header{
		Name:       "source/payload.txt",
		Mode:       0o644,
		Size:       int64(len(payload)),
		ModTime:    now,
		AccessTime: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "sources"), []byte("https://example.invalid/source.lzma\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "tar"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := prepareSources("example", pkgDir, buildDir, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(buildDir, "payload.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("unexpected extracted contents: %q", data)
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

	if err := copyDirContents(src, dst); err != nil {
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

	if err := copyDirContents(srcLink, dst); err != nil {
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

func TestGenerateDependsPreservesPostInstallAlternativeGroup(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", "linux")
	outputDir := filepath.Join(tmp, "out")
	targetDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", "linux")

	for _, dir := range []string{pkgDir, targetDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	line := "dracut | mkinitcpio post-install\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "depends"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends("linux", pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != line {
		t.Fatalf("unexpected depends content: got %q want %q", got, line)
	}
}

func TestGenerateDependsKeepsConstraintOfVersionedRuntimePackage(t *testing.T) {
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
	// The constraint is kept (the parallel name only carries the major
	// line: glew<2.3 as glew-2 let installs pick glew 2.3.1), and the library
	// owner webrtc-audio-processing-1 adds no second line.
	if got, want := string(data), "webrtc-audio-processing<2.0\n"; got != want {
		t.Fatalf("unexpected generated dependencies: got %q want %q", got, want)
	}
}

func generateDependsForCrossOwners(t *testing.T, pkgName string, uses map[string]libDepMachineUse) []string {
	t.Helper()
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "repo", strings.TrimPrefix(pkgName, "aarch64-"))
	outputDir := filepath.Join(tmp, "out")
	dbRoot := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	targetDir := filepath.Join(dbRoot, pkgName)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	owners := map[string]string{
		"harfbuzz":         "/usr/lib/libharfbuzz.so.0",
		"aarch64-harfbuzz": "/usr/aarch64-linux-gnu/lib/libharfbuzz.so.0",
		"zlib-ng":          "/usr/lib/libz.so.1",
		"aarch64-zlib-ng":  "/usr/aarch64-linux-gnu/lib/libz.so.1",
	}
	for owner, path := range owners {
		if err := os.MkdirAll(filepath.Join(dbRoot, owner), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dbRoot, owner, "manifest"), []byte(path+" -\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, "libdeps"), []byte("elf64:libharfbuzz.so.0\nelf64:libz.so.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldScan := libDepsByMachine
	libDepsByMachine = func(string, elf.Machine) (map[string]libDepMachineUse, error) { return uses, nil }
	t.Cleanup(func() { libDepsByMachine = oldScan })

	execCtx := &Executor{Context: context.Background()}
	if err := generateDepends(pkgName, pkgDir, outputDir, outputDir, execCtx, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(targetDir, "depends"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	sort.Strings(got)
	return got
}

func TestGenerateDependsCrossSystemPackageRecordsSysrootOwners(t *testing.T) {
	// aarch64-freetype's target library needs libharfbuzz.so.0 from the
	// sysroot, and a host tool it ships needs the host's libz alongside the
	// target library's sysroot libz.
	got := generateDependsForCrossOwners(t, "aarch64-freetype", map[string]libDepMachineUse{
		"elf64:libharfbuzz.so.0": {target: true},
		"elf64:libz.so.1":        {target: true, host: true},
	})
	want := []string{"aarch64-harfbuzz", "aarch64-zlib-ng", "zlib-ng"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("depends = %v, want %v", got, want)
	}
}

func TestGenerateDependsNativePackageIgnoresSysrootOwners(t *testing.T) {
	got := generateDependsForCrossOwners(t, "freetype", nil)
	want := []string{"harfbuzz", "zlib-ng"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("depends = %v, want %v", got, want)
	}
}
