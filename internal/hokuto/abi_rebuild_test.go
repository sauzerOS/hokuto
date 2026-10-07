package hokuto

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// writeTestArchive writes a .tar.zst with the given regular files (path ->
// content) and symlinks (path -> target).
func writeTestArchive(t *testing.T, path string, files, symlinks map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zw.Close()
	tw := tar.NewWriter(zw)
	defer tw.Close()
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range symlinks {
		if err := tw.WriteHeader(&tar.Header{Name: name, Linkname: target, Mode: 0o777, Typeflag: tar.TypeSymlink}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTarballSharedLibraryPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libfoo.tar.zst")
	writeTestArchive(t, path, map[string]string{
		"./usr/lib/libfoo.so.3.1.0":                  "elf",
		"usr/lib32/libfoo.so.3.1.0":                  "elf",
		"usr/include/foo.h":                          "h",
		"var/db/hokuto/installed/libfoo/libdeps":     "elf64:libc.so.6\n",
		"var/db/hokuto/installed/libfoo/libx.so.1":   "not a payload file",
		"usr/share/doc/libfoo/libfoo.so.3.1.0.notes": "txt",
	}, map[string]string{
		"usr/lib/libfoo.so.3": "libfoo.so.3.1.0",
		"usr/lib/libfoo.so":   "libfoo.so.3",
	})
	got, err := tarballSharedLibraryPaths(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"/usr/lib/libfoo.so.3.1.0": true, "/usr/lib32/libfoo.so.3.1.0": true,
		"/usr/lib/libfoo.so.3": true, "/usr/lib/libfoo.so": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("unexpected library path %s in %v", p, got)
		}
	}
}

func TestRemovedSharedLibraries(t *testing.T) {
	old := []string{
		"/usr/lib/libfoo.so", "/usr/lib/libfoo.so.3", "/usr/lib/libfoo.so.3.1.0",
		"/usr/lib32/libfoo.so.3", // still shipped for 32-bit
		"/usr/lib/foo/libbar.so.1",
		"/usr/lib/libgone.so.2",
	}
	updated := []string{
		"/usr/lib/libfoo.so", "/usr/lib/libfoo.so.4", "/usr/lib/libfoo.so.4.0.0",
		"/usr/lib32/libfoo.so.3",
		"/usr/lib/libbar.so.1", // moved directory, same library
	}
	got := removedSharedLibraries(old, updated)
	want := []libDepRef{
		{ABI: "elf64", Name: "libfoo.so.3"},
		{ABI: "elf64", Name: "libfoo.so.3.1.0"},
		{ABI: "elf64", Name: "libgone.so.2"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("removed: got %v want %v", got, want)
	}
	// A minor update that keeps the soname removes only the versioned file,
	// which nothing links against.
	if got := removedSharedLibraries([]string{"/usr/lib/libfoo.so.3", "/usr/lib/libfoo.so.3.1.0"},
		[]string{"/usr/lib/libfoo.so.3", "/usr/lib/libfoo.so.3.2.0"}); len(got) != 1 || got[0].Name != "libfoo.so.3.1.0" {
		t.Fatalf("soname-preserving update: %v", got)
	}
}

func TestAbiConsumers(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	for _, name := range []string{"libfoo", "app", "tool", "old-user", "prebuilt", "lib32-user-src", "cross-user", "variant-mix", "both-variants"} {
		writeTestPackage(t, repo, name, "")
	}
	if err := os.WriteFile(filepath.Join(repo, "prebuilt", "options"), []byte("binary\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "lib32-user-src", "depends.lib32-user"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	v2 := repoEntryLibdepsMetadataVersion
	index := []RepoEntry{
		{Name: "app", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libc.so.6", "elf64:libfoo.so.3"}},
		{Name: "tool", Version: "2.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"/usr/lib/libfoo.so.3"}}, // old absolute format
		// Only the newest entry counts: old-user dropped the dependency.
		{Name: "old-user", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		{Name: "old-user", Version: "1.1", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libc.so.6"}},
		{Name: "prebuilt", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "generic", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		// An older build of another variant is not current either: only
		// variant-mix 1.2 (generic) is checked, not 1.1 (optimized).
		{Name: "variant-mix", Version: "1.1", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		{Name: "variant-mix", Version: "1.2", Revision: "1", Arch: "x86_64", Variant: "generic", MetadataVersion: v2, Libdeps: []string{"elf64:libc.so.6"}},
		// Both variants of the newest version count.
		{Name: "both-variants", Version: "2.0", Revision: "1", Arch: "x86_64", Variant: "generic", MetadataVersion: v2, Libdeps: []string{"elf64:libc.so.6"}},
		{Name: "both-variants", Version: "2.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		{Name: "libfoo-utils", Version: "3.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}}, // no recipe
		{Name: "libfoo", Version: "3.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		{Name: "lib32-user", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "multi-optimized", MetadataVersion: v2, Libdeps: []string{"elf32:libfoo.so.3"}}, // 32-bit library kept
		{Name: "cross-user", Version: "1.0", Revision: "1", Arch: "aarch64", Variant: "optimized", MetadataVersion: v2, Libdeps: []string{"elf64:libfoo.so.3"}},
		{Name: "unscanned", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: 1},
	}
	brk := abiBreak{Library: "libfoo", Removed: []libDepRef{{ABI: "elf64", Name: "libfoo.so.3"}}}
	got, unknown := abiConsumers(index, "x86_64", brk)
	want := map[string][]string{"app": {"libfoo.so.3"}, "tool": {"libfoo.so.3"}, "both-variants": {"libfoo.so.3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers: got %v want %v", got, want)
	}
	if unknown != 1 {
		t.Fatalf("expected 1 unscanned package, got %d", unknown)
	}

	// A split package maps to its recipe.
	brk32 := abiBreak{Library: "libfoo", Removed: []libDepRef{{ABI: "elf32", Name: "libfoo.so.3"}}}
	if got, _ := abiConsumers(index, "x86_64", brk32); !reflect.DeepEqual(got, map[string][]string{"lib32-user-src": {"libfoo.so.3"}}) {
		t.Fatalf("split consumer: %v", got)
	}

	// A consumer already bumped past its published package (app 1.0-2 in
	// the repository, 1.0-1 published) waits for its rebuild: checking the
	// same library change again must not bump it a second time.
	if err := os.WriteFile(filepath.Join(repo, "app", "version"), []byte("1.0 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ = abiConsumers(index, "x86_64", brk)
	want = map[string][]string{"tool": {"libfoo.so.3"}, "both-variants": {"libfoo.so.3"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pending rebuild bumped again: got %v want %v", got, want)
	}
}

func TestAbiLibraryRecipesSkipsBinaryRecipes(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	for _, name := range []string{"dav1d", "proton"} {
		writeTestPackage(t, repo, name, "")
	}
	// proton bundles its own libdav1d.so.7; dropping it breaks nothing.
	if err := os.WriteFile(filepath.Join(repo, "proton", "options"), []byte("binary multilib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := abiLibraryRecipes([]string{"proton", "dav1d"}); !reflect.DeepEqual(got, []string{"dav1d"}) {
		t.Fatalf("got %v, want only dav1d", got)
	}
}

func TestReadPackageMetadataRecordsLibdeps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app-1.0-1-x86_64-optimized.tar.zst")
	writeTestArchive(t, path, map[string]string{
		"var/db/hokuto/installed/app/pkginfo": "name=app\nversion=1.0\nrevision=1\narch=x86_64\ngeneric=0\nmultilib=0\n",
		"var/db/hokuto/installed/app/depends": "glibc\n",
		"var/db/hokuto/installed/app/libdeps": "elf64:libc.so.6\nelf64:libfoo.so.3\n",
		"usr/share/app/libdeps":               "not metadata\n",
	}, nil)
	entry, err := ReadPackageMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if entry.MetadataVersion != repoEntryMetadataVersion || !reflect.DeepEqual(entry.Libdeps, []string{"elf64:libc.so.6", "elf64:libfoo.so.3"}) {
		t.Fatalf("entry: version %d libdeps %v", entry.MetadataVersion, entry.Libdeps)
	}
	// Older index entries still count as having dependency metadata, so
	// clients do not download packages before the index is reindexed.
	if !repoEntryHasDependencyMetadata(RepoEntry{MetadataVersion: 1}) {
		t.Fatal("metadata version 1 entries lost their dependency metadata")
	}
}

func TestBumpABIConsumersCommitsAndPushes(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "master", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	gitIn(t, repo, "init", "-q", "-b", "master")
	gitIn(t, repo, "config", "user.name", "Hokuto Test")
	gitIn(t, repo, "config", "user.email", "test@sauzeros.invalid")
	gitIn(t, repo, "remote", "add", "origin", remote)
	for _, name := range []string{"app", "tool", "edited"} {
		writeTestPackage(t, repo, name, "")
	}
	gitIn(t, repo, "add", ".")
	gitIn(t, repo, "commit", "-q", "-m", "initial")
	gitIn(t, repo, "push", "-q", "-u", "origin", "master")

	// Your own uncommitted version change must not be swept into the commit.
	if err := os.WriteFile(filepath.Join(repo, "edited", "version"), []byte("2.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Nor unrelated staged work.
	if err := os.WriteFile(filepath.Join(repo, "app", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, "add", "app/build")

	consumers := map[string][]string{"app": {"libfoo.so.3"}, "tool": {"libfoo.so.3"}, "edited": {"libfoo.so.3"}}
	result, err := bumpABIConsumers(consumers, abiRebuildCommitMessage(map[string][]string{"libfoo": {"libfoo.so.3"}}))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Bumped, []string{"app", "tool"}) || len(result.Skipped) != 1 || !strings.HasPrefix(result.Skipped[0], "edited:") {
		t.Fatalf("result: %+v", result)
	}
	for _, name := range []string{"app", "tool"} {
		if got := gitIn(t, repo, "show", "origin/master:"+name+"/version"); got != "1.0 2" {
			t.Fatalf("%s pushed version %q", name, got)
		}
	}
	if msg := gitIn(t, remote, "log", "-1", "--format=%s"); msg != "rebuild for libfoo (libfoo.so.3) ABI change" {
		t.Fatalf("commit message %q", msg)
	}
	if files := gitIn(t, remote, "show", "--name-only", "--format=", "HEAD"); files != "app/version\ntool/version" {
		t.Fatalf("commit contains %q", files)
	}
	if got, _ := os.ReadFile(filepath.Join(repo, "edited", "version")); string(got) != "2.0 1\n" {
		t.Fatalf("edited version file changed: %q", got)
	}
	if staged := gitIn(t, repo, "diff", "--cached", "--name-only"); staged != "app/build" {
		t.Fatalf("staged work lost or committed: %q", staged)
	}
}

func TestDetectABIBreak(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "libfoo", "")
	if err := os.WriteFile(filepath.Join(repo, "libfoo", "version"), []byte("4.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "libfoo", "depends.lib32-libfoo"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	variant := GetSystemVariantForPackage(cfg, "libfoo")
	archive := func(name, version, variant string, libs ...string) string {
		path := filepath.Join(BinDir, StandardizeRemoteName(name, version, "1", "x86_64", variant))
		files := map[string]string{}
		for _, lib := range libs {
			files[lib] = "elf"
		}
		writeTestArchive(t, path, files, nil)
		return path
	}
	archive("libfoo", "4.0", variant, "usr/lib/libfoo.so.4")
	archive("libfoo", "3.0", "optimized", "usr/lib/libfoo.so.3")
	lib32Variant := GetSystemVariantForPackage(cfg, "lib32-libfoo")
	archive("lib32-libfoo", "4.0", lib32Variant, "usr/lib32/libfoo.so.4")
	archive("lib32-libfoo", "3.0", "multi-optimized", "usr/lib32/libfoo.so.3")

	index := []RepoEntry{
		{Name: "libfoo", Version: "3.0", Revision: "1", Arch: "x86_64", Variant: "optimized"},
		{Name: "libfoo", Version: "5.0", Revision: "1", Arch: "x86_64", Variant: "optimized"}, // newer than the build: ignored
		{Name: "lib32-libfoo", Version: "3.0", Revision: "1", Arch: "x86_64", Variant: "multi-optimized"},
	}
	brk, err := detectABIBreak("libfoo", cfg, index)
	if err != nil {
		t.Fatal(err)
	}
	want := []libDepRef{{ABI: "elf64", Name: "libfoo.so.3"}, {ABI: "elf32", Name: "libfoo.so.3"}}
	if brk.Version != "4.0" || !reflect.DeepEqual(brk.Removed, want) {
		t.Fatalf("break: %+v", brk)
	}
}

func TestMajorMinor(t *testing.T) {
	for version, want := range map[string]string{"6.12.0": "6.12", "6.12": "6.12", "26.08.1": "26.08", "2026e": "2026e", "1.53.0-0": "1.53"} {
		if got := majorMinor(version); got != want {
			t.Errorf("majorMinor(%q) = %q, want %q", version, got, want)
		}
	}
}

func TestDetectPrivateAPIChange(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "qt", "")
	setVersion := func(v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, "qt", "version"), []byte(v+" 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	variant := GetSystemVariantForPackage(cfg, "qt")
	built := func(version string) {
		writeTestArchive(t, filepath.Join(BinDir, StandardizeRemoteName("qt", version, "1", "x86_64", variant)),
			map[string]string{"usr/lib/libQt6Gui.so.6." + strings.ReplaceAll(version, ".", ""): "elf"},
			map[string]string{"usr/lib/libQt6Gui.so.6": "libQt6Gui.so.6.x", "usr/lib/libQt6Core.so.6": "libQt6Core.so.6.x"})
	}

	// A minor update: 6.11.2 is published, 6.12.0 was just built.
	setVersion("6.12.0")
	built("6.12.0")
	index := []RepoEntry{{Name: "qt", Version: "6.11.2", Revision: "1", Arch: "x86_64", Variant: "optimized"}}
	change, err := detectPrivateAPIChange("qt", cfg, index)
	if err != nil {
		t.Fatal(err)
	}
	if change.Previous != "6.11.2" || !slices.Contains(change.Sonames, "libQt6Core.so.6") || !slices.Contains(change.Sonames, "libQt6Gui.so.6") {
		t.Fatalf("minor update: %+v", change)
	}

	// A patch release keeps private API compatibility.
	setVersion("6.12.1")
	built("6.12.1")
	index = []RepoEntry{{Name: "qt", Version: "6.12.0", Revision: "1", Arch: "x86_64", Variant: "optimized"}}
	if change, err := detectPrivateAPIChange("qt", cfg, index); err != nil || len(change.Sonames) != 0 {
		t.Fatalf("patch release must not trigger: %+v %v", change, err)
	}
}

func TestPrivateAPIConsumers(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	for _, name := range []string{"qt", "kwin", "dolphin", "konsole", "plasma-src", "prebuilt"} {
		writeTestPackage(t, repo, name, "")
	}
	if err := os.WriteFile(filepath.Join(repo, "plasma-src", "depends.plasma-split"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "prebuilt", "options"), []byte("binary\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v3 := repoEntryPrivateDepsMetadataVersion
	entry := func(name string, deps ...string) RepoEntry {
		return RepoEntry{Name: name, Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: v3, PrivateDeps: deps}
	}
	index := []RepoEntry{
		entry("kwin", "libQt6Gui.so.6", "libQt6Core.so.6"),
		entry("dolphin", "libQt6Gui.so.6"),
		entry("konsole"), // links Qt, but only its public API
		entry("plasma-split", "libQt6Gui.so.6"),
		entry("prebuilt", "libQt6Gui.so.6"),
		entry("qt", "libQt6Core.so.6"), // the library itself
		{Name: "old", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized", MetadataVersion: repoEntryLibdepsMetadataVersion},
	}
	change := privateAPIChange{Library: "qt", Version: "6.12.0", Sonames: []string{"libQt6Core.so.6", "libQt6Gui.so.6"}}
	got, unknown := privateAPIConsumers(index, "x86_64", change)
	want := map[string][]string{
		"kwin":       {"libQt6Gui.so.6", "libQt6Core.so.6"},
		"dolphin":    {"libQt6Gui.so.6"},
		"plasma-src": {"libQt6Gui.so.6"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("consumers: got %v want %v", got, want)
	}
	if unknown != 1 {
		t.Fatalf("expected 1 package without privatedeps, got %d", unknown)
	}
}

func TestRebuildCommitMessageForPrivateAPI(t *testing.T) {
	msg := rebuildCommitMessage(map[string][]string{"libfoo": {"libfoo.so.3"}}, []string{"qt 6.12"})
	if msg != "rebuild for libfoo (libfoo.so.3) ABI change; rebuild for qt 6.12 private API" {
		t.Fatalf("message: %q", msg)
	}
	if got := rebuildReason(msg); got != "rebuild for libfoo ABI change; rebuild for qt 6.12 private API" {
		t.Fatalf("rebuild list reason: %q", got)
	}
}

func TestCollectPrivateAPILibsFromRealLibrary(t *testing.T) {
	src, err := filepath.EvalSymlinks("/usr/lib/libkwin.so.6")
	if err != nil {
		t.Skip("no KWin library on this system")
	}
	data, err := os.ReadFile(src)
	if err != nil {
		t.Skip(err)
	}
	out := t.TempDir()
	write := func(rel string, content []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(out, filepath.Dir(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, rel), content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/lib/libkwin.so.6", data)
	libs, err := collectPrivateAPILibs(out)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(libs, []string{"libQt6Gui.so.6"}) {
		t.Fatalf("KWin uses Qt GUI private API, got %v", libs)
	}

	// A library the package ships itself does not count.
	write("usr/lib/libQt6Gui.so.6", []byte("not elf"))
	if libs, _ := collectPrivateAPILibs(out); len(libs) != 0 {
		t.Fatalf("own library must be left out, got %v", libs)
	}
}

func TestReadPackageMetadataRecordsPrivateDeps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kwin-6.7.5-1-x86_64-optimized.tar.zst")
	writeTestArchive(t, path, map[string]string{
		"var/db/hokuto/installed/kwin/pkginfo":     "name=kwin\nversion=6.7.5\nrevision=1\narch=x86_64\ngeneric=0\nmultilib=0\n",
		"var/db/hokuto/installed/kwin/privatedeps": "libQt6Gui.so.6\n",
	}, nil)
	entry, err := ReadPackageMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entry.PrivateDeps, []string{"libQt6Gui.so.6"}) || entry.MetadataVersion < repoEntryPrivateDepsMetadataVersion {
		t.Fatalf("entry: version %d privatedeps %v", entry.MetadataVersion, entry.PrivateDeps)
	}
}
