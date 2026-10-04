package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withTestRemoteIndex(t *testing.T, index []RepoEntry) {
	t.Helper()
	oldIndex, oldErr, oldLoaded := GlobalRemoteIndex, GlobalRemoteIndexErr, GlobalRemoteIndexLoaded
	oldMirror := BinaryMirror
	GlobalRemoteIndex, GlobalRemoteIndexErr, GlobalRemoteIndexLoaded = index, nil, true
	// Never contacted: locating does not download.
	BinaryMirror = "https://mirror.invalid/sauzeros"
	t.Cleanup(func() {
		GlobalRemoteIndex, GlobalRemoteIndexErr, GlobalRemoteIndexLoaded = oldIndex, oldErr, oldLoaded
		BinaryMirror = oldMirror
	})
}

func testIndexEntry(name, depends string) RepoEntry {
	var deps []string
	if depends != "" {
		deps = []string{depends}
	}
	return RepoEntry{
		Name: name, Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized",
		Filename:        name + "-1.0-1-x86_64-optimized.tar.zst",
		Depends:         deps,
		MetadataVersion: repoEntryMetadataVersion,
	}
}

func TestBuildDepRuntimeClosurePlansMissingRuntimeDepsFirst(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	// ffmpeg is a build dependency; its binary needs librsvg, which needs
	// gdk-pixbuf, which needs glycin. glib is installed already, and libass
	// is a build dependency of its own later in the plan.
	for _, name := range []string{"ffmpeg", "librsvg", "gdk-pixbuf", "glycin", "glib", "libass"} {
		writeTestPackage(t, repo, name, "")
	}
	writeInstalledTestPackage(t, "glib")
	ffmpeg := testIndexEntry("ffmpeg", "")
	ffmpeg.Depends = []string{"librsvg", "glib", "libass"}
	withTestRemoteIndex(t, []RepoEntry{
		ffmpeg,
		testIndexEntry("librsvg", "gdk-pixbuf"),
		testIndexEntry("gdk-pixbuf", "glycin"),
		testIndexEntry("glycin", "glib"),
		testIndexEntry("glib", ""),
		testIndexEntry("libass", ""),
	})

	var installs []buildDepInstall
	for _, name := range []string{"ffmpeg", "libass"} {
		b, ok, err := locateBuildDependencyBinaryTarball(name, cfg, false)
		if err != nil || !ok {
			t.Fatalf("locate %s: ok=%v err=%v", name, ok, err)
		}
		if b.entry == nil {
			t.Fatalf("%s should still be on the mirror, got %+v", name, b)
		}
		installs = append(installs, buildDepInstall{name: name, cfg: cfg, tarball: b})
	}
	if entries, _ := os.ReadDir(BinDir); len(entries) != 0 {
		t.Fatalf("locating must not download anything, BinDir has %v", entries)
	}

	var got []string
	for _, d := range withBuildDepRuntimeClosure(installs, cfg, false) {
		got = append(got, d.name)
		if !d.isBinary() || d.tarball.entry == nil {
			t.Errorf("%s should be a binary from the mirror: %+v", d.name, d)
		}
	}
	want := []string{"glycin", "gdk-pixbuf", "librsvg", "ffmpeg", "libass"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %v, want %v", got, want)
	}
}

func TestBuildDepRuntimeClosureLeavesCrossSystemPackagesAlone(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "libxcb", "")
	// Its recipe's native lines name host packages it does not use; the
	// install knows that, the closure does not try.
	cross := RepoEntry{
		Name: "aarch64-libx11", Version: "1.0", Revision: "1", Arch: "aarch64", Variant: "generic",
		Depends: []string{"libxcb"}, MetadataVersion: repoEntryMetadataVersion,
	}
	withTestRemoteIndex(t, []RepoEntry{cross, testIndexEntry("libxcb", "")})

	installs := []buildDepInstall{{name: "aarch64-libx11", cfg: cfg, tarball: remoteBinaryTarball("aarch64-libx11", &cross, cfg)}}
	got := withBuildDepRuntimeClosure(installs, cfg, false)
	if len(got) != 1 || got[0].name != "aarch64-libx11" {
		t.Fatalf("plan = %+v, want only aarch64-libx11", got)
	}
}

func TestLocateBuildDependencyBinaryPrefersCache(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "meson", "")
	withTestRemoteIndex(t, []RepoEntry{testIndexEntry("meson", "")})

	cached := filepath.Join(BinDir, "meson-1.0-1-x86_64-optimized.tar.zst")
	if err := os.WriteFile(cached, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, ok, err := locateBuildDependencyBinaryTarball("meson", cfg, false)
	if err != nil || !ok || b.entry != nil || b.path != cached {
		t.Fatalf("expected the cached archive, got %+v ok=%v err=%v", b, ok, err)
	}
	if path, err := b.fetch(cfg); err != nil || path != cached {
		t.Fatalf("fetch of a cached archive: %q, %v", path, err)
	}
}
