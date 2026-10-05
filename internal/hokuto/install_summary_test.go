package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func indexEntry(name string, size, installed int64, depends, postInstall []string) RepoEntry {
	return RepoEntry{
		Name: name, Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized",
		Filename:           StandardizeRemoteName(name, "1.0", "1", "x86_64", "optimized"),
		Size:               size,
		InstalledSize:      installed,
		Depends:            depends,
		PostInstallDepends: postInstall,
		MetadataVersion:    repoEntryMetadataVersion,
	}
}

// An install plan from the index includes the post-install dependencies,
// ahead of the package whose hook needs them, so nothing turns up mid-install.
func TestRemotePlanIncludesPostInstallDependencies(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	index := []RepoEntry{
		indexEntry("linux", 100, 1000, []string{"kmod"}, []string{"dracut"}),
		indexEntry("kmod", 10, 20, nil, nil),
		indexEntry("dracut", 30, 40, []string{"bash"}, nil),
		indexEntry("bash", 5, 6, nil, nil),
	}
	var plan []string
	if err := resolveRemoteDependencies("linux", map[string]bool{}, &plan, false, true, cfg, index); err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	for i, p := range plan {
		pos[p] = i
	}
	for _, want := range []string{"kmod", "dracut", "bash", "linux"} {
		if _, ok := pos[want]; !ok {
			t.Fatalf("plan %v lacks %s", plan, want)
		}
	}
	if pos["dracut"] > pos["linux"] || pos["bash"] > pos["dracut"] {
		t.Fatalf("dependencies must come first: %v", plan)
	}
}

// Download size counts what the cache lacks; installed size comes from the
// index, and an entry from before metadata version 4 is reported unknown.
func TestComputeInstallPlanSizes(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	old := indexEntry("old", 7, 0, nil, nil)
	old.MetadataVersion = 3
	index := []RepoEntry{
		indexEntry("fresh", 100, 1000, nil, nil),
		indexEntry("cached", 50, 500, nil, nil),
		old,
	}
	// "cached" is already in the binary cache, at the indexed size.
	if err := os.WriteFile(filepath.Join(BinDir, index[1].Filename), make([]byte, 50), 0o644); err != nil {
		t.Fatal(err)
	}
	sizes := computeInstallPlanSizes([]string{"fresh", "cached", "old"}, cfg, index)
	if sizes.download != 100+7 {
		t.Errorf("download = %d, want %d", sizes.download, 107)
	}
	if sizes.installed != 1000+500 || sizes.unknownInstalled != 1 {
		t.Errorf("installed = %d (+%d unknown), want 1500 (+1)", sizes.installed, sizes.unknownInstalled)
	}
}

func TestComputeRemoteUpdateSizesNetChange(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	root := t.TempDir()
	rootDir = root

	// foo is installed: one 1000-byte file and a hard link to it.
	writeInstalledTestPackage(t, "foo")
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "foo"), make([]byte, 1000), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "usr", "bin", "foo"), filepath.Join(root, "usr", "bin", "foo2")); err != nil {
		t.Fatal(err)
	}
	manifest := "/usr/\n/usr/bin/\n/usr/bin/foo  aaaa\n/usr/bin/foo2  aaaa\n"
	if err := os.WriteFile(filepath.Join(Installed, "foo", "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if size, ok := installedPackageFootprint("foo"); !ok || size != 1000 {
		t.Fatalf("footprint = %d, %v; want 1000 (hard link counted once)", size, ok)
	}

	// The upgrade shrinks it to 400 bytes and brings bar (100 bytes).
	foo := RepoEntry{Name: "foo", Version: "2", Revision: "1", Arch: "x86_64", Variant: "optimized",
		Filename: "foo-2-1-x86_64-optimized.tar.zst", Size: 300, Depends: []string{"bar"},
		InstalledSize: 400, MetadataVersion: repoEntryMetadataVersion}
	bar := RepoEntry{Name: "bar", Version: "1", Revision: "1", Arch: "x86_64", Variant: "optimized",
		Filename: "bar-1-1-x86_64-optimized.tar.zst", Size: 50,
		InstalledSize: 100, MetadataVersion: repoEntryMetadataVersion}
	index := []RepoEntry{foo, bar}

	sizes := computeRemoteUpdateSizes([]string{"foo"}, map[string]RepoEntry{"foo": foo}, cfg, index)
	if sizes.download != 350 || sizes.net != -500 || sizes.unknown != 0 || sizes.known != 2 {
		t.Fatalf("sizes = %+v, want download 350, net -500", sizes)
	}
	if got := formatSignedSize(sizes.net); got != "-500 B" {
		t.Fatalf("formatSignedSize = %q", got)
	}
}

func TestLocalTarballPackageNameFromFileName(t *testing.T) {
	// The files do not exist: the name comes from the file name.
	cases := map[string]string{
		"/x/foo-1.0-1.tar.zst":                                 "foo",
		"/x/gtk+3-3.24.52-2-x86_64-optimized.tar.zst":          "gtk+3",
		"/x/lib32-glibc-2.42-1-x86_64-multi-optimized.tar.zst": "lib32-glibc",
		"/x/aarch64-binutils-2.45-1-aarch64-generic.tar.zst":   "aarch64-binutils",
		"/x/old-1.0.tar.zst":                                   "old",
	}
	for path, want := range cases {
		got, err := localTarballPackageName(path)
		if err != nil || got != want {
			t.Errorf("localTarballPackageName(%q) = %q, %v; want %q", path, got, err, want)
		}
	}
	if _, err := localTarballPackageName("/x/broken.tar.zst"); err == nil {
		t.Error("a file name without version should be an error")
	}
}
