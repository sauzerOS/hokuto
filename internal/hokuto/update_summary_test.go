package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClassifyUpdatePlan(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	rootDir = t.TempDir()
	// bash has a binary of its new release, linux must be built, and the
	// update needs libnew (published) and libsrc (no binary) besides
	// glibc, which is installed.
	for _, name := range []string{"bash", "linux", "libnew", "libsrc", "glibc"} {
		writeTestPackage(t, repo, name, "")
	}
	writeInstalledTestPackage(t, "bash")
	writeInstalledTestPackage(t, "glibc")
	if err := os.WriteFile(filepath.Join(Installed, "bash", "manifest"), []byte("/usr/bin/\n/usr/bin/bash  aaaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rootDir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "usr", "bin", "bash"), make([]byte, 700), 0o755); err != nil {
		t.Fatal(err)
	}
	bash := testIndexEntry("bash", "")
	bash.Size, bash.InstalledSize = 300, 1000
	libnew := testIndexEntry("libnew", "")
	libnew.Size, libnew.InstalledSize = 50, 200
	withTestRemoteIndex(t, []RepoEntry{bash, libnew})

	updateBinaries := make(map[string]binaryTarball)
	binaryAvailable := make(map[string]bool)
	for _, name := range []string{"bash", "linux"} {
		if b, ok := locateUpdateBinary(name, cfg, GlobalRemoteIndex); ok {
			updateBinaries[name] = b
			binaryAvailable[name] = true
		}
	}
	if !binaryAvailable["bash"] || binaryAvailable["linux"] {
		t.Fatalf("binaryAvailable = %v, want bash only", binaryAvailable)
	}
	if entries, _ := os.ReadDir(BinDir); len(entries) != 0 {
		t.Fatalf("locating must not download anything, BinDir has %v", entries)
	}

	plan := &BuildPlan{Order: []string{"glibc", "libnew", "libsrc", "bash", "linux"}}
	requested := map[string]bool{"bash": true, "linux": true}
	builds, binaries, sizes := classifyUpdatePlan(plan, requested, binaryAvailable, updateBinaries, nil, cfg)
	if !reflect.DeepEqual(builds, []string{"libsrc", "linux"}) {
		t.Errorf("builds = %v", builds)
	}
	if !reflect.DeepEqual(binaries, []string{"libnew", "bash"}) {
		t.Errorf("binaries = %v", binaries)
	}
	// bash grows by 300, libnew adds 200; both are downloaded.
	if sizes.download != 350 || sizes.net != 500 || sizes.known != 2 || sizes.built != 2 {
		t.Errorf("sizes = %+v, want download 350, net 500, known 2, built 2", sizes)
	}
}

func TestClassifyUpdatePlanListsSplitBinariesFirst(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	rootDir = t.TempDir()
	utils := testIndexEntry("harfbuzz-utils", "")
	utils.Size, utils.InstalledSize = 40, 100
	splits := []splitUpdateBinary{{name: "harfbuzz-utils", tarball: remoteBinaryTarball("harfbuzz-utils", &utils, cfg)}}

	// Only split outputs selected: no build plan at all.
	builds, binaries, sizes := classifyUpdatePlan(nil, nil, nil, nil, splits, cfg)
	if len(builds) != 0 || !reflect.DeepEqual(binaries, []string{"harfbuzz-utils"}) {
		t.Fatalf("builds %v, binaries %v", builds, binaries)
	}
	// Not installed yet, so it adds its whole size.
	if sizes.download != 40 || sizes.net != 100 || sizes.known != 1 {
		t.Fatalf("sizes = %+v", sizes)
	}
	if entries := splitUpdateEntries(splits); len(entries) != 1 || entries[0].Name != "harfbuzz-utils" {
		t.Fatalf("entries to download = %+v", entries)
	}
}
