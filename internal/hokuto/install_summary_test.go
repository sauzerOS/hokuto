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
