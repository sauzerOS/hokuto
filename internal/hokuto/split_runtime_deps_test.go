package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

// A binary package comes without the other outputs of its recipe: gcc's
// runtime libasan is a split package of its own, which must be installed with
// it when gcc is installed from a binary for a build.
func TestResolveMissingDepsIncludesSplitSiblingsOfBinaryDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "target", "gcc make\n")
	writeTestPackage(t, repo, "gcc", "libasan\nlibstdc++\n")
	for _, split := range []string{"libasan", "libstdc++"} {
		if err := os.WriteFile(filepath.Join(repo, "gcc", "depends."+split), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// libstdc++ is installed already; libasan is not.
	if err := os.MkdirAll(filepath.Join(Installed, "libstdc++"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Installed, "libstdc++", "version"), []byte("1.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gcc", "libasan", "libstdc++"} {
		path := filepath.Join(BinDir, StandardizeRemoteName(name, "1.0", "1", "x86_64", "optimized"))
		deps := ""
		if name == "gcc" {
			deps = "libasan\nlibstdc++\n"
		}
		writeTestBinaryTarballWithDepends(t, path, name, "1.0", "1", deps)
	}

	var missing []string
	if err := resolveMissingDeps("target", map[string]bool{}, &missing, map[string]bool{"target": true}, cfg, true); err != nil {
		t.Fatal(err)
	}
	t.Logf("missing: %v", missing)
	if !containsString(missing, "gcc") || !containsString(missing, "libasan") {
		t.Fatalf("missing = %v, want gcc and libasan", missing)
	}
	if containsString(missing, "libstdc++") {
		t.Fatalf("missing = %v, libstdc++ is installed", missing)
	}
}
