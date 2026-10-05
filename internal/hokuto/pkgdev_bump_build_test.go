package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBumpedPackageBuiltLooksForTheNewRelease(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "geeqie", "") // version 1.0 1
	if bumpedPackageBuilt("geeqie", cfg) {
		t.Fatal("nothing built yet")
	}
	// The package of the previous release does not count.
	old := filepath.Join(BinDir, StandardizeRemoteName("geeqie", "0.9", "1", "x86_64", "optimized"))
	if err := os.WriteFile(old, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if bumpedPackageBuilt("geeqie", cfg) {
		t.Fatal("an older release's package is not the bump's build")
	}
	built := filepath.Join(BinDir, StandardizeRemoteName("geeqie", "1.0", "1", "x86_64", "optimized"))
	if err := os.WriteFile(built, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !bumpedPackageBuilt("geeqie", cfg) {
		t.Fatal("the package of the bumped release is there")
	}
}
