package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeInstalledDepends(t *testing.T, pkgName, depends string) {
	t.Helper()
	writeInstalledTestPackage(t, pkgName)
	if err := os.WriteFile(filepath.Join(Installed, pkgName, "depends"), []byte(depends), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMissingInstalledRuntimeDepsFindsBrokenChain(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	// The hokuto-builder container: gdk-pixbuf was installed without glycin.
	writeInstalledDepends(t, "gtk+3", "gdk-pixbuf\nglib\nmeson make\n")
	writeInstalledDepends(t, "gdk-pixbuf", "glib\nglycin\nshared-mime-info\naarch64-glib cross\n")
	writeInstalledDepends(t, "glib", "gtk+3 optional\nglibc\n")
	writeInstalledDepends(t, "glibc", "")
	writeInstalledDepends(t, "shared-mime-info", "glib\n")
	// A cycle, an unsatisfied alternative group and a make-only line must
	// neither loop nor be reported.
	writeInstalledDepends(t, "python", "python-pip\npy-a | py-b\n")
	writeInstalledDepends(t, "python-pip", "python\n")

	got := missingInstalledRuntimeDeps([]string{"gtk+3", "python", "not-installed"}, cfg)
	want := map[string][]string{"glycin": {"gdk-pixbuf"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}

	writeInstalledDepends(t, "glycin", "glib\n")
	if got := missingInstalledRuntimeDeps([]string{"gtk+3"}, cfg); len(got) != 0 {
		t.Fatalf("nothing should be missing once glycin is installed, got %v", got)
	}
}

func TestBuildDependencyRootsCoversCompiledPackagesOnly(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "qemu", "gtk+3 make\nglib\nmeson make\n")
	writeTestPackage(t, repo, "harfbuzz", "freetype\n")

	plan := &BuildPlan{Order: []string{"qemu", "harfbuzz"}, BinaryPackages: map[string]bool{"harfbuzz": true}}
	roots := buildDependencyRoots(plan, cfg)
	has := make(map[string]bool)
	for _, r := range roots {
		has[r] = true
	}
	for _, want := range []string{"gtk+3", "glib", "meson"} {
		if !has[want] {
			t.Errorf("roots %v lack qemu's build dependency %s", roots, want)
		}
	}
	if has["freetype"] {
		t.Errorf("harfbuzz is installed from a binary; its build dependencies are not needed: %v", roots)
	}
}
