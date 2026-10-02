package hokuto

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = old
	w.Close()
	data, _ := io.ReadAll(r)
	return string(data)
}

func TestRepairInstalledRuntimeDepsSkipsWhatThePlanBuilds(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	oldMirror := BinaryMirror
	BinaryMirror = ""
	t.Cleanup(func() { BinaryMirror = oldMirror })

	writeTestPackage(t, repo, "qemu", "gtk+3 make\n")
	writeTestPackage(t, repo, "glycin", "")
	writeInstalledDepends(t, "gtk+3", "gdk-pixbuf\n")
	writeInstalledDepends(t, "gdk-pixbuf", "glycin\nlibjxl\n")
	writeTestPackage(t, repo, "libjxl", "")

	// A rebuild run builds glycin itself, so only libjxl is really missing.
	plan := &BuildPlan{Order: []string{"glycin", "qemu"}}
	out := captureStderr(t, func() {
		if installed := repairInstalledRuntimeDeps(plan, cfg, true, true); len(installed) != 0 {
			t.Errorf("nothing can be installed without binaries, got %v", installed)
		}
	})
	if strings.Contains(out, "glycin") {
		t.Errorf("glycin is built by this plan and must not be warned about:\n%s", out)
	}
	if !strings.Contains(out, "runtime dependency libjxl of gdk-pixbuf has no binary available") {
		t.Errorf("libjxl is missing with no binary and must be reported:\n%s", out)
	}
}

func TestMissingInstalledRuntimeDepsCrossSystemPackages(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_CROSS_ARCH"] = "arm64"
	writeTestPackage(t, repo, "gcc", "")
	if err := os.WriteFile(filepath.Join(repo, "gcc", "options"), []byte("host-tool\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A sysroot library keeps its recipe's native lines (libxcb, xorgproto);
	// they name host packages it does not use.
	writeInstalledDepends(t, "aarch64-libx11", "aarch64-libxcb\nlibxcb\nxorgproto\nglibc\n")
	writeInstalledDepends(t, "aarch64-libxcb", "aarch64-libxau cross\nlibxau\n")
	// The cross compiler's programs run on the host and need gmp.
	writeInstalledDepends(t, "aarch64-gcc", "aarch64-glibc cross\ngmp\nglibc\n")
	writeInstalledDepends(t, "aarch64-glibc", "")
	writeInstalledDepends(t, "glibc", "")
	// A native host tool used by the cross build.
	writeInstalledDepends(t, "cmake", "jsoncpp\nglibc\naarch64-gcc cross make\n")

	got := missingInstalledRuntimeDeps([]string{"aarch64-libx11", "aarch64-gcc", "cmake"}, cfg)
	want := map[string][]string{
		"aarch64-libxau": {"aarch64-libxcb"},
		"gmp":            {"aarch64-gcc"},
		"jsoncpp":        {"cmake"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing = %v, want %v", got, want)
	}
}

func TestCrossSessionLooksUpHostRuntimeDependencyNatively(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_CROSS_ARCH"] = "arm64"
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	writeTestPackage(t, repo, "jsoncpp", "")
	oldMirror := BinaryMirror
	BinaryMirror = ""
	t.Cleanup(func() { BinaryMirror = oldMirror })

	native := packageBuildConfig("jsoncpp", cfg)
	name := StandardizeRemoteName("jsoncpp", "1.0", "1", GetSystemArchForPackage(native, "jsoncpp"), GetSystemVariantForPackage(native, "jsoncpp"))
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(BinDir, name), []byte("pkg"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, ok, _ := availableBinaryPackageTarball("jsoncpp", native, true); !ok {
		t.Fatalf("the native %s must be found for cmake's runtime dependency", name)
	}
	// What the lookup used to do: ask for the cross target's binary.
	if _, _, ok, _ := availableBinaryPackageTarball("jsoncpp", cfg, true); ok {
		t.Fatal("expected the cross configuration to miss the native binary; the test no longer shows the difference")
	}
}
