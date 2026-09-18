package hokuto

import "testing"

// TestParseDependsNoCrossFlag covers the "nocross" flag: a dependency of the
// native build that must not be recorded in a cross-built package, which would
// otherwise demand packages the target neither needs nor has.
func TestParseDependsNoCrossFlag(t *testing.T) {
	deps, err := parseDependsData([]byte(`
libdrm
libglvnd nocross
llvm-libs nocross
wayland nocross runtime
spirv-tools make
aarch64-libdrm cross make
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]DepSpec{}
	for _, d := range deps {
		got[d.Name] = d
	}
	for _, name := range []string{"libglvnd", "llvm-libs", "wayland"} {
		d, ok := got[name]
		if !ok {
			t.Fatalf("%s missing from parsed deps", name)
		}
		if !d.NoCross {
			t.Errorf("%s: NoCross = false, want true", name)
		}
	}
	if got["libdrm"].NoCross {
		t.Error("libdrm: NoCross = true, want false (no flag given)")
	}
	if !got["wayland"].RuntimeOnly {
		t.Error("wayland: nocross must not swallow the runtime flag beside it")
	}
	if !got["aarch64-libdrm"].Cross {
		t.Error("aarch64-libdrm: cross flag lost")
	}
}

func TestCrossBuildActiveToggles(t *testing.T) {
	t.Cleanup(func() { setCrossBuildActive(false) })
	setCrossBuildActive(false)
	if crossBuildInProgress() {
		t.Fatal("expected no cross build in progress")
	}
	setCrossBuildActive(true)
	if !crossBuildInProgress() {
		t.Fatal("expected cross build in progress")
	}
}
