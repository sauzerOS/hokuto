package hokuto

import "testing"

func TestApplyMoldLinker(t *testing.T) {
	old := moldInstalled
	t.Cleanup(func() { moldInstalled = old })
	const lto = "-fuse-ld=bfd -flto=8 -O1"

	moldInstalled = func() bool { return true }
	if got := applyMoldLinker(lto, map[string]bool{}); got != "-fuse-ld=mold -flto=8 -O1 -Wl,--undefined-version" {
		t.Errorf("LTO build with mold installed: %q", got)
	}
	if got := applyMoldLinker(lto, map[string]bool{"nomold": true}); got != lto {
		t.Errorf("nomold should keep ld.bfd: %q", got)
	}
	if got := applyMoldLinker("-fuse-ld=gold", map[string]bool{}); got != "-fuse-ld=mold -Wl,--undefined-version" {
		t.Errorf("gold should become mold: %q", got)
	}

	if got := applyMoldLinker("-fuse-ld=mold -Wl,--undefined-version", map[string]bool{}); got != "-fuse-ld=mold -Wl,--undefined-version" {
		t.Errorf("the flag must not be added twice: %q", got)
	}

	moldInstalled = func() bool { return false }
	if got := applyMoldLinker("-fuse-ld=mold -O1", map[string]bool{}); got != "-fuse-ld=bfd -O1" {
		t.Errorf("without mold the build must fall back to ld.bfd: %q", got)
	}
}
