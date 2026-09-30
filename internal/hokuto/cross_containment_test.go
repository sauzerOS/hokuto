package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stageFile(t *testing.T, root, rel string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCrossSystemContainmentAcceptsSysrootAndMetadata(t *testing.T) {
	dir := t.TempDir()
	stageFile(t, dir, "usr/aarch64-linux-gnu/lib/libharfbuzz.so.0")
	stageFile(t, dir, "usr/aarch64-linux-gnu/lib/pkgconfig/harfbuzz.pc")
	stageFile(t, dir, "var/db/hokuto/installed/aarch64-harfbuzz/manifest")

	if err := verifyCrossSystemContainment(dir, "/usr/aarch64-linux-gnu"); err != nil {
		t.Fatalf("expected containment to pass, got %v", err)
	}
}

func TestVerifyCrossSystemContainmentRejectsHostPaths(t *testing.T) {
	dir := t.TempDir()
	stageFile(t, dir, "usr/aarch64-linux-gnu/lib/libfoo.so.0")
	stageFile(t, dir, "usr/lib/libharfbuzz.so.0")
	stageFile(t, dir, "usr/include/hb.h")

	err := verifyCrossSystemContainment(dir, "/usr/aarch64-linux-gnu")
	if err == nil {
		t.Fatal("expected a package escaping its sysroot to be rejected")
	}
	if !strings.Contains(err.Error(), "/usr/lib/libharfbuzz.so.0") {
		t.Fatalf("error should name the offending file, got %v", err)
	}
	if !strings.Contains(err.Error(), "2 file(s)") {
		t.Fatalf("error should count every stray file, got %v", err)
	}
}

func TestVerifyCrossSystemContainmentAcceptsCrossToolchainLayout(t *testing.T) {
	// aarch64-gcc and aarch64-binutils install their host programs and
	// support files outside the sysroot, all named after the triplet.
	dir := t.TempDir()
	stageFile(t, dir, "usr/aarch64-linux-gnu/lib/libgcc_s.so.1")
	stageFile(t, dir, "usr/bin/aarch64-linux-gnu-gcc")
	stageFile(t, dir, "usr/lib/gcc/aarch64-linux-gnu/16.2.0/cc1")
	stageFile(t, dir, "usr/lib/gcc/aarch64-linux-gnu/16.2.0/include/arm_neon.h")

	if err := verifyCrossSystemContainment(dir, "/usr/aarch64-linux-gnu"); err != nil {
		t.Fatalf("cross toolchain layout should pass, got %v", err)
	}

	// Anything a native package could also own still fails.
	stageFile(t, dir, "usr/share/info/gcc.info")
	stageFile(t, dir, "usr/lib/gcc/x86_64-pc-linux-gnu/16.2.0/cc1")
	err := verifyCrossSystemContainment(dir, "/usr/aarch64-linux-gnu")
	if err == nil || !strings.Contains(err.Error(), "2 file(s)") {
		t.Fatalf("host-named paths must still be rejected, got %v", err)
	}
}

func TestVerifyCrossSystemContainmentSkippedWhenNotCrossSystem(t *testing.T) {
	dir := t.TempDir()
	stageFile(t, dir, "usr/lib/libfoo.so.0")

	if err := verifyCrossSystemContainment(dir, ""); err != nil {
		t.Fatalf("a non cross,system build must not be checked, got %v", err)
	}
}

func TestCrossSystemSysrootForOnlyTriggersOnSysrootPrefix(t *testing.T) {
	sysCfg := &Config{Values: map[string]string{"HOKUTO_CROSS_SYSTEM": "1"}}
	defs := map[string]string{"CROSS_PREFIX": "/usr/aarch64-linux-gnu"}
	if got := crossSystemSysrootFor(sysCfg, defs); got != "/usr/aarch64-linux-gnu" {
		t.Fatalf("cross,system build should report its sysroot, got %q", got)
	}

	// A plain cross build targets the Pi's own rootfs, where /usr is correct.
	plainCfg := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}}
	if got := crossSystemSysrootFor(plainCfg, map[string]string{"CROSS_PREFIX": "/usr"}); got != "" {
		t.Fatalf("plain cross build must not be containment checked, got %q", got)
	}
}
