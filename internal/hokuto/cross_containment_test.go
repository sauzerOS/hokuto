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
