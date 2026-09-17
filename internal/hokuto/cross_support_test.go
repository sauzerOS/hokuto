package hokuto

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeRecipe(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPackageSupportsCrossBuildFromBuildScript(t *testing.T) {
	for _, tc := range []struct{ name, build string }{
		{"CROSS_PREFIX", "#!/bin/bash -e\nPREFIX=\"${CROSS_PREFIX:-/usr}\"\n"},
		{"HOKUTO_CROSS", "#!/bin/bash -e\nif [ \"${HOKUTO_CROSS:-0}\" = \"1\" ]; then :; fi\n"},
		{"CROSS_COMPILE", "#!/bin/bash -e\nmake ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeRecipe(t, map[string]string{"build": tc.build})
			ok, reason := packageSupportsCrossBuild(dir, map[string]bool{})
			if !ok {
				t.Errorf("not detected as cross capable: %s", reason)
			}
		})
	}
}

func TestPackageSupportsCrossBuildFromCrossDependencies(t *testing.T) {
	// shadow and linux-rpi4 carry cross dependencies without naming hokuto's
	// variables in their build script.
	dir := writeRecipe(t, map[string]string{
		"build":   "#!/bin/bash -e\nmake install DESTDIR=\"$1\"\n",
		"depends": "glibc\naarch64-glibc cross\naarch64-gcc cross make\n",
	})
	ok, reason := packageSupportsCrossBuild(dir, map[string]bool{})
	if !ok {
		t.Errorf("cross dependencies should mark the recipe as adapted, got: %s", reason)
	}
}

func TestPackageSupportsCrossBuildRejectsPlainRecipe(t *testing.T) {
	dir := writeRecipe(t, map[string]string{
		"build":   "#!/bin/bash -e\n./configure --prefix=/usr\nmake\nmake install DESTDIR=\"$1\"\n",
		"depends": "glibc\nzlib\n",
	})
	if ok, _ := packageSupportsCrossBuild(dir, map[string]bool{}); ok {
		t.Error("a recipe with no cross handling at all should be rejected")
	}
}

func TestPackageSupportsCrossBuildOptionsWin(t *testing.T) {
	plain := map[string]string{"build": "#!/bin/bash -e\nmake\n"}
	if ok, _ := packageSupportsCrossBuild(writeRecipe(t, plain), map[string]bool{crossSupportOption: true}); !ok {
		t.Error("the cross option should mark an otherwise plain recipe as adapted")
	}

	adapted := map[string]string{"build": "#!/bin/bash -e\nPREFIX=\"${CROSS_PREFIX:-/usr}\"\n"}
	if ok, _ := packageSupportsCrossBuild(writeRecipe(t, adapted), map[string]bool{noCrossSupportOption: true}); ok {
		t.Error("the nocross option must override what the recipe looks like")
	}
}

func TestBuildScriptCrossMarkersIgnoreComments(t *testing.T) {
	// A recipe should not be credited for merely mentioning cross builds in a
	// comment, which is how a note like "TODO: handle CROSS_PREFIX" reads.
	dir := writeRecipe(t, map[string]string{
		"build": "#!/bin/bash -e\n# TODO: adapt this for CROSS_PREFIX one day\nmake\n",
	})
	if ok, _ := packageSupportsCrossBuild(dir, map[string]bool{}); ok {
		t.Error("a commented-out mention should not count as cross support")
	}

	// But a trailing comment must not hide real code on the same line.
	dir = writeRecipe(t, map[string]string{
		"build": "#!/bin/bash -e\nPREFIX=\"${CROSS_PREFIX:-/usr}\"  # target prefix\n",
	})
	if ok, _ := packageSupportsCrossBuild(dir, map[string]bool{}); !ok {
		t.Error("code followed by a comment should still count")
	}
}

func TestStripShellComment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"make install", "make install"},
		{"# whole line", ""},
		{"make  # trailing", "make  "},
		{"url=https://x/y.git#tag=v1", "url=https://x/y.git#tag=v1"},
		{`echo "a # b"`, `echo "a # b"`},
		{"echo 'a # b'", "echo 'a # b'"},
	} {
		if got := stripShellComment(tc.in); got != tc.want {
			t.Errorf("stripShellComment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPackageSupportsCrossBuildMissingBuildScript(t *testing.T) {
	if ok, _ := packageSupportsCrossBuild(t.TempDir(), map[string]bool{}); ok {
		t.Error("a recipe with no build script should not be treated as adapted")
	}
}

func TestBuiltForAnotherRoot(t *testing.T) {
	tests := []struct {
		name string
		vals map[string]string
		want bool
	}{
		// A plain cross build produces packages for the target device.
		{"plain cross", map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}, true},
		// A cross-system build produces sysroot packages that belong here.
		{"cross system", map[string]string{"HOKUTO_CROSS_ARCH": "arm64", "HOKUTO_CROSS_SYSTEM": "1"}, false},
		// A native build, and a native dependency built during a cross session
		// (its per-package config has the cross values cleared).
		{"native", map[string]string{}, false},
		{"native dep in cross session", map[string]string{"HOKUTO_CROSS_ARCH": "", "HOKUTO_CROSS_SYSTEM": ""}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := builtForAnotherRoot(&Config{Values: tc.vals}); got != tc.want {
				t.Errorf("builtForAnotherRoot(%v) = %v, want %v", tc.vals, got, tc.want)
			}
		})
	}
	if builtForAnotherRoot(nil) {
		t.Error("a nil config should not be treated as a foreign root")
	}
}

func TestPreInstallUninstallSkippedDuringCrossBuild(t *testing.T) {
	// python-* packages are set to uninstall themselves before install, which
	// during a cross build would remove the host's own copy of a build tool.
	// getPackageDependenciesToUninstall still reports it; the hook is what must
	// decline to act on it.
	if got := getPackageDependenciesToUninstall("python-flit-core"); len(got) != 1 || got[0] != "python-flit-core" {
		t.Fatalf("getPackageDependenciesToUninstall = %v, want [python-flit-core]", got)
	}

	crossCfg := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}}
	if !builtForAnotherRoot(crossCfg) {
		t.Fatal("a plain cross build should be recognised as building for another root")
	}

	// The call must return without touching the installed package database.
	// With no installed tree configured, any real uninstall attempt would be
	// visible as a change here.
	oldInstalled := Installed
	Installed = t.TempDir()
	t.Cleanup(func() { Installed = oldInstalled })
	before, _ := os.ReadDir(Installed)
	handlePreInstallUninstall("python-flit-core", crossCfg, nil, true, io.Discard)
	after, _ := os.ReadDir(Installed)
	if len(before) != len(after) {
		t.Errorf("the hook touched the installed tree during a cross build")
	}
}
