package hokuto

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateLibDepsRecordsOnlyDirectDependencies builds:
//   - libext.so outside the package, itself linked against libm
//   - libown.so inside the package
//   - libver.so.1.0.0 inside the package, reached through its soname
//     symlink libver.so.1
//   - usr/bin/app inside the package, linked against libext, libown and libver
//   - a usr/lib/libext.so.1 symlink pointing outside the package
//
// libdeps must list libext (a direct DT_NEEDED of app) but neither libm
// (only needed by libext, i.e. indirect) nor libown and libver (provided by
// the package, libver only under its soname symlink). The out-of-tree
// libext.so.1 link does not make libext provided.
func TestGenerateLibDepsRecordsOnlyDirectDependencies(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %v: %v\n%s", args, err, out)
		}
	}
	src := t.TempDir()
	write := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(src, "ext.c"), "#include <math.h>\ndouble ext(double x) { return sqrt(x); }\n", 0o644)
	write(filepath.Join(src, "own.c"), "int own(void) { return 1; }\n", 0o644)
	write(filepath.Join(src, "ver.c"), "int ver(void) { return 2; }\n", 0o644)
	write(filepath.Join(src, "app.c"), "double ext(double); int own(void); int ver(void);\nint main(void) { return (int)ext(own() + ver()); }\n", 0o644)

	extDir := t.TempDir()
	pkg := t.TempDir()
	libDir := filepath.Join(pkg, "usr", "lib")
	binDir := filepath.Join(pkg, "usr", "bin")
	for _, d := range []string{libDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run("-shared", "-fPIC", "-Wl,-soname,libext.so.1", "-o", filepath.Join(extDir, "libext.so.1"), filepath.Join(src, "ext.c"), "-lm")
	if err := os.Symlink("libext.so.1", filepath.Join(extDir, "libext.so")); err != nil {
		t.Fatal(err)
	}
	run("-shared", "-fPIC", "-Wl,-soname,libown.so", "-o", filepath.Join(libDir, "libown.so"), filepath.Join(src, "own.c"))
	run("-shared", "-fPIC", "-Wl,-soname,libver.so.1", "-o", filepath.Join(libDir, "libver.so.1.0.0"), filepath.Join(src, "ver.c"))
	for link, target := range map[string]string{"libver.so.1": "libver.so.1.0.0", "libver.so": "libver.so.1"} {
		if err := os.Symlink(target, filepath.Join(libDir, link)); err != nil {
			t.Fatal(err)
		}
	}
	run("-Wl,--no-as-needed", "-o", filepath.Join(binDir, "app"), filepath.Join(src, "app.c"), "-L"+extDir, "-lext", "-L"+libDir, "-lown", "-lver")
	// Named like the external library but leading out of the package.
	if err := os.Symlink("/opt/elsewhere/libext.so.1", filepath.Join(libDir, "libext.so.1")); err != nil {
		t.Fatal(err)
	}
	// Neither a script nor a non-executable file may be inspected.
	write(filepath.Join(binDir, "script"), "#!/bin/sh\nexit 0\n", 0o755)
	write(filepath.Join(pkg, "usr", "share", "data.bin"), "\x7fELF garbage", 0o644)

	libdeps := filepath.Join(t.TempDir(), "libdeps")
	if err := generateLibDeps(pkg, libdeps, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(libdeps)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(data))
	has := func(lib string) bool {
		for _, g := range got {
			if g == "elf64:"+lib {
				return true
			}
		}
		return false
	}
	if !has("libext.so.1") || !has("libc.so.6") {
		t.Errorf("direct dependencies missing: %v", got)
	}
	if has("libm.so.6") {
		t.Errorf("libm is only needed by libext (indirect) and must not be listed: %v", got)
	}
	if has("libown.so") {
		t.Errorf("libown is provided by the package and must be filtered out: %v", got)
	}
	if has("libver.so.1") {
		t.Errorf("libver.so.1 is a soname symlink inside the package and must be filtered out: %v", got)
	}
}

func TestGenerateLibDepsWritesEmptyFileWithoutELF(t *testing.T) {
	pkg := t.TempDir()
	if err := os.WriteFile(filepath.Join(pkg, "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	libdeps := filepath.Join(t.TempDir(), "libdeps")
	if err := generateLibDeps(pkg, libdeps, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(libdeps); err != nil || len(data) != 0 {
		t.Fatalf("expected an empty libdeps file, got %q (%v)", data, err)
	}
}
