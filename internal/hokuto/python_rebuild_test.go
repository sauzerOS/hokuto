package hokuto

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, data := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindPythonVersionedFile(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"site-packages": {map[string]string{"usr/lib/python3.14/site-packages/foo/__init__.py": ""}, "/usr/lib/python3.14/site-packages/foo/__init__.py"},
		"lib32":         {map[string]string{"usr/lib32/python3.14/site-packages/foo.py": ""}, "/usr/lib32/python3.14/site-packages/foo.py"},
		"cross sysroot": {map[string]string{"usr/aarch64-linux-gnu/lib/python3.14/site-packages/foo.py": ""}, "/usr/aarch64-linux-gnu/lib/python3.14/site-packages/foo.py"},
		"libpython": {map[string]string{
			"usr/bin/gdb":                         "",
			"var/db/hokuto/installed/gdb/libdeps": "elf64:libc.so.6\nelf64:libpython3.14.so.1.0\n",
		}, "elf64:libpython3.14.so.1.0"},
		// Unversioned Python paths survive an upgrade.
		"unversioned": {map[string]string{
			"usr/share/glib-2.0/codegen/parser.py": "",
			"usr/bin/script":                       "#!/usr/bin/python3\n",
			"var/db/hokuto/installed/gdb/libdeps":  "elf64:libc.so.6\n",
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, tc.files)
			got := findPythonVersionedFile(dir, filepath.Join(dir, "var/db/hokuto/installed/gdb/libdeps"))
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWarnMissingPythonRebuildOption(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"usr/lib/python3.14/site-packages/libxml2mod.so": ""})
	var out bytes.Buffer
	warnMissingPythonRebuildOption("libxml2", "libxml2-python", dir, map[string]bool{}, &out)
	if !strings.Contains(out.String(), "libxml2-python installs Python modules") || !strings.Contains(out.String(), "options file of libxml2 lacks") {
		t.Fatalf("no warning: %q", out.String())
	}
	out.Reset()
	warnMissingPythonRebuildOption("libxml2", "libxml2-python", dir, map[string]bool{pythonRebuildOption: true}, &out)
	warnMissingPythonRebuildOption("python", "python", dir, map[string]bool{}, &out)
	if out.Len() != 0 {
		t.Fatalf("unexpected warning: %q", out.String())
	}
}

// The bootstrap stage is the marked build tools and the marked recipes they
// need; unmarked dependencies (python itself) and cross lines stay out.
func TestPythonBootstrapSet(t *testing.T) {
	repo := t.TempDir()
	recipes := map[string]string{
		"python-build":           "python\npython-packaging\npython-pyproject-hooks\npython-flit-core make\n",
		"python-flit-core":       "python\npython-installer make\n",
		"python-installer":       "python\n",
		"python-packaging":       "python\n",
		"python-pyproject-hooks": "python\npython-wheel make\naarch64-python-foo cross\n",
		"python-wheel":           "python\n",
		"python-foo":             "python\n",
		"meson":                  "python\npython-setuptools make\nninja\n",
		"python-setuptools":      "python\npython-trove | python-other make\n",
		"python-trove":           "python\n",
	}
	marked := make(map[string]string)
	for name, depends := range recipes {
		dir := filepath.Join(repo, name)
		writeTree(t, dir, map[string]string{"depends": depends, "version": "1 1\n"})
		marked[name] = dir
	}
	got := pythonBootstrapSet(marked)
	want := []string{"meson", "python-build", "python-flit-core", "python-installer", "python-packaging",
		"python-pyproject-hooks", "python-setuptools", "python-trove", "python-wheel"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bootstrap set = %v, want %v", got, want)
	}
}

// After an upgrade, the build tools' old site-packages entries are linked
// into one PYTHONPATH directory; without one there is nothing to do.
func TestPythonBootstrapPath(t *testing.T) {
	root := t.TempDir()
	installed := filepath.Join(root, "var/db/hokuto/installed")
	oldRoot, oldInstalled := rootDir, Installed
	rootDir, Installed = root, installed
	t.Cleanup(func() { rootDir, Installed = oldRoot, oldInstalled })
	writeTree(t, installed, map[string]string{
		"python-build/manifest": "/usr/\n/usr/lib/python3.14/\n/usr/lib/python3.14/site-packages/\n" +
			"/usr/lib/python3.14/site-packages/build/__init__.py  abc\n" +
			"/usr/lib/python3.14/site-packages/build-1.3.dist-info/METADATA  abc\n" +
			"/usr/bin/pyproject-build  abc\n",
		"meson/manifest":            "/usr/lib/python3.14/site-packages/mesonbuild/mesonmain.py  abc\n",
		"python-installer/manifest": "/usr/lib/python3.15/site-packages/installer/__init__.py  abc\n",
	})

	path, err := pythonBootstrapPath([]string{"python-build", "meson", "python-installer"}, "3.15")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(path) })
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"build", "build-1.3.dist-info", "mesonbuild"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("linked %v, want %v (installer is already built for 3.15)", names, want)
	}
	if target, _ := os.Readlink(filepath.Join(path, "mesonbuild")); target != filepath.Join(root, "usr/lib/python3.14/site-packages/mesonbuild") {
		t.Fatalf("mesonbuild -> %q", target)
	}

	none, err := pythonBootstrapPath([]string{"python-installer"}, "3.15")
	if err != nil || none != "" {
		t.Fatalf("no upgrade in progress: got %q, %v", none, err)
	}
}

func TestBuiltRecipePackage(t *testing.T) {
	dir := t.TempDir()
	recipe := filepath.Join(t.TempDir(), "python-foo")
	writeTree(t, recipe, map[string]string{"version": "2.0 3\n"})
	writeTree(t, dir, map[string]string{
		"python-foo-2.0-2-x86_64-optimized.tar.zst":     "",
		"python-foo-bar-2.0-3-x86_64-optimized.tar.zst": "",
	})
	if builtRecipePackage(dir, "python-foo", recipe) {
		t.Fatal("an older revision or another package counted as built")
	}
	writeTree(t, dir, map[string]string{"python-foo-2.0-3-x86_64-optimized.tar.zst": ""})
	if !builtRecipePackage(dir, "python-foo", recipe) {
		t.Fatal("the current revision was not found")
	}
}
