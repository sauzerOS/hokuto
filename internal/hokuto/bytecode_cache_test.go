package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestModifiedFilesIgnorePythonBytecodeCaches(t *testing.T) {
	root := t.TempDir()
	oldRoot, oldInstalled := rootDir, Installed
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	t.Cleanup(func() { rootDir, Installed = oldRoot, oldInstalled })

	files := map[string]string{
		"usr/lib/python3.14/site-packages/inputremapper/__pycache__/installation_info.cpython-314.pyc": "rewritten by python",
		"etc/input-remapper.conf":                                  "edited by hand",
		"usr/lib/python3.14/site-packages/inputremapper/cache.pyc": "not in __pycache__",
	}
	manifest := ""
	for path, data := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		// The checksums the package was installed with: no longer these.
		manifest += "/" + path + "  0123456789abcdef\n"
	}
	if err := os.MkdirAll(filepath.Join(Installed, "input-remapper"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Installed, "input-remapper", "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	modified, err := getModifiedFiles("input-remapper", root, &Executor{Context: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, path := range modified {
		got[filepath.ToSlash(path)] = true
	}
	if got["/usr/lib/python3.14/site-packages/inputremapper/__pycache__/installation_info.cpython-314.pyc"] {
		t.Fatalf("a bytecode cache python rewrote is not a modified file: %v", modified)
	}
	if !got["/etc/input-remapper.conf"] || !got["/usr/lib/python3.14/site-packages/inputremapper/cache.pyc"] {
		t.Fatalf("other changed files must still be reported: %v", modified)
	}
}
