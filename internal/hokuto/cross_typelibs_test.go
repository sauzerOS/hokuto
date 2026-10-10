package hokuto

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestIsIntrospectionDataPath(t *testing.T) {
	for name, want := range map[string]bool{
		"usr/lib/girepository-1.0/Gtk-3.0.typelib": true,
		"usr/share/gir-1.0/Gtk-3.0.gir":            true,
		"usr/share/vala/vapi/gtk+-3.0.vapi":        true,
		"usr/lib/girepository-1.0/":                false,
		"usr/lib/girepository-1.0/sub/x.typelib":   false,
		"usr/lib/libgtk-3.so.0":                    false,
		"var/db/hokuto/installed/gtk+3/manifest":   false,
	} {
		if got := isIntrospectionDataPath(name); got != want {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

func TestRecipeUsesIntrospection(t *testing.T) {
	dir := t.TempDir()
	write := func(depends string) {
		if err := os.WriteFile(filepath.Join(dir, "depends"), []byte(depends), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("glib\ngobject-introspection make\nmeson make\n")
	if !recipeUsesIntrospection(dir) {
		t.Error("gobject-introspection make: want true")
	}
	write("glib\nmeson make\naarch64-gobject-introspection cross make\n")
	if recipeUsesIntrospection(dir) {
		t.Error("no native gobject-introspection dependency: want false")
	}
}

func TestIntrospectionSourceEntry(t *testing.T) {
	index := []RepoEntry{
		{Name: "gtk+3", Version: "3.24.50", Revision: "1", Arch: "x86_64", Variant: "generic", Filename: "g"},
		{Name: "gtk+3", Version: "3.24.50", Revision: "1", Arch: "x86_64", Variant: "optimized", Filename: "o"},
		{Name: "gtk+3", Version: "3.24.50", Revision: "1", Arch: "aarch64", Variant: "optimized", Filename: "a"},
		{Name: "gtk+3", Version: "3.24.49", Revision: "1", Arch: "x86_64", Variant: "optimized", Filename: "old"},
	}
	if e := introspectionSourceEntry(index, "gtk+3", "3.24.50", "1"); e == nil || e.Filename != "o" {
		t.Fatalf("got %+v, want the optimized x86_64 package", e)
	}
	if e := introspectionSourceEntry(index, "gtk+3", "3.24.50", "2"); e != nil {
		t.Fatalf("another revision must not match: %+v", e)
	}
}

func TestCopyIntrospectionData(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "gtk.tar.zst")
	f, err := os.Create(tarball)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	files := map[string]string{
		"./usr/lib/girepository-1.0/Gtk-3.0.typelib": "typelib",
		"./usr/lib/girepository-1.0/Gdk-3.0.typelib": "x86 gdk",
		"./usr/share/gir-1.0/Gtk-3.0.gir":            "<gir/>",
		"./usr/lib/libgtk-3.so.0":                    "x86 elf",
	}
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./usr/share/vala/vapi/gtk+-3.0.deps", Typeflag: tar.TypeSymlink, Linkname: "gtk3.deps"}); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	zw.Close()
	f.Close()

	out := filepath.Join(dir, "out")
	// The cross build's own file is kept.
	own := filepath.Join(out, "usr", "lib", "girepository-1.0", "Gdk-3.0.typelib")
	if err := os.MkdirAll(filepath.Dir(own), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("aarch64 gdk"), 0o644); err != nil {
		t.Fatal(err)
	}

	copied, err := copyIntrospectionData(tarball, out)
	if err != nil {
		t.Fatal(err)
	}
	if copied != 3 {
		t.Fatalf("copied %d files, want 3", copied)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "usr", "lib", "girepository-1.0", "Gtk-3.0.typelib")); string(b) != "typelib" {
		t.Errorf("Gtk typelib = %q", b)
	}
	if b, _ := os.ReadFile(own); string(b) != "aarch64 gdk" {
		t.Errorf("the output's own typelib was replaced: %q", b)
	}
	if _, err := os.Stat(filepath.Join(out, "usr", "lib", "libgtk-3.so.0")); !os.IsNotExist(err) {
		t.Error("a non-introspection file was copied")
	}
	if l, err := os.Readlink(filepath.Join(out, "usr", "share", "vala", "vapi", "gtk+-3.0.deps")); err != nil || l != "gtk3.deps" {
		t.Errorf("symlink = %q, %v", l, err)
	}
}
