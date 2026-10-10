package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestUnmanagedFileIsDebris(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(name, target string) string {
		p := filepath.Join(dir, name)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	incoming := write("incoming", "print('hi')\n")
	for name, tc := range map[string]struct {
		target, incoming string
		want             bool
	}{
		"empty file":       {write("empty", ""), incoming, true},
		"same contents":    {write("same", "print('hi')\n"), incoming, true},
		"other contents":   {write("other", "print('bye')\n"), incoming, false},
		"same symlink":     {link("l1", "python3.14"), link("l2", "python3.14"), true},
		"other symlink":    {link("l3", "python3.13"), link("l4", "python3.14"), false},
		"symlink vs file":  {link("l5", "incoming"), incoming, false},
		"missing incoming": {write("x", ""), filepath.Join(dir, "nope"), false},
	} {
		if got := unmanagedFileIsDebris(tc.target, tc.incoming); got != tc.want {
			t.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
	}
}

// Empty or identical files no package owns are taken over by the incoming
// package, and the "unmanaged" alternative an earlier install recorded for one
// of them is forgotten; a file with other contents is still kept as an
// alternative.
func TestCheckStagingConflictsTakesOverUnmanagedDebris(t *testing.T) {
	root := t.TempDir()
	stagingDir := t.TempDir()
	oldInstalled := Installed
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	t.Cleanup(func() { Installed = oldInstalled })

	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sum := strings.Repeat("0", 64)
	var manifest strings.Builder
	for name, existing := range map[string]string{"empty": "", "same": "incoming same\n", "user": "edited by the user\n"} {
		write(filepath.Join(root, "usr", "lib", name), existing)
		write(filepath.Join(stagingDir, "usr", "lib", name), "incoming "+name+"\n")
		manifest.WriteString("/usr/lib/" + name + "  " + sum + "\n")
	}
	if err := os.Symlink("python3.14", filepath.Join(root, "usr", "lib", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("python3.14", filepath.Join(stagingDir, "usr", "lib", "link")); err != nil {
		t.Fatal(err)
	}
	manifest.WriteString("/usr/lib/link  " + sum + "\n")
	manifestPath := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", "newpkg", "manifest")
	write(manifestPath, manifest.String())

	// What an earlier install recorded for the empty file.
	emptySum := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	write(filepath.Join(root, GlobalAlternativesDBPath), `{"files": {"/usr/lib/empty": {"path": "/usr/lib/empty", "alternatives": [
		{"b3sum": "`+emptySum+`", "owners": ["unmanaged"], "state": "active", "mode": "0644", "uid": 0, "gid": 0, "type": "regular"}]}}}`)

	execCtx := &Executor{Context: context.Background()}
	if err := checkStagingConflicts("newpkg", stagingDir, root, manifestPath, execCtx, true, false, map[string]bool{}, nil); err != nil {
		t.Fatal(err)
	}

	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty", "same", "link"} {
		if entry := db.Files["/usr/lib/"+name]; entry != nil {
			t.Errorf("%s: taken over, but still has alternatives %#v", name, entry)
		}
	}
	entry := db.Files["/usr/lib/user"]
	if entry == nil || len(entry.Alternatives) != 2 {
		t.Fatalf("user's file: want two alternatives, got %#v", entry)
	}
	for _, alt := range entry.Alternatives {
		if alt.State == StateStashed && !slices.Equal(alt.Owners, []string{"unmanaged"}) {
			t.Errorf("user's file: stashed owned by %v, want [unmanaged]", alt.Owners)
		}
	}
}
