package hokuto

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBumpPerlDependentsBumpsPerlXSRecipesAndCommits(t *testing.T) {
	repo := t.TempDir()
	oldRepoPaths := repoPaths
	repoPaths = repo
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	runGit := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v: %s", args, err, out)
		}
		return string(out)
	}
	runGit("init", "-q")
	runGit("config", "user.name", "Hokuto Test")
	runGit("config", "user.email", "test@sauzeros.invalid")

	recipes := map[string]map[string]string{
		"perl":            {"version": "5.44.0 1\n"},
		"perl-xml-parser": {"version": "2.47 3\n", "options": "perlxs\n"},
		"texinfo":         {"version": "7.3 1\n", "depends": "perl\n", "options": "nolto\nperlxs\n"},
		"vim":             {"version": "9.2\n", "options": "perlxs\n"},
		"perl-json":       {"version": "4.10 1\n", "depends": "perl\n"},
		"llvm":            {"version": "22.1.8 1\n", "depends": "perl\n", "options": "nocrossopt\n"},
		"unrelated":       {"version": "1.0 1\n"},
		"no-version-file": {"options": "perlxs\n"},
	}
	for name, files := range recipes {
		dir := filepath.Join(repo, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, data := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Unrelated staged work must not end up in the bump commit.
	if err := os.WriteFile(filepath.Join(repo, "unrelated", "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit("add", ".")
	runGit("commit", "-q", "-m", "initial", "--", ".", ":!unrelated/build")
	runGit("add", "unrelated/build")

	if err := bumpPerlDependents("5.44.0"); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"perl":            "5.44.0 1",
		"perl-xml-parser": "2.47 4",
		"texinfo":         "7.3 2",
		"vim":             "9.2 2",
		"perl-json":       "4.10 1",
		"llvm":            "22.1.8 1",
		"unrelated":       "1.0 1",
	}
	for name, version := range want {
		data, err := os.ReadFile(filepath.Join(repo, name, "version"))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(data)); got != version {
			t.Errorf("%s: version %q, want %q", name, got, version)
		}
	}

	if msg := strings.TrimSpace(runGit("log", "-1", "--pretty=%s")); msg != "perl 5.44.0: bump revision of dependent packages" {
		t.Errorf("unexpected commit message %q", msg)
	}
	committed := strings.Fields(runGit("show", "--name-only", "--pretty=", "HEAD"))
	wantCommitted := []string{"perl-xml-parser/version", "texinfo/version", "vim/version"}
	if strings.Join(committed, " ") != strings.Join(wantCommitted, " ") {
		t.Errorf("commit touched %v, want %v", committed, wantCommitted)
	}
	if staged := strings.TrimSpace(runGit("diff", "--cached", "--name-only")); staged != "unrelated/build" {
		t.Errorf("unrelated staged work should stay staged, got %q", staged)
	}
}

func TestPerlAPIVersion(t *testing.T) {
	for _, tc := range []struct {
		old, new string
		changed  bool
	}{
		{"5.42.2", "5.44.0", true},
		{"5.42.1", "5.42.2", false},
		{"5.44.0", "5.44.0", false},
	} {
		if got := perlAPIVersion(tc.old) != perlAPIVersion(tc.new); got != tc.changed {
			t.Errorf("%s -> %s: API changed = %v, want %v", tc.old, tc.new, got, tc.changed)
		}
	}
}

func TestFindPerlXSObjects(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	root := t.TempDir()
	build := func(rel, src string) {
		t.Helper()
		out := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		c := filepath.Join(t.TempDir(), "x.c")
		if err := os.WriteFile(c, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if b, err := exec.Command(cc, "-shared", "-fPIC", "-o", out, c).CombinedOutput(); err != nil {
			t.Fatalf("cc: %v: %s", err, b)
		}
	}
	build("usr/lib/perl5/vendor_perl/auto/XML/Parser/Expat/Expat.so", "void Perl_newSV(void); void boot(void) { Perl_newSV(); }\n")
	build("usr/lib/libz.so.1", "int deflate(void) { return 0; }\n")
	if err := os.WriteFile(filepath.Join(root, "usr/lib/notes.so.txt"), []byte("not elf"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := findPerlXSObjects(root)
	if want := []string{"/usr/lib/perl5/vendor_perl/auto/XML/Parser/Expat/Expat.so"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
