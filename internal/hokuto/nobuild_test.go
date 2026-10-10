package hokuto

import (
	"path/filepath"
	"strings"
	"testing"
)

func withTempNoBuild(t *testing.T) {
	t.Helper()
	old := NoBuildFile
	NoBuildFile = filepath.Join(t.TempDir(), "nobuild.json")
	t.Cleanup(func() { NoBuildFile = old })
}

func TestNoBuildCommandScopes(t *testing.T) {
	withTempNoBuild(t)
	for _, args := range [][]string{
		{"firefox", "qt"},         // bare names add native entries
		{"-cross", "firefox"},     // -cross adds a cross entry
		{"add", "-cross", "llvm"}, // explicit add
		{"add", "firefox"},        // already there: no duplicate
	} {
		if err := handleNoBuildCommand(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	entries, err := loadNoBuildList()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries = %+v", entries)
	}
	if !noBuildListed(entries, "firefox", false) || !noBuildListed(entries, "firefox", true) {
		t.Fatal("firefox should be listed for both builds")
	}
	if noBuildListed(entries, "qt", true) || !noBuildListed(entries, "qt", false) {
		t.Fatal("qt is a native entry only")
	}
	// A cross-system package counts as its recipe.
	if !noBuildListed(entries, "aarch64-llvm", true) || noBuildListed(entries, "aarch64-llvm", false) {
		t.Fatal("aarch64-llvm should follow llvm's cross entry")
	}

	if err := handleNoBuildCommand([]string{"remove", "-cross", "firefox"}); err != nil {
		t.Fatal(err)
	}
	entries, _ = loadNoBuildList()
	if noBuildListed(entries, "firefox", true) || !noBuildListed(entries, "firefox", false) {
		t.Fatal("remove -cross must keep the native entry")
	}
	if err := handleNoBuildCommand([]string{"clear", "-native"}); err != nil {
		t.Fatal(err)
	}
	entries, _ = loadNoBuildList()
	if len(entries) != 1 || !noBuildListed(entries, "llvm", true) {
		t.Fatalf("clear -native left %+v", entries)
	}
	if err := handleNoBuildCommand([]string{"clear"}); err != nil {
		t.Fatal(err)
	}
	if entries, _ = loadNoBuildList(); len(entries) != 0 {
		t.Fatalf("clear left %+v", entries)
	}
}

func TestFilterNoBuild(t *testing.T) {
	withTempNoBuild(t)
	if err := handleNoBuildCommand([]string{"qt"}); err != nil {
		t.Fatal(err)
	}
	if got := filterNoBuild([]string{"gtk", "qt", "mesa"}, false); strings.Join(got, " ") != "gtk mesa" {
		t.Fatalf("native filter = %v", got)
	}
	if got := filterNoBuild([]string{"gtk", "qt"}, true); strings.Join(got, " ") != "gtk qt" {
		t.Fatalf("a native entry must not affect cross builds: %v", got)
	}
}

func TestNoBuildNeedsRootToChange(t *testing.T) {
	for args, want := range map[string]bool{
		"nobuild":             false,
		"nobuild list":        false,
		"nobuild -cross list": false,
		"nobuild qt":          true,
		"nobuild -cross qt":   true,
		"nobuild remove qt":   true,
		"nobuild clear":       true,
	} {
		if got := needsRootPrivileges(strings.Fields(args)); got != want {
			t.Errorf("%q needs root = %v, want %v", args, got, want)
		}
	}
}
