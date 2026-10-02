package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLocalRepoPathsSkipsMissingEntries(t *testing.T) {
	oldRepoPaths := repoPaths
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	base := t.TempDir()
	core := filepath.Join(base, "sauzeros", "core")
	if err := os.MkdirAll(core, 0o755); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(base, "file")
	if err := os.WriteFile(notDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "sauzeros", "extra")

	repoPaths = core + ":" + missing + "::" + notDir
	if got, want := localRepoPaths(), []string{core}; !reflect.DeepEqual(got, want) {
		t.Fatalf("localRepoPaths() = %v, want %v", got, want)
	}

	repoPaths = missing
	if got := localRepoPaths(); len(got) != 0 {
		t.Fatalf("localRepoPaths() = %v, want none", got)
	}
}

func TestGitRepoRootRequiresGitDirectory(t *testing.T) {
	base := t.TempDir()
	plain := filepath.Join(base, "plain", "core")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	if root, ok := gitRepoRoot(plain); ok {
		t.Fatalf("gitRepoRoot(%q) = %q, want no repository", plain, root)
	}

	repo := filepath.Join(base, "repo")
	core := filepath.Join(repo, "core")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(core, 0o755); err != nil {
		t.Fatal(err)
	}
	if root, ok := gitRepoRoot(core); !ok || root != repo {
		t.Fatalf("gitRepoRoot(%q) = %q, %v; want %q", core, root, ok, repo)
	}
}
