package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAlternativeDependencyUsesPreferFile(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "xlibre", "")
	writeTestPackage(t, repo, "xorg-server", "")

	oldPrefer := PreferFile
	PreferFile = filepath.Join(t.TempDir(), "hokuto.prefer")
	t.Cleanup(func() { PreferFile = oldPrefer })
	alternativeDepCache = make(map[string]string)
	t.Cleanup(func() { alternativeDepCache = make(map[string]string) })

	dep := DepSpec{Name: "xorg-server", Alternatives: []string{"xorg-server", "xlibre"}}
	// Without the file, --yes takes the first alternative.
	if got, err := resolveAlternativeDep(dep, true, cfg, "xwayland"); err != nil || got != "xorg-server" {
		t.Fatalf("without hokuto.prefer: got %q, %v; want xorg-server", got, err)
	}

	if err := os.WriteFile(PreferFile, []byte("# display server\nmesa  xlibre # not xorg-server\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alternativeDepCache = make(map[string]string)
	// Asked interactively otherwise: the file answers instead.
	if got, err := resolveAlternativeDep(dep, false, cfg, "xwayland"); err != nil || got != "xlibre" {
		t.Fatalf("with hokuto.prefer: got %q, %v; want xlibre", got, err)
	}
}
