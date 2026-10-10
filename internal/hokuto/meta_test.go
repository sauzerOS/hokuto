package hokuto

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePkgDBIncludesMetaPackages(t *testing.T) {
	oldRepoPaths := repoPaths
	oldPkgDBPath := PkgDBPath
	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		PkgDBPath = oldPkgDBPath
	})

	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".hokuto"), 0o755); err != nil {
		t.Fatal(err)
	}
	repoPaths = repo
	PkgDBPath = filepath.Join(tmp, "pkg-db.json.zst")

	manifest := `[gcc-libs]
description = "Runtime libraries shipped by GCC"
depends = [
  "libgcc",
  "libstdc++",
]
`
	if err := os.WriteFile(filepath.Join(repo, ".hokuto", "metapackages.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := GeneratePkgDB(&Config{Values: map[string]string{}}); err != nil {
		t.Fatal(err)
	}

	db, err := readPkgDB(PkgDBPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range db.Packages {
		if entry.Name != "gcc-libs" {
			continue
		}
		if entry.Type != "meta" {
			t.Fatalf("expected gcc-libs to be marked as meta, got type %q", entry.Type)
		}
		if entry.Version != "meta" {
			t.Fatalf("expected meta version marker, got %q", entry.Version)
		}
		if entry.Metadata.Description != "Runtime libraries shipped by GCC" {
			t.Fatalf("unexpected description: %q", entry.Metadata.Description)
		}
		if len(entry.Metadata.Tags) != 1 || entry.Metadata.Tags[0] != "meta" {
			t.Fatalf("expected meta tag, got %v", entry.Metadata.Tags)
		}
		return
	}

	t.Fatal("gcc-libs metapackage not found in generated package database")
}

func TestGeneratePkgDBAppliesSplitMetadataOverrides(t *testing.T) {
	oldRepoPaths := repoPaths
	oldPkgDBPath := PkgDBPath
	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		PkgDBPath = oldPkgDBPath
	})

	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	pkgDir := filepath.Join(repo, "vlc")
	if err := os.MkdirAll(filepath.Join(pkgDir, "split", "libvlc"), 0o755); err != nil {
		t.Fatal(err)
	}
	repoPaths = repo
	PkgDBPath = filepath.Join(tmp, "pkg-db.json.zst")

	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("3.0.23 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "split", "libvlc", "depends"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	metadata := `{
  "url": "https://www.videolan.org/vlc/",
  "category": "extra",
  "description": "Free and open source cross-platform multimedia player and framework",
  "info": "",
  "license": "LGPL",
  "tags": ["gui", "multimedia", "utility"],
  "split_metadata": {
    "libvlc": {
      "description": "VLC media framework runtime library",
      "tags": ["library", "multimedia"]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(pkgDir, "metadata.json"), []byte(metadata), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := GeneratePkgDB(&Config{Values: map[string]string{}}); err != nil {
		t.Fatal(err)
	}

	db, err := readPkgDB(PkgDBPath)
	if err != nil {
		t.Fatal(err)
	}

	var parent, split *PkgDBEntry
	for i := range db.Packages {
		switch db.Packages[i].Name {
		case "vlc":
			parent = &db.Packages[i]
		case "libvlc":
			split = &db.Packages[i]
		}
	}
	if parent == nil {
		t.Fatal("vlc package not found")
	}
	if parent.Metadata.Description != "Free and open source cross-platform multimedia player and framework" {
		t.Fatalf("unexpected parent description: %q", parent.Metadata.Description)
	}
	if parent.Metadata.SplitMetadata != nil {
		t.Fatalf("split overrides should not be exported on parent DB entry: %#v", parent.Metadata.SplitMetadata)
	}
	if split == nil {
		t.Fatal("libvlc split package not found")
	}
	if split.SourcePackage != "vlc" {
		t.Fatalf("expected source package vlc, got %q", split.SourcePackage)
	}
	if split.Metadata.Description != "VLC media framework runtime library" {
		t.Fatalf("unexpected split description: %q", split.Metadata.Description)
	}
	if len(split.Metadata.Tags) != 2 || split.Metadata.Tags[0] != "library" || split.Metadata.Tags[1] != "multimedia" {
		t.Fatalf("unexpected split tags: %v", split.Metadata.Tags)
	}
	if split.Metadata.URL != parent.Metadata.URL {
		t.Fatalf("expected split URL to inherit parent URL, got %q", split.Metadata.URL)
	}
	if got := searchResultVersion(*parent); got != "3.0.23-4" {
		t.Fatalf("parent search version: got %q", got)
	}
	if got := searchResultVersion(*split); got != "3.0.23-4" {
		t.Fatalf("split search version: got %q", got)
	}
}

func TestSearchResultVersion(t *testing.T) {
	for _, c := range []struct {
		entry PkgDBEntry
		want  string
	}{
		{PkgDBEntry{Version: "1.99.0", Revision: "2"}, "1.99.0-2"},
		{PkgDBEntry{Version: "1.99.0"}, "1.99.0"}, // database from an older hokuto
		{PkgDBEntry{Type: "meta", Version: "meta", Revision: "1"}, "meta"},
	} {
		if got := searchResultVersion(c.entry); got != c.want {
			t.Fatalf("%+v: got %q want %q", c.entry, got, c.want)
		}
	}
}

func TestSplitMetadataOverrideRoundTrip(t *testing.T) {
	parent := PackageMetadata{
		URL:         "https://example.invalid",
		Category:    "extra",
		Description: "Parent package",
		License:     "MIT",
		Tags:        []string{"gui", "utility"},
	}
	split := parent
	split.Description = "Split package"
	split.Tags = []string{"library"}

	override := splitMetadataOverride(parent, split)
	if override.Description != "Split package" {
		t.Fatalf("unexpected override description: %q", override.Description)
	}
	if len(override.Tags) != 1 || override.Tags[0] != "library" {
		t.Fatalf("unexpected override tags: %v", override.Tags)
	}
	if override.URL != "" {
		t.Fatalf("expected inherited URL to be omitted, got %q", override.URL)
	}

	parent.SplitMetadata = map[string]SplitPkgMetadata{"libexample": override}
	effective := effectiveMetadataForPackage("libexample", "example", &parent)
	if effective.Description != "Split package" {
		t.Fatalf("unexpected effective description: %q", effective.Description)
	}
	if effective.URL != "https://example.invalid" {
		t.Fatalf("expected inherited URL, got %q", effective.URL)
	}
}

func TestParseMajorVersionSearch(t *testing.T) {
	pkg, major, ok := parseMajorVersionSearch("java-openjdk@17")
	if !ok || pkg != "java-openjdk" || major != "17" {
		t.Fatalf("unexpected parse result: pkg=%q major=%q ok=%v", pkg, major, ok)
	}
	for _, query := range []string{"java-openjdk", "java-openjdk@", "@17", "java-openjdk@17.0", "java-openjdk@latest"} {
		if _, _, ok := parseMajorVersionSearch(query); ok {
			t.Fatalf("expected %q to be rejected", query)
		}
	}
}

func TestMajorVersionSearchCandidateUsesNaturalVersionOrdering(t *testing.T) {
	best := majorVersionSearchResult{}
	addMajorVersionSearchCandidate(&best, "17.0.9+7", "1", true, false)
	addMajorVersionSearchCandidate(&best, "17.0.20+7", "1", false, true)
	if best.version != "17.0.20+7" || !best.git || best.remote {
		t.Fatalf("unexpected best candidate: %#v", best)
	}
	addMajorVersionSearchCandidate(&best, "17.0.20+7", "1", true, false)
	if !best.git || !best.remote {
		t.Fatalf("expected matching sources to be merged: %#v", best)
	}
	addMajorVersionSearchCandidate(&best, "17.0.20+7", "2", true, false)
	if best.revision != "2" || !best.remote || best.git {
		t.Fatalf("expected newer revision to win: %#v", best)
	}
}

// A binary-only system has no recipe repositories. Generating the package
// database there wrote an empty one over the copy synced from the mirror,
// with a newer revision that kept 'hokuto sync' from restoring it.
func TestGeneratePkgDBRefusesWithoutRepositories(t *testing.T) {
	oldRepoPaths, oldDB := repoPaths, PkgDBPath
	t.Cleanup(func() { repoPaths, PkgDBPath = oldRepoPaths, oldDB })
	PkgDBPath = filepath.Join(t.TempDir(), "pkg-db.json.zst")
	if err := os.WriteFile(PkgDBPath, []byte("synced from the mirror"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, paths := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		repoPaths = paths
		if err := generatePkgDBQuiet(&Config{Values: map[string]string{}}); !errors.Is(err, errNoLocalRepositories) {
			t.Fatalf("HOKUTO_PATH=%q: err = %v, want errNoLocalRepositories", paths, err)
		}
	}
	if data, _ := os.ReadFile(PkgDBPath); string(data) != "synced from the mirror" {
		t.Fatalf("the existing database was replaced: %q", data)
	}
}

func TestPkgDBHasPackagesIgnoresMetapackages(t *testing.T) {
	if pkgDBHasPackages(PkgDB{Revision: 2000000000, Packages: []PkgDBEntry{{Name: "xfce-desktop", Type: "meta"}}}) {
		t.Fatal("a database of metapackages only counts as having packages")
	}
	if !pkgDBHasPackages(PkgDB{Packages: []PkgDBEntry{{Name: "exo"}}}) {
		t.Fatal("a database with a package counts as empty")
	}
}
