package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSuggestionInstallableOnArch(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	oldIndex, oldLoaded, oldErr := GlobalRemoteIndex, GlobalRemoteIndexLoaded, GlobalRemoteIndexErr
	t.Cleanup(func() {
		GlobalRemoteIndexMu.Lock()
		GlobalRemoteIndex, GlobalRemoteIndexLoaded, GlobalRemoteIndexErr = oldIndex, oldLoaded, oldErr
		GlobalRemoteIndexMu.Unlock()
	})

	recipe := func(name, build, options string) string {
		dir := filepath.Join(repo, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		files := map[string]string{"version": "1.0 1\n", "build": build, "depends": ""}
		if options != "" {
			files["options"] = options
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	plainBuild := "#!/bin/sh\nmake\n"
	recipe("ready", plainBuild, "cross\n")
	recipe("adapted", "#!/bin/sh\n./configure --prefix=\"${CROSS_PREFIX:-/usr}\"\n", "")
	recipe("notready", plainBuild, "")
	parent := recipe("parent", plainBuild, "cross\n")
	if err := os.MkdirAll(filepath.Join(parent, "split", "parent-data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "split", "parent-data", "depends"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	setLoadedRemoteIndex([]RepoEntry{
		{Name: "published", Version: "1.0", Revision: "1", Arch: "aarch64", Variant: "optimized"},
		{Name: "x86only", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized"},
		{Name: "notready", Version: "1.0", Revision: "1", Arch: "aarch64", Variant: "optimized"},
	})

	cfg.Values["HOKUTO_ARCH"] = "aarch64"
	for name, want := range map[string]bool{
		"ready":       true,  // options file says cross
		"adapted":     true,  // build script branches on the cross environment
		"parent-data": true,  // split output of a cross-ready recipe
		"published":   true,  // no recipe, but a package for this arch
		"notready":    true,  // not cross ready, yet a package was published
		"x86only":     false, // published for x86_64 only, no recipe
		"unknown":     false, // neither a recipe nor a package
	} {
		if got := suggestionInstallableOnArch(name, cfg, false); got != want {
			t.Errorf("aarch64 %s: got %v, want %v", name, got, want)
		}
	}

	setLoadedRemoteIndex(nil)
	if suggestionInstallableOnArch("notready", cfg, false) {
		t.Error("aarch64 notready: a recipe not prepared for cross builds must not be suggested")
	}
	// Without the index there is nothing to say a package is missing.
	if !suggestionInstallableOnArch("unknown", cfg, true) {
		t.Error("aarch64 unknown, no index: must be kept")
	}

	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	if !suggestionInstallableOnArch("notready", cfg, false) || !suggestionInstallableOnArch("unknown", cfg, false) {
		t.Error("x86_64 builds every recipe natively; nothing is filtered")
	}

	cfg.Values["HOKUTO_ARCH"] = "aarch64"
	known := make(map[string]bool)
	item := packageSuggestion{Package: "owner", Name: "notready", Alternates: []string{"notready", "ready"}, Dependency: "notready | ready"}
	got, ok := filterSuggestionForArch(item, cfg, false, known)
	if !ok || !reflect.DeepEqual(got.Alternates, []string{"ready"}) || got.Dependency != "ready" {
		t.Fatalf("filtered alternatives = %v (%q), %v", got.Alternates, got.Dependency, ok)
	}
	if _, ok := filterSuggestionForArch(packageSuggestion{Name: "notready", Alternates: []string{"notready"}, Dependency: "notready"}, cfg, false, known); ok {
		t.Fatal("a suggestion with no installable alternative must be dropped")
	}
}
