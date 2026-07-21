package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func withSplitUpdateFixture(t *testing.T) (*Config, string) {
	t.Helper()
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	installed := filepath.Join(tmp, "installed")
	sourceDir := filepath.Join(repo, "networkmanager")
	if err := os.MkdirAll(filepath.Join(sourceDir, "split", "libnma"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{
		filepath.Join(sourceDir, "build"):                      "#!/bin/sh\n",
		filepath.Join(sourceDir, "version"):                    "1.58.0 1\n",
		filepath.Join(sourceDir, "split", "libnma", "depends"): "\n",
		filepath.Join(installed, "libnma", "version"):          "1.56.1 1\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	oldRepoPaths, oldInstalled := repoPaths, Installed
	repoPaths, Installed = repo, installed
	t.Cleanup(func() {
		repoPaths, Installed = oldRepoPaths, oldInstalled
	})
	return &Config{Values: map[string]string{"HOKUTO_ARCH": "x86_64"}}, installed
}

func TestLocalUpgradeFindsInstalledSplitWithoutParent(t *testing.T) {
	_, _ = withSplitUpdateFixture(t)
	installed := map[string]Package{
		"libnma": {Name: "libnma", InstalledVersion: "1.56.1", InstalledRevision: "1"},
	}

	upgrades := localUpgradeCandidates(installed)
	if len(upgrades) != 1 || upgrades[0].Name != "libnma" {
		t.Fatalf("expected split-only libnma upgrade, got %#v", upgrades)
	}
	if upgrades[0].RepoVersion != "1.58.0" || upgrades[0].RepoRevision != "1" {
		t.Fatalf("split should use source recipe release, got %s %s", upgrades[0].RepoVersion, upgrades[0].RepoRevision)
	}

	requested := map[string]bool{"libnma": true}
	targets, splits := normalizeSplitUpdateTargets([]string{"libnma"}, requested)
	if len(targets) != 1 || targets[0] != "networkmanager" {
		t.Fatalf("expected one networkmanager source build, got %v", targets)
	}
	if requested["networkmanager"] {
		t.Fatal("split-only update must not request installation of the parent output")
	}
	if got := splits["networkmanager"]; len(got) != 1 || got[0] != "libnma" {
		t.Fatalf("expected libnma split install target, got %v", splits)
	}
}

func TestRemoteUpgradeFindsInstalledSplitWithoutParent(t *testing.T) {
	cfg, _ := withSplitUpdateFixture(t)
	installed := map[string]Package{
		"libnma": {Name: "libnma", InstalledVersion: "1.56.1", InstalledRevision: "1"},
	}
	index := []RepoEntry{{
		Name: "libnma", Version: "1.58.0", Revision: "1",
		Arch: "x86_64", Variant: "optimized",
	}}

	upgrades, targets, _ := remoteUpgradeCandidates(installed, cfg, index)
	if len(upgrades) != 1 || upgrades[0].Name != "libnma" {
		t.Fatalf("expected remote split-only libnma upgrade, got %#v", upgrades)
	}
	if target, ok := targets["libnma"]; !ok || target.Version != "1.58.0" {
		t.Fatalf("expected remote libnma target, got %#v", targets)
	}
}

func TestRemoteUpgradeIgnoresVersionConstrainedPackages(t *testing.T) {
	cfg, _ := withSplitUpdateFixture(t)
	installed := map[string]Package{
		"glibmm-2.66":        {Name: "glibmm-2.66", InstalledVersion: "2.66.9", InstalledRevision: "1"},
		"python-sabctools-9": {Name: "python-sabctools-9", InstalledVersion: "9.4.0", InstalledRevision: "4"},
	}
	index := []RepoEntry{
		{Name: "glibmm", Version: "2.88.1", Revision: "1", Arch: "x86_64", Variant: "optimized"},
		{Name: "python-sabctools", Version: "9.6.2", Revision: "1", Arch: "x86_64", Variant: "optimized"},
	}

	upgrades, targets, fallbacks := remoteUpgradeCandidates(installed, cfg, index)
	if len(upgrades) != 0 || len(targets) != 0 || len(fallbacks) != 0 {
		t.Fatalf("version-constrained packages must not be remote update targets: upgrades=%v targets=%v", upgrades, targets)
	}
}

func TestUpdatePlanSkipsBuildPreparationForBinaryOnlyTarget(t *testing.T) {
	plan := &BuildPlan{
		Order:           []string{"firefox"},
		RebuildPackages: map[string]bool{},
	}
	available := map[string]bool{"firefox": true}
	if updatePlanRequiresSourceBuild(plan, available, nil) {
		t.Fatal("cached Firefox binary must not trigger source-build preparation")
	}
	if !updatePlanRequiresSourceBuild(plan, nil, nil) {
		t.Fatal("package without a binary must trigger source-build preparation")
	}
	if !updatePlanRequiresSourceBuild(plan, available, map[string][]string{"firefox": {"firefox-l10n"}}) {
		t.Fatal("missing selected split binary must trigger its source build")
	}
}

func TestUpdatePlanSourceBuildPackages(t *testing.T) {
	plan := &BuildPlan{
		Order:           []string{"binary-dependency", "nodevel-source", "rebuild-source", "split-source"},
		RebuildPackages: map[string]bool{"rebuild-source": true},
	}
	available := map[string]bool{
		"binary-dependency": true,
		"nodevel-source":    false,
		"rebuild-source":    true,
		"split-source":      true,
	}
	selectedSplits := map[string][]string{
		"split-source": {"split-output"},
	}

	got := updatePlanSourceBuildPackages(plan, available, selectedSplits)
	want := []string{"nodevel-source", "rebuild-source", "split-source"}
	if len(got) != len(want) {
		t.Fatalf("source build packages = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("source build packages = %v, want %v", got, want)
		}
	}
}

func TestUpdateNodevelSourceBuildSkipsToolchain(t *testing.T) {
	_, _ = withSplitUpdateFixture(t)
	for name, options := range map[string]string{
		"fonts-meta": "nodevel\n",
		"regular":    "",
	} {
		pkgDir := filepath.Join(repoPaths, name)
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "options"), []byte(options), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if packageSetNeedsDevelPackages([]string{"fonts-meta"}) {
		t.Fatal("nodevel source build must not request the standard toolchain")
	}
	if !packageSetNeedsDevelPackages([]string{"fonts-meta", "regular"}) {
		t.Fatal("a regular source build in a mixed plan must request the standard toolchain")
	}
}

func TestBinaryUpdatePlanDoesNotTraverseSourceBuildDependencies(t *testing.T) {
	cfg, _ := withSplitUpdateFixture(t)
	for name, depends := range map[string]string{
		"firefox": "zip\n",
		"zip":     "\n",
	} {
		pkgDir := filepath.Join(repoPaths, name)
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, data := range map[string]string{
			"build":   "#!/bin/sh\n",
			"version": "1.0 1\n",
			"depends": depends,
		} {
			if err := os.WriteFile(filepath.Join(pkgDir, file), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	plan, err := resolveBuildPlan(
		[]string{"firefox"},
		map[string]bool{"firefox": true},
		false,
		cfg,
		map[string]bool{"firefox": true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Order) != 1 || plan.Order[0] != "firefox" {
		t.Fatalf("binary-only plan must exclude source dependency zip, got %v", plan.Order)
	}
	if deps := collectAvailableBinaryDependenciesForPlan(plan, cfg, true); len(deps) != 0 {
		t.Fatalf("binary-only execution must not rescan Firefox source dependencies, got %v", deps)
	}
}

func TestAutomaticPerlRebuildDiscoversAndOrdersInstalledModules(t *testing.T) {
	_, installedRoot := withSplitUpdateFixture(t)
	for name, depends := range map[string]string{
		"perl-base-module": "perl\n",
		"perl-app-module":  "perl\nperl-base-module\n",
		"perl-5":           "\n",
		"unrelated":        "perl\n",
	} {
		if err := os.MkdirAll(filepath.Join(installedRoot, name), 0o755); err != nil {
			t.Fatal(err)
		}
		pkgDir := filepath.Join(repoPaths, name)
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "build"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("1.0 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "depends"), []byte(depends), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := automaticRebuildTriggers("perl", true)
	want := []string{"perl-base-module", "perl-app-module"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected Perl rebuild order: got %v want %v", got, want)
	}
	if got := automaticRebuildTriggers("perl", false); len(got) != 0 {
		t.Fatalf("fresh Perl install must not rebuild modules, got %v", got)
	}

	nonInstalledDir := filepath.Join(repoPaths, "perl-repository-only")
	if err := os.MkdirAll(nonInstalledDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range map[string]string{"build": "#!/bin/sh\n", "version": "1.0 1\n", "depends": "perl\n"} {
		if err := os.WriteFile(filepath.Join(nonInstalledDir, file), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	repoModules := repositoryPerlModulePackages()
	if len(repoModules) != 3 || repoModules[0] != "perl-base-module" || repoModules[1] != "perl-app-module" || repoModules[2] != "perl-repository-only" {
		t.Fatalf("repository scan must include uninstalled Perl modules in dependency order, got %v", repoModules)
	}
}
