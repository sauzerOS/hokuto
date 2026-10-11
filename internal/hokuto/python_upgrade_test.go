package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// withPythonUpgradeEnv gives a test a recipe repository holding python at
// pythonRelease, an empty cache and no website checkout.
func withPythonUpgradeEnv(t *testing.T, pythonRelease string) (*Config, string) {
	t.Helper()
	cfg, repo := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	oldCache, oldWebsite := CacheDir, WebsiteRepo
	CacheDir = t.TempDir()
	WebsiteRepo = filepath.Join(t.TempDir(), "no-website")
	t.Cleanup(func() { CacheDir, WebsiteRepo = oldCache, oldWebsite })
	writePythonUpgradeRecipe(t, repo, "python", pythonRelease, "")
	return cfg, repo
}

func writePythonUpgradeRecipe(t *testing.T, repo, name, release, options string) {
	t.Helper()
	files := map[string]string{
		"version": release + "\n",
		"build":   "#!/bin/sh\n",
	}
	if options != "" {
		files["options"] = options
	}
	for file, data := range files {
		path := filepath.Join(repo, name, file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHoldPythonUpgrade(t *testing.T) {
	cfg, _ := withPythonUpgradeEnv(t, "3.15.0 1")
	index := []RepoEntry{
		{Name: "python", Version: "3.14.8", Revision: "1", Arch: "x86_64", Variant: "optimized"},
		{Name: "python", Version: "3.15.0", Revision: "1", Arch: "aarch64", Variant: "optimized"},
	}
	// The new package is in BinDir, waiting for the upload.
	tarball := filepath.Join(BinDir, StandardizeRemoteName("python", "3.15.0", "1", "x86_64", GetSystemVariantForPackage(cfg, "python")))
	if err := os.WriteFile(tarball, []byte("pkg"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := holdPythonUpgrade([]string{"glib", "python"}, cfg, index)
	if !reflect.DeepEqual(got, []string{"glib"}) {
		t.Fatalf("built after the hold = %v, want [glib]", got)
	}
	state, err := loadPythonUpgrade()
	if err != nil || state == nil {
		t.Fatalf("no upgrade recorded: %v", err)
	}
	if state.From != "3.14" || state.To != "3.15" || state.Release != "3.15.0-1" || state.Status != pythonUpgradePending {
		t.Fatalf("recorded %+v", state)
	}
	if _, err := os.Stat(tarball); !os.IsNotExist(err) {
		t.Errorf("the new python package must be kept off the mirror: %v", err)
	}
	for name, want := range map[string]bool{"python": true, "aarch64-python": true, "python-foo": false} {
		if got := pythonUpgradeHeld(name); got != want {
			t.Errorf("held %s = %v, want %v", name, got, want)
		}
	}
	if got := filterNoBuild([]string{"python", "glib"}, false); !reflect.DeepEqual(got, []string{"glib"}) {
		t.Errorf("filterNoBuild = %v, want [glib]", got)
	}

	// Confirmed, python is built and published as usual.
	state.Status = pythonUpgradeConfirmed
	if err := savePythonUpgrade(state); err != nil {
		t.Fatal(err)
	}
	if got := holdPythonUpgrade([]string{"python"}, cfg, index); !reflect.DeepEqual(got, []string{"python"}) {
		t.Fatalf("confirmed: built = %v, want [python]", got)
	}
	if pythonUpgradeHeld("python") {
		t.Error("a confirmed upgrade must not hold python")
	}
}

func TestHoldPythonUpgradeIgnoresMaintenanceRelease(t *testing.T) {
	cfg, _ := withPythonUpgradeEnv(t, "3.14.9 1")
	index := []RepoEntry{{Name: "python", Version: "3.14.8", Revision: "1", Arch: "x86_64"}}
	if got := holdPythonUpgrade([]string{"python"}, cfg, index); !reflect.DeepEqual(got, []string{"python"}) {
		t.Fatalf("built = %v, want [python]", got)
	}
	if state, _ := loadPythonUpgrade(); state != nil {
		t.Fatalf("a maintenance release recorded an upgrade: %+v", state)
	}
}

func TestPythonRebuildRecipes(t *testing.T) {
	cfg, repo := withPythonUpgradeEnv(t, "3.15.0 1")
	writePythonUpgradeRecipe(t, repo, "python-foo", "1.0 1", "python-rebuild\n")
	writePythonUpgradeRecipe(t, repo, "gdb", "18.1 1", "")
	writePythonUpgradeRecipe(t, repo, "glib", "2.90 1", "")
	writePythonUpgradeRecipe(t, repo, "sublime-text", "4215 1", "binary\n")
	index := []RepoEntry{
		{Name: "gdb", Version: "18.1", Revision: "1", Arch: "x86_64", Libdeps: []string{"elf64:libc.so.6", "elf64:libpython3.14.so.1.0"}},
		{Name: "glib", Version: "2.90", Revision: "1", Arch: "x86_64", Libdeps: []string{"elf64:libc.so.6"}},
		{Name: "sublime-text", Version: "4215", Revision: "1", Arch: "x86_64", Libdeps: []string{"elf64:libpython3.14.so.1.0"}},
		{Name: "gdb", Version: "18.1", Revision: "1", Arch: "aarch64", Libdeps: []string{"elf64:libpython3.13.so.1.0"}},
	}
	got := sortedKeys(keysOf(pythonRebuildRecipes(index, GetSystemArch(cfg), "3.14")))
	if want := []string{"gdb", "python-foo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuild set = %v, want %v", got, want)
	}
}

func TestPythonUpgradeConfirmWantsAPassedCheck(t *testing.T) {
	cfg, _ := withPythonUpgradeEnv(t, "3.15.0 1")
	setLoadedRemoteIndexForTest(t, []RepoEntry{{Name: "python", Version: "3.14.8", Revision: "1", Arch: "x86_64"}})

	// Not checked yet: currentPythonUpgrade records the hand-made bump.
	err := pythonUpgradeConfirm("", false, cfg)
	if err == nil || !strings.Contains(err.Error(), "not been checked") {
		t.Fatalf("confirm before a check: %v", err)
	}
	state, _ := loadPythonUpgrade()
	if state == nil || state.Status != pythonUpgradePending {
		t.Fatalf("state = %+v", state)
	}
	state.Status, state.Failed, state.Packages = pythonUpgradeFailed, []string{"python-foo"}, []string{"python-foo", "gdb"}
	if err := savePythonUpgrade(state); err != nil {
		t.Fatal(err)
	}
	if err := pythonUpgradeConfirm("", false, cfg); err == nil || !strings.Contains(err.Error(), "1 failure") {
		t.Fatalf("confirm after a failed check: %v", err)
	}
	// Forced, with nothing published to bump, it releases python.
	if err := pythonUpgradeConfirm("", true, cfg); err != nil {
		t.Fatal(err)
	}
	if state, _ := loadPythonUpgrade(); state == nil || state.Status != pythonUpgradeConfirmed {
		t.Fatalf("state after a forced confirm = %+v", state)
	}
}

func setLoadedRemoteIndexForTest(t *testing.T, index []RepoEntry) {
	t.Helper()
	oldIndex, oldLoaded, oldErr := GlobalRemoteIndex, GlobalRemoteIndexLoaded, GlobalRemoteIndexErr
	t.Cleanup(func() {
		GlobalRemoteIndexMu.Lock()
		GlobalRemoteIndex, GlobalRemoteIndexLoaded, GlobalRemoteIndexErr = oldIndex, oldLoaded, oldErr
		GlobalRemoteIndexMu.Unlock()
	})
	setLoadedRemoteIndex(index)
}

func TestFindCPythonExtension(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"usr/lib/gobject-introspection/giscanner/_giscanner.cpython-314-x86_64-linux-gnu.so": "",
		"usr/lib/gobject-introspection/giscanner/__init__.py":                                "",
	})
	if got := findCPythonExtension(dir); got != "/usr/lib/gobject-introspection/giscanner/_giscanner.cpython-314-x86_64-linux-gnu.so" {
		t.Fatalf("got %q", got)
	}
	if got := findCPythonExtension(t.TempDir()); got != "" {
		t.Fatalf("empty tree: got %q", got)
	}
}

func TestWebsiteNotices(t *testing.T) {
	site := withWebsiteCheckout(t)
	oldWebsite := WebsiteRepo
	WebsiteRepo = site
	t.Cleanup(func() { WebsiteRepo = oldWebsite })

	setWebsiteNotice(WebsiteNotice{ID: "python-upgrade", Level: "warn", Title: "python 3.14 → 3.15", Text: "check"})
	setWebsiteNotice(WebsiteNotice{ID: "python-upgrade", Level: "ok", Title: "python 3.14 → 3.15", Text: "passed"})
	notices, err := readWebsiteNotices(filepath.Join(site, "notices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(notices) != 1 || notices[0].Level != "ok" || notices[0].Text != "passed" || notices[0].Updated == "" {
		t.Fatalf("notices = %+v", notices)
	}
	removeWebsiteNotice("python-upgrade")
	notices, _ = readWebsiteNotices(filepath.Join(site, "notices.json"))
	if len(notices) != 0 {
		t.Fatalf("after removal: %+v", notices)
	}
	if log := gitIn(t, site, "log", "--oneline", "--", "notices.json"); len(strings.Split(log, "\n")) != 3 {
		t.Errorf("notices.json commits:\n%s", log)
	}
}

// Once the new release is on the mirror, nothing is held any more.
func TestCurrentPythonUpgradeOnceReleasePublished(t *testing.T) {
	cfg, _ := withPythonUpgradeEnv(t, "3.15.0 1")
	index := []RepoEntry{
		{Name: "python", Version: "3.14.8", Revision: "1", Arch: "x86_64"},
		{Name: "python", Version: "3.15.0", Revision: "1", Arch: "x86_64"},
	}
	state, err := currentPythonUpgrade(cfg, index, "")
	if err != nil || state != nil {
		t.Fatalf("got %+v, %v; want no upgrade", state, err)
	}
	if _, err := os.Stat(pythonUpgradeFile()); !os.IsNotExist(err) {
		t.Fatalf("a state file was written: %v", err)
	}
}

// --from starts an upgrade by hand once the new python is published.
func TestCurrentPythonUpgradeFrom(t *testing.T) {
	cfg, _ := withPythonUpgradeEnv(t, "3.15.0 1")
	index := []RepoEntry{{Name: "python", Version: "3.15.0", Revision: "1", Arch: "x86_64"}}
	state, err := currentPythonUpgrade(cfg, index, "3.14")
	if err != nil || state == nil || state.From != "3.14" || state.To != "3.15" || state.Status != pythonUpgradePending {
		t.Fatalf("got %+v, %v", state, err)
	}
	if loaded, _ := loadPythonUpgrade(); loaded == nil || loaded.From != "3.14" {
		t.Fatalf("not saved: %+v", loaded)
	}
}

func TestCommandHelpNeedsNoRoot(t *testing.T) {
	for _, args := range [][]string{
		{"nobuild", "help"},
		{"nobuild", "add", "--help"},
		{"python-rebuild", "check", "-h"},
		{"python-rebuild", "--help"},
	} {
		if needsRootPrivileges(args) {
			t.Errorf("%v asks for root", args)
		}
	}
	if !needsRootPrivileges([]string{"python-rebuild", "check"}) || !needsRootPrivileges([]string{"nobuild", "add", "foo"}) {
		t.Error("the commands themselves still need root")
	}
}

func TestPythonBootstrapOrder(t *testing.T) {
	dir := t.TempDir()
	marked := map[string]string{}
	for name, depends := range map[string]string{
		"python-installer":       "python\npython-flit-core make\n",
		"python-flit-core":       "python\npython-build make\npython-installer make\n",
		"python-packaging":       "python\npython-flit-core make\n",
		"python-build":           "python\npython-packaging\npython-pyproject-hooks\n",
		"python-setuptools":      "python\npython-build make\npython-wheel make\n",
		"python-wheel":           "python\npython-packaging\n",
		"meson":                  "python\npython-setuptools make\n",
		"python-pyproject-hooks": "python\npython-flit-core make\n",
	} {
		marked[name] = filepath.Join(dir, name)
		writeTree(t, marked[name], map[string]string{"depends": depends})
	}
	got := pythonBootstrapOrder(sortedKeys(keysOf(marked)), marked)
	pos := map[string]int{}
	for i, name := range got {
		pos[name] = i
	}
	if len(got) != len(marked) {
		t.Fatalf("order %v lost tools", got)
	}
	// Edges outside the cycles (flit-core, installer, build and
	// pyproject-hooks build each other); inside one any order works, the
	// old copies standing in.
	for _, edge := range [][2]string{
		{"python-packaging", "python-wheel"},
		{"python-wheel", "python-setuptools"},
		{"python-setuptools", "meson"},
		{"python-build", "python-setuptools"},
	} {
		if pos[edge[0]] > pos[edge[1]] {
			t.Errorf("%s comes after %s in %v", edge[0], edge[1], got)
		}
	}
}

func TestPythonRecheckRecipes(t *testing.T) {
	_, repo := withPythonUpgradeEnv(t, "3.15.0 1")
	all := map[string]string{}
	for name, depends := range map[string]string{
		"python-pyqt6":      "python\npyqt-builder make\nqt6-base\n",
		"pyqt-builder":      "python\npython-sip\n",
		"python-sip":        "python\npython-setuptools make\n",
		"python-setuptools": "python\n",
		"python-wheel":      "python\n",
		"python-pygame":     "python\nsdl2\n",
		"gdb":               "python\n",
	} {
		writePythonUpgradeRecipe(t, repo, name, "1.0 1", "")
		writeTree(t, filepath.Join(repo, name), map[string]string{"depends": depends})
		all[name] = filepath.Join(repo, name)
	}
	got := sortedKeys(keysOf(pythonRecheckRecipes(all, []string{"python-pyqt6"})))
	want := []string{"pyqt-builder", "python-pyqt6", "python-setuptools", "python-sip", "python-wheel"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recheck set = %v, want %v (the failed one, its rebuilt dependencies, the build tools)", got, want)
	}
}

func TestPreparePythonUpgradeBuildOnlyForAConfirmedUpgrade(t *testing.T) {
	cfg, repo := withPythonUpgradeEnv(t, "9.99.0 1")
	writePythonUpgradeRecipe(t, repo, "python-build", "1.0 2", "python-rebuild\n")
	targets := []string{"python-build", "foo"}

	got, restore := preparePythonUpgradeBuild(targets, nil, cfg)
	restore()
	if !slices.Equal(got, targets) {
		t.Fatalf("without a held upgrade the targets must stay, got %v", got)
	}

	// Confirmed, but the python installed is not the new one: nothing can be
	// bootstrapped and nothing is built here.
	state := &pythonUpgrade{From: "9.98", To: "9.99", Release: "9.99.0-1", Status: pythonUpgradePassed}
	if err := savePythonUpgrade(state); err != nil {
		t.Fatal(err)
	}
	got, restore = preparePythonUpgradeBuild(targets, nil, cfg)
	restore()
	if !slices.Equal(got, targets) {
		t.Fatalf("an unconfirmed upgrade must not change the targets, got %v", got)
	}
	state.Status = pythonUpgradeConfirmed
	if err := savePythonUpgrade(state); err != nil {
		t.Fatal(err)
	}
	got, restore = preparePythonUpgradeBuild(targets, nil, cfg)
	restore()
	if !slices.Equal(got, targets) {
		t.Fatalf("without the new python installed the targets must stay, got %v", got)
	}
}

func TestPythonToolInstallOrderPutsRuntimeDependenciesFirst(t *testing.T) {
	_, repo := withTempDependencyRepo(t)
	depends := map[string]string{
		"python-build":           "python\npython-packaging\npython-pyproject-hooks\npython-build make\npython-flit-core make\npython-installer make\n",
		"python-pyproject-hooks": "python\npython-build make\npython-flit-core make\npython-installer make\npython-wheel make\n",
		"python-packaging":       "python\npython-build make\npython-flit-core make\npython-installer make\n",
		"python-flit-core":       "python\npython-build make\npython-flit-core make\npython-installer make\n",
		"python-installer":       "python\npython-build make\npython-flit-core make\npython-installer make\n",
		"python-wheel":           "python\npython-packaging\npython-build make\npython-flit-core make\npython-installer make\n",
	}
	marked := make(map[string]string)
	for name, deps := range depends {
		writeTestPackage(t, repo, name, deps)
		marked[name] = filepath.Join(repo, name)
	}
	tools := sortedKeys(keysOf(marked))

	order := pythonToolInstallOrder(tools, marked)
	pos := make(map[string]int)
	for i, name := range order {
		pos[name] = i
	}
	for _, pair := range [][2]string{
		{"python-packaging", "python-build"},
		{"python-pyproject-hooks", "python-build"},
		{"python-packaging", "python-wheel"},
	} {
		if pos[pair[0]] > pos[pair[1]] {
			t.Fatalf("%s must be installed before %s, which needs it at runtime: %v", pair[0], pair[1], order)
		}
	}
	if len(order) != len(tools) {
		t.Fatalf("every tool must be ordered: %v", order)
	}
}
