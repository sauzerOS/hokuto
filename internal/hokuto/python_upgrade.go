package hokuto

// The held Python upgrade: see the comment at the top of python_rebuild.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// pythonRecipe is the interpreter's recipe.
const pythonRecipe = "python"

// Upgrade states: waiting for a check, checked with every package built,
// checked with failures, and confirmed (bumped and released).
const (
	pythonUpgradePending   = "pending"
	pythonUpgradePassed    = "passed"
	pythonUpgradeFailed    = "failed"
	pythonUpgradeConfirmed = "confirmed"
)

// pythonUpgrade is a Python minor upgrade the build server holds back until
// the packages built against the old release are known to build against the
// new one.
type pythonUpgrade struct {
	From     string `json:"from"`    // "3.14", the published minor release
	To       string `json:"to"`      // "3.15"
	Release  string `json:"release"` // the recipe's release: "3.15.0-1"
	Detected string `json:"detected"`
	Status   string `json:"status"`
	Checked  string `json:"checked,omitempty"`
	// Packages are the recipes the last check built, Failed those of them
	// that failed or were blocked by a failed dependency.
	Packages []string `json:"packages,omitempty"`
	Failed   []string `json:"failed,omitempty"`
}

// pythonUpgradeFile is in HOKUTO_CACHE_DIR, which the build containers share
// with the host.
func pythonUpgradeFile() string {
	return filepath.Join(CacheDir, "python-upgrade.json")
}

func loadPythonUpgrade() (*pythonUpgrade, error) {
	data, err := os.ReadFile(pythonUpgradeFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var state pythonUpgrade
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("%s: %w", pythonUpgradeFile(), err)
	}
	return &state, nil
}

func savePythonUpgrade(state *pythonUpgrade) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeStateFile(pythonUpgradeFile(), append(data, '\n'))
}

// pythonUpgradeHeld reports whether pkgName is python (or one of its cross
// builds, aarch64-python) held back by an upgrade that is not confirmed yet.
func pythonUpgradeHeld(pkgName string) bool {
	if strings.TrimPrefix(strings.TrimPrefix(pkgName, crossSyncPrefix), "x86_64-") != pythonRecipe {
		return false
	}
	state, err := loadPythonUpgrade()
	return err == nil && state != nil && state.Status != pythonUpgradeConfirmed
}

// heldPythonNote is how the builds that skip python say why.
func heldPythonNote() string {
	return "python is held until its upgrade is confirmed (hokuto-builder python-rebuild --check, then --confirm)"
}

// publishedPythonMinor returns the minor release of the newest python
// published for arch up to version-revision, or "". Once that release is on
// the mirror, there is no upgrade left to hold.
func publishedPythonMinor(index []RepoEntry, arch, version, revision string) string {
	current := RepoEntry{Version: version, Revision: revision}
	var newest *RepoEntry
	for i := range index {
		e := &index[i]
		if e.Name != pythonRecipe || e.Arch != arch || e.Type == "meta" || isNewer(*e, current) {
			continue
		}
		if newest == nil || isNewer(*e, *newest) {
			newest = e
		}
	}
	if newest == nil {
		return ""
	}
	return majorMinor(newest.Version)
}

// holdPythonUpgrade is the part of a publishing build's ABI check that
// concerns python. When python was built with a new minor release, it records
// the upgrade, keeps the new package off the mirror and posts the website
// notice, and returns built without python, so its libpython consumers are
// not bumped: the check decides that. A confirmed upgrade of that release is
// built and published as usual.
func holdPythonUpgrade(built []string, cfg *Config, index []RepoEntry) []string {
	if !slices.Contains(built, pythonRecipe) {
		return built
	}
	version, revision, err := getRepoVersion2(pythonRecipe)
	if err != nil {
		return built
	}
	to := majorMinor(version)
	from := publishedPythonMinor(index, GetSystemArch(cfg), version, revision)
	if from == "" || from == to {
		return built
	}
	state, err := loadPythonUpgrade()
	if err != nil {
		colWarn.Printf("Warning: %v\n", err)
	}
	if state != nil && state.To == to && state.Status == pythonUpgradeConfirmed {
		return built
	}
	if state == nil || state.To != to {
		state = &pythonUpgrade{From: from, To: to, Detected: time.Now().UTC().Format(time.RFC3339), Status: pythonUpgradePending}
	}
	state.Release = version + "-" + revision
	if err := savePythonUpgrade(state); err != nil {
		colWarn.Printf("Warning: failed to record the python upgrade: %v\n", err)
	}

	// Off the mirror until confirmed: the upload that follows this build
	// would hand python to systems whose modules are still built for the old
	// release.
	if tarball := findCachedBinaryTarballVersion(getOutputPackageName(pythonRecipe, cfg), version, revision, cfg); tarball != "" {
		if err := os.Remove(tarball); err != nil {
			colWarn.Printf("Warning: failed to keep %s off the mirror: %v\n", filepath.Base(tarball), err)
		}
	}

	fmt.Println()
	colArrow.Print("-> ")
	colWarn.Printf("python %s -> %s: a new minor release; every package with Python modules or linked against libpython needs a rebuild.\n", from, to)
	colArrow.Print("-> ")
	colWarn.Println("Nothing was bumped and python was not uploaded. Test the rebuild with `hokuto-builder python-rebuild --check`, then bump everything with `hokuto-builder python-rebuild --confirm`.")
	postPythonUpgradeNotice(state, cfg)

	return slices.DeleteFunc(slices.Clone(built), func(name string) bool { return name == pythonRecipe })
}

// pythonRebuildRecipes returns the recipes to rebuild for a Python upgrade
// from the minor release from, keyed by name: those marked python-rebuild,
// and those of the packages published for arch that link libpython<from>.
// Binary recipes, which bundle their own Python, and python itself are left
// out.
func pythonRebuildRecipes(index []RepoEntry, arch, from string) map[string]string {
	recipes := recipesWithOption(pythonRebuildOption)
	lib := "libpython" + from
	for _, e := range latestIndexEntries(index) {
		if e.Arch != arch || e.Type == "meta" {
			continue
		}
		linked := false
		for _, dep := range e.Libdeps {
			if strings.Contains(dep, lib) {
				linked = true
				break
			}
		}
		if !linked {
			continue
		}
		recipe := e.Name
		pkgDir, err := findPackageMetadataDir(recipe)
		if err != nil || !isRecipeDir(pkgDir) {
			source, sourceDir, ok := findSplitPackageSource(recipe)
			if !ok {
				continue
			}
			recipe, pkgDir = source, sourceDir
		}
		recipes[recipe] = pkgDir
	}
	delete(recipes, pythonRecipe)
	for name, pkgDir := range recipes {
		if loadBuildOptions(pkgDir)["binary"] {
			delete(recipes, name)
		}
	}
	return recipes
}

// isRecipeDir reports whether pkgDir is a recipe in a repository rather than
// installed package metadata, which findPackageMetadataDir falls back to.
func isRecipeDir(pkgDir string) bool {
	if strings.HasPrefix(pkgDir, Installed) {
		return false
	}
	_, err := os.Stat(filepath.Join(pkgDir, "build"))
	return err == nil
}

// currentPythonUpgrade returns the recorded upgrade, or, when none was
// recorded but the python recipe is a minor release ahead of the mirror (a
// version bumped by hand), a new pending one. from, when not "", starts one
// from that minor release even though the new python is published already.
func currentPythonUpgrade(cfg *Config, index []RepoEntry, from string) (*pythonUpgrade, error) {
	state, err := loadPythonUpgrade()
	if err != nil || (state != nil && (from == "" || state.From == from)) {
		return state, err
	}
	version, revision, err := getRepoVersion2(pythonRecipe)
	if err != nil {
		return nil, err
	}
	to := majorMinor(version)
	if from == "" {
		from = publishedPythonMinor(index, GetSystemArch(cfg), version, revision)
	}
	if from == "" || from == to {
		return nil, nil
	}
	state = &pythonUpgrade{From: from, To: to, Release: version + "-" + revision, Detected: time.Now().UTC().Format(time.RFC3339), Status: pythonUpgradePending}
	return state, savePythonUpgrade(state)
}

// pythonRebuildHelp is what hokuto python-rebuild --help prints.
const pythonRebuildHelp = `Usage: hokuto python-rebuild [command] [options]

A new Python minor release (3.14 -> 3.15) needs every package with Python
modules or linked against libpython rebuilt. A publishing build of such a
python holds the upgrade: nothing is bumped, the new python is not uploaded,
rebuild and cross-sync leave python alone, and the website shows a notice.
Maintenance releases (3.15.0 -> 3.15.1) are not held.

Commands:
  status                  show the held upgrade and its last check (default)
  list                    list the packages the upgrade rebuilds
  check [build flags]     build and install the new python, then build every
                          package that needs the rebuild against it, without
                          publishing anything, and report which fail
                          (hokuto-builder python-rebuild --check runs it in a
                          throwaway overlay of the build container)
  confirm [--force]       once every package built: bump their revisions,
                          commit and push, and release python for the next
                          rebuild; --force confirms without a passed check
  cancel                  drop the hold (after reverting the python bump)

Options:
  --from X.Y              start an upgrade from this minor release when none
                          is held, e.g. after the new python was published
  -h, --help              show this help
`

func handlePythonRebuildCommand(args []string, cfg *Config) error {
	if wantsCommandHelp(args) {
		fmt.Print(pythonRebuildHelp)
		return nil
	}
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	// --from 3.14 starts an upgrade from that minor release when none is
	// held, e.g. after the new python was published before this existed.
	from, force := "", false
	var rest []string
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "-from" || arg == "--from":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a python minor release, e.g. 3.14", arg)
			}
			i++
			from = args[i]
		case strings.HasPrefix(arg, "--from="):
			from = strings.TrimPrefix(arg, "--from=")
		case sub == "confirm" && (arg == "-force" || arg == "--force"):
			force = true
		default:
			rest = append(rest, arg)
		}
	}
	switch sub {
	case "status":
		return pythonUpgradeStatus(cfg)
	case "list":
		return pythonUpgradeList(from, cfg)
	case "check":
		return pythonUpgradeCheck(from, rest, cfg)
	case "confirm":
		if len(rest) > 0 {
			return fmt.Errorf("usage: hokuto python-rebuild confirm [--force] [--from X.Y]")
		}
		return pythonUpgradeConfirm(from, force, cfg)
	case "cancel":
		return pythonUpgradeCancel(cfg)
	}
	return fmt.Errorf("unknown python-rebuild command %q (status, list, check, confirm or cancel)", sub)
}

func pythonUpgradeStatus(cfg *Config) error {
	state, err := loadPythonUpgrade()
	if err != nil {
		return err
	}
	colArrow.Print("-> ")
	if state == nil {
		colSuccess.Println("No python upgrade is held.")
		return nil
	}
	colSuccess.Printf("python %s -> %s (%s): %s\n", state.From, state.To, state.Release, state.Status)
	if state.Checked != "" {
		colArrow.Print("-> ")
		fmt.Printf("Last check %s: %d of %d package(s) built\n", state.Checked, len(state.Packages)-len(state.Failed), len(state.Packages))
		for _, name := range state.Failed {
			fmt.Printf("   failed: %s\n", name)
		}
	}
	return nil
}

// pythonUpgradeList prints the recipes an upgrade from the held minor
// release (or from, or the published one) rebuilds. It records nothing.
func pythonUpgradeList(from string, cfg *Config) error {
	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return err
	}
	if from == "" {
		if state, err := loadPythonUpgrade(); err == nil && state != nil {
			from = state.From
		} else if version, revision, err := getRepoVersion2(pythonRecipe); err == nil {
			from = publishedPythonMinor(index, GetSystemArch(cfg), version, revision)
		}
	}
	if from == "" {
		return fmt.Errorf("no published python to rebuild from")
	}
	for _, name := range sortedKeys(keysOf(pythonRebuildRecipes(index, GetSystemArch(cfg), from))) {
		fmt.Println(name)
	}
	return nil
}

// pythonUpgradeCheck builds the new python and installs it, then builds every
// package that needs the rebuild against it, without publishing anything,
// and records the result. hokuto-builder runs it in a throwaway copy of the
// build container. buildArgs are passed on to hokuto build (-jN, -i, ...).
func pythonUpgradeCheck(from string, buildArgs []string, cfg *Config) error {
	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return fmt.Errorf("remote index unavailable: %w", err)
	}
	state, err := currentPythonUpgrade(cfg, index, from)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("no python upgrade is waiting: the python recipe is at the published minor release")
	}
	if state.Status == pythonUpgradeConfirmed {
		return fmt.Errorf("the python %s upgrade is already confirmed", state.To)
	}
	marked := pythonRebuildRecipes(index, GetSystemArch(cfg), state.From)

	// Test builds go to a directory of their own and are deleted afterwards:
	// they keep the published revision and must never be uploaded.
	scratch, err := os.MkdirTemp(CacheDir, "python-rebuild-")
	if err != nil {
		return fmt.Errorf("failed to create a scratch binary directory: %w", err)
	}
	oldBinDir := BinDir
	BinDir = scratch
	defer func() {
		BinDir = oldBinDir
		os.RemoveAll(scratch)
	}()

	colArrow.Print("-> ")
	colSuccess.Printf("Building and installing python %s\n", state.Release)
	if err := handleBuildCommand(append(append([]string{}, buildArgs...), "--no-install", pythonRecipe), cfg); err != nil {
		debugf("python-rebuild: python build: %v\n", err)
	}
	installBuiltRecipes([]string{pythonRecipe}, cfg)
	current, err := currentPythonMinor()
	if err != nil {
		return err
	}
	if current != state.To {
		state.Status = pythonUpgradeFailed
		state.Checked = time.Now().UTC().Format(time.RFC3339)
		state.Packages = []string{pythonRecipe}
		state.Failed = []string{pythonRecipe}
		_ = savePythonUpgrade(state)
		postPythonUpgradeNotice(state, cfg)
		return fmt.Errorf("python %s did not build or install (python3 is %s)", state.To, current)
	}

	pythonRebuildBuildAll(marked, current, buildArgs, cfg)

	var failed []string
	for _, name := range sortedKeys(keysOf(marked)) {
		if !builtRecipePackage(scratch, name, marked[name]) {
			failed = append(failed, name)
		}
	}
	state.Checked = time.Now().UTC().Format(time.RFC3339)
	state.Packages = sortedKeys(keysOf(marked))
	state.Failed = failed
	state.Status = pythonUpgradePassed
	if len(failed) > 0 {
		state.Status = pythonUpgradeFailed
	}
	if err := savePythonUpgrade(state); err != nil {
		colWarn.Printf("Warning: failed to record the check: %v\n", err)
	}
	postPythonUpgradeNotice(state, cfg)

	colArrow.Print("-> ")
	if len(failed) == 0 {
		colSuccess.Printf("All %d package(s) build against python %s. Bump them with: hokuto-builder python-rebuild --confirm\n", len(marked), state.To)
		return nil
	}
	colWarn.Printf("%d of %d package(s) failed or were blocked by a failed dependency against python %s:\n", len(failed), len(marked), state.To)
	for _, name := range failed {
		fmt.Printf("   %s\n", name)
	}
	colArrow.Print("-> ")
	colNote.Println("Fix them and check again, or bump anyway with: hokuto-builder python-rebuild --confirm --force")
	return fmt.Errorf("%d package(s) failed", len(failed))
}

// pythonRebuildBuildAll builds the recipes of marked against the installed
// python, the Python build tools first (installed, so the rest can use
// them), then the rest.
func pythonRebuildBuildAll(marked map[string]string, current string, buildArgs []string, cfg *Config) {
	bootstrap := pythonBootstrapSet(marked)
	var rest []string
	for _, name := range sortedKeys(keysOf(marked)) {
		if !slices.Contains(bootstrap, name) {
			rest = append(rest, name)
		}
	}
	colArrow.Print("-> ")
	colSuccess.Printf("Rebuilding %d package(s) against python %s\n", len(marked), current)

	oldPath, hadPath := os.LookupEnv("PYTHONPATH")
	restorePath := func() {
		if hadPath {
			os.Setenv("PYTHONPATH", oldPath)
		} else {
			os.Unsetenv("PYTHONPATH")
		}
	}
	defer restorePath()

	if len(bootstrap) > 0 {
		// The new python sees none of the build tools: their packages are
		// built for the old one, and a build container has them installed
		// only while a build needs them. Install the published ones, so their
		// pure-Python code runs on the new python from PYTHONPATH (see
		// pythonBootstrapPath) while they are rebuilt.
		for _, name := range bootstrap {
			if !isPackageInstalled(name) {
				if _, err := ensurePackageInstalled(name, cfg, false); err != nil {
					colWarn.Printf("Warning: failed to install the published %s: %v\n", name, err)
				}
			}
		}
		order := pythonBootstrapOrder(bootstrap, marked)
		colArrow.Print("-> ")
		colSuccess.Printf("Building the Python build tools first: %s\n", strings.Join(order, " "))
		// One at a time, each installed before the next, with PYTHONPATH made
		// afresh from the old copies still installed: a tool once rebuilt
		// replaced its old copy, and a link left to it would shadow the new
		// one (a dangling setuptools .dist-info hid its entry points).
		for _, name := range order {
			cleanup := setPythonBootstrapPath(bootstrap, current)
			args := append(append(append([]string{}, buildArgs...), "--no-install"), name)
			if err := handleBuildCommand(args, cfg); err != nil {
				debugf("python-rebuild: bootstrap build of %s: %v\n", name, err)
			}
			installBuiltRecipes([]string{name}, cfg)
			cleanup()
		}
		for _, name := range bootstrap {
			if !builtRecipePackage(BinDir, name, marked[name]) {
				colWarn.Printf("Warning: %s did not rebuild; the rest uses its old copy\n", name)
			}
		}
	}

	// What one of the rest needs from another is built and installed on the
	// way; the rest is not installed. A build tool that did not rebuild keeps
	// its old copy on PYTHONPATH, so its failure is reported once rather than
	// failing every package that uses it.
	if len(rest) > 0 {
		cleanup := setPythonBootstrapPath(bootstrap, current)
		defer cleanup()
		colArrow.Print("-> ")
		colSuccess.Printf("Building the remaining %d package(s)\n", len(rest))
		args := append(append(append([]string{}, buildArgs...), "--no-install"), rest...)
		if err := handleBuildCommand(args, cfg); err != nil {
			debugf("python-rebuild: build: %v\n", err)
		}
	}
}

// setPythonBootstrapPath points PYTHONPATH at the old-Python copies of the
// tools among pkgs still installed, or unsets it when there are none. The
// returned function removes the link directory.
func setPythonBootstrapPath(pkgs []string, current string) func() {
	path, err := pythonBootstrapPath(pkgs, current)
	if err != nil {
		colWarn.Printf("Warning: failed to prepare the old build tools: %v\n", err)
	}
	if path == "" {
		os.Unsetenv("PYTHONPATH")
		return func() {}
	}
	os.Setenv("PYTHONPATH", path)
	return func() { os.RemoveAll(path) }
}

// pythonBootstrapOrder sorts the build tools so each comes after the tools
// among them it depends on (build-time dependencies included); ties, and
// tools caught in a cycle, go in name order.
func pythonBootstrapOrder(tools []string, marked map[string]string) []string {
	inSet := make(map[string]bool, len(tools))
	for _, name := range tools {
		inSet[name] = true
	}
	needs := make(map[string]map[string]bool, len(tools))
	for _, name := range tools {
		needs[name] = make(map[string]bool)
		deps, err := parseDependsFile(marked[name])
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep.Cross || dep.CrossNative || dep.Suggest || dep.Optional {
				continue
			}
			names := dep.Alternatives
			if len(names) == 0 {
				names = []string{dep.Name}
			}
			for _, n := range names {
				if inSet[n] && n != name {
					needs[name][n] = true
				}
			}
		}
	}
	var order []string
	done := make(map[string]bool, len(tools))
	for len(order) < len(tools) {
		progressed := false
		for _, name := range sortedKeys(inSet) {
			if done[name] {
				continue
			}
			ready := true
			for dep := range needs[name] {
				if !done[dep] {
					ready = false
					break
				}
			}
			if ready {
				order = append(order, name)
				done[name] = true
				progressed = true
			}
		}
		if !progressed {
			// A cycle (flit-core and installer build each other): break it
			// with the tool that waits for the fewest others, its old copy
			// standing in for the rest.
			// Ties go to the tool more of the others wait for.
			pick, fewest, mostWaiting := "", -1, -1
			for _, name := range sortedKeys(inSet) {
				if done[name] {
					continue
				}
				unmet, waiting := 0, 0
				for dep := range needs[name] {
					if !done[dep] {
						unmet++
					}
				}
				for other := range inSet {
					if !done[other] && needs[other][name] {
						waiting++
					}
				}
				if fewest < 0 || unmet < fewest || (unmet == fewest && waiting > mostWaiting) {
					pick, fewest, mostWaiting = name, unmet, waiting
				}
			}
			order = append(order, pick)
			done[pick] = true
		}
	}
	return order
}

// installBuiltRecipes installs the packages just built of recipes, from
// BinDir. A build's own install is no use here: python and the build tools
// are build dependencies of themselves, installed from the mirror for the
// build, and the build removes them again as temporary.
func installBuiltRecipes(recipes []string, cfg *Config) {
	for _, name := range recipes {
		version, revision, err := getRepoVersion2(name)
		if err != nil {
			continue
		}
		tarball := findCachedBinaryTarballVersion(getOutputPackageName(name, cfg), version, revision, cfg)
		if tarball == "" {
			continue // did not build: reported with the others
		}
		// Its runtime dependencies may have gone with the build's cleanup.
		if _, err := installBinaryTarballWithRemotePolicy(tarball, name, cfg, false, false); err != nil {
			colWarn.Printf("Warning: failed to install %s: %v\n", filepath.Base(tarball), err)
		}
	}
}

// pythonUpgradeConfirm bumps the revision of every package the upgrade
// rebuilds, commits and pushes, and releases python: the next rebuild round
// builds python and the bumped packages and publishes them together. It
// wants a check in which everything built, unless force.
func pythonUpgradeConfirm(from string, force bool, cfg *Config) error {
	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return fmt.Errorf("remote index unavailable: %w", err)
	}
	state, err := currentPythonUpgrade(cfg, index, from)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("no python upgrade is waiting")
	}
	switch {
	case state.Status == pythonUpgradeConfirmed:
		return fmt.Errorf("the python %s upgrade is already confirmed", state.To)
	case state.Status == pythonUpgradePassed:
	case force:
		colWarn.Printf("Warning: confirming python %s without a passed check (%s)\n", state.To, state.Status)
	case state.Status == pythonUpgradePending:
		return fmt.Errorf("python %s has not been checked yet: run hokuto-builder python-rebuild --check first, or confirm with --force", state.To)
	default:
		return fmt.Errorf("the last check of python %s had %d failure(s): fix them and check again, or confirm with --force", state.To, len(state.Failed))
	}

	arch := GetSystemArch(cfg)
	recipes := pythonRebuildRecipes(index, arch, state.From)
	published := make(map[string]RepoEntry)
	for _, e := range latestIndexEntries(index) {
		if e.Arch == arch && e.Type != "meta" {
			published[e.Name] = e
		}
	}
	notes := make(map[string]string)
	for _, name := range sortedKeys(keysOf(recipes)) {
		e, ok := published[name]
		if !ok {
			continue // never published: built on its own when it is
		}
		if rebuildPending(name, e) {
			continue // already ahead of its package
		}
		notes[name] = "python " + state.To
	}

	msg := fmt.Sprintf("python %s: rebuild dependent packages", state.To)
	if len(notes) > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("Bumping the revision of %d package(s) for python %s\n", len(notes), state.To)
		result, err := bumpRebuildRecipes(notes, msg)
		for _, skipped := range result.Skipped {
			colWarn.Printf("Warning: not bumped: %s\n", skipped)
		}
		if err != nil {
			return err
		}
	}

	state.Status = pythonUpgradeConfirmed
	if err := savePythonUpgrade(state); err != nil {
		return err
	}
	postPythonUpgradeNotice(state, cfg)
	colArrow.Print("-> ")
	colSuccess.Printf("python %s released: run `hokuto-builder rebuild` to build and publish python and the bumped packages\n", state.To)
	return nil
}

// pythonUpgradeCancel forgets the upgrade, for when the python bump is
// reverted.
func pythonUpgradeCancel(cfg *Config) error {
	if err := os.Remove(pythonUpgradeFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	removeWebsiteNotice(pythonUpgradeNoticeID)
	colArrow.Print("-> ")
	colSuccess.Println("The python upgrade is no longer held.")
	return nil
}

// pythonUpgradeNoticeID names the upgrade's notice on the website.
const pythonUpgradeNoticeID = "python-upgrade"

// postPythonUpgradeNotice shows the upgrade's state on the website, and
// removes the notice once it is confirmed.
func postPythonUpgradeNotice(state *pythonUpgrade, cfg *Config) {
	if state.Status == pythonUpgradeConfirmed {
		removeWebsiteNotice(pythonUpgradeNoticeID)
		return
	}
	notice := WebsiteNotice{
		ID:    pythonUpgradeNoticeID,
		Level: "warn",
		Title: fmt.Sprintf("python %s → %s: rebuild required", state.From, state.To),
	}
	switch state.Status {
	case pythonUpgradePending:
		notice.Text = "A new Python minor release is held back: nothing was bumped and python was not published. " +
			"Test the rebuild with hokuto-builder python-rebuild --check."
	case pythonUpgradePassed:
		notice.Level = "ok"
		notice.Text = fmt.Sprintf("Checked %s: all %d packages build against python %s. Bump them with hokuto-builder python-rebuild --confirm.",
			shortTime(state.Checked), len(state.Packages), state.To)
	case pythonUpgradeFailed:
		notice.Text = fmt.Sprintf("Checked %s: %d of %d packages fail against python %s: %s.",
			shortTime(state.Checked), len(state.Failed), len(state.Packages), state.To, strings.Join(state.Failed, ", "))
	}
	setWebsiteNotice(notice)
}

// shortTime turns an RFC 3339 time into "2006-01-02 15:04 UTC".
func shortTime(value string) string {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return value
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// sortedNotes returns the names of notes in order.
func sortedNotes(notes map[string]string) []string {
	names := make([]string, 0, len(notes))
	for name := range notes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
