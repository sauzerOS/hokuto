package hokuto

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gookit/color"
)

type syncPackage struct {
	Full     string // package name on the mirror (aarch64-gcc for -system)
	Base     string // recipe name, what gets built
	Version  string
	Revision string
}

// crossSyncPrefix names the cross-system (toolchain/sysroot) packages that
// -cross=arm64,system builds.
const crossSyncPrefix = "aarch64-"

// crossSyncArch is the architecture cross-sync builds for, as the build
// blacklist records it.
const crossSyncArch = "aarch64"

func handleCrossSyncCommand(args []string, cfg *Config) error {
	// use build-style arg preprocessing for -jN support
	args = PreprocessBuildArgs(args)

	syncCmd := flag.NewFlagSet("cross-sync", flag.ContinueOnError)
	systemModeFlag := syncCmd.Bool("system", false, "Sync the cross-system packages (aarch64-*) on the mirror instead of native aarch64 packages")
	idleFlag := syncCmd.Bool("i", false, "Use idle build priority")
	noInstallFlag := syncCmd.Bool("no-install", false, "Do not offer to install the built -system packages on this host")
	parallelFlag := syncCmd.Int("j", 1, "Number of parallel build jobs")
	yesFlag := syncCmd.Bool("y", false, "Build every missing package and answer yes to every question")

	if err := syncCmd.Parse(args); err != nil {
		return err
	}

	systemMode := *systemModeFlag

	// Fetch remote index early
	colArrow.Print("-> ")
	colSuccess.Println("Checking remote repository index")
	remoteIndex, _ := FetchRemoteIndex(cfg)

	var targetPkgs []syncPackage
	colArrow.Print("-> ")
	if systemMode {
		colSuccess.Println("Scanning the mirror for cross-system packages (aarch64-*)")
		targetPkgs = crossSystemSyncTargets(remoteIndex)
	} else {
		colSuccess.Println("Scanning repository for existing native aarch64 packages")
		targetPkgs = nativeSyncTargets(remoteIndex)
	}

	if len(targetPkgs) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No packages found to sync.")
		return nil
	}

	missing := missingSyncPackages(targetPkgs, remoteIndex)
	// A package whose aarch64 build failed in an unattended run waits for its
	// next version or revision (hokuto blacklist remove retries it sooner).
	if ignores, err := loadBuildIgnoreList(); err == nil && len(ignores) > 0 {
		var kept []syncPackage
		hidden := 0
		for _, pkg := range missing {
			if buildIgnoredArch(ignores, pkg.Full, crossSyncArch, pkg.Version+"-"+pkg.Revision) {
				hidden++
				continue
			}
			kept = append(kept, pkg)
		}
		if hidden > 0 {
			colArrow.Print("-> ")
			colNote.Printf("%d blacklisted package(s) skipped until their version or revision changes (hokuto blacklist)\n", hidden)
		}
		missing = kept
	}
	if len(missing) == 0 {
		colArrow.Print("-> ")
		if systemMode {
			colSuccess.Println("All cross-system packages on the mirror are at their repository version.")
		} else {
			colSuccess.Println("All tracked repository packages have corresponding native aarch64 binaries.")
		}
		return nil
	}

	// Print Missing List
	fmt.Println()
	if systemMode {
		colSuccess.Println("Missing or outdated cross-system packages:")
	} else {
		colSuccess.Println("Missing or outdated native aarch64 packages:")
	}
	for i, pkg := range missing {
		colArrow.Print("-> ")
		fmt.Printf("%2d) ", i+1)
		color.Bold.Printf("%s", pkg.Full)
		fmt.Printf(" (%s-%s)\n", pkg.Version, pkg.Revision)
	}
	fmt.Println()

	var toBuild []syncPackage
	if *yesFlag {
		toBuild = missing
		// The build's own questions too: it runs unattended.
		oldAssumeYes := GlobalAssumeYes
		GlobalAssumeYes = true
		defer func() { GlobalAssumeYes = oldAssumeYes }()
	} else {
		promptMsg := "Build (a)ll, (q)uit, or pick packages to build (numbers or -numbers):"
		indices, ok := AskForSelection(promptMsg, len(missing))
		if !ok {
			colNote.Println("Operation canceled.")
			return nil
		}
		for _, idx := range indices {
			toBuild = append(toBuild, missing[idx])
		}
	}

	// Execute Build
	if len(toBuild) == 0 {
		return nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Starting build for %d packages\n", len(toBuild))

	buildArgs := crossSyncBuildArgs(systemMode, *idleFlag, *noInstallFlag, *parallelFlag, toBuild)

	// Single call to handleBuildCommand allows it to manage parallel builds and order
	buildErr := handleBuildCommand(buildArgs, cfg)
	// Unattended: a failed package is not tried again every run.
	if *yesFlag {
		releases := make(map[string]string, len(toBuild))
		bases := make(map[string]string, len(toBuild))
		names := make([]string, 0, len(toBuild))
		for _, pkg := range toBuild {
			releases[pkg.Full] = pkg.Version + "-" + pkg.Revision
			bases[pkg.Full] = pkg.Base
			names = append(names, pkg.Full)
		}
		blacklistFailedBuilds(names, crossSyncArch,
			func(name string) string { return releases[name] },
			func(name string) bool { return ownBuildFailed(name) || ownBuildFailed(bases[name]) })
	}
	if buildErr != nil {
		return fmt.Errorf("build failed: %w", buildErr)
	}

	return nil
}

// crossSyncBuildArgs are the hokuto build arguments for the selected
// packages. Native aarch64 builds publish their status to the website's
// package table (--index), listed under aarch64 next to the x86_64 builds;
// -system builds are the build host's cross toolchain and sysroot
// (aarch64-*), which the table does not list.
func crossSyncBuildArgs(systemMode, idle, noInstall bool, jobs int, pkgs []syncPackage) []string {
	args := []string{"--cross=arm64"}
	if systemMode {
		args = []string{"--cross=arm64,system"}
	} else {
		args = append(args, "--index")
	}
	if idle {
		args = append(args, "-i")
	}
	if noInstall {
		args = append(args, "--no-install")
	}
	if jobs > 1 {
		args = append(args, "-j"+strconv.Itoa(jobs))
	}
	for _, pkg := range pkgs {
		args = append(args, pkg.Base)
	}
	return args
}

// nativeSyncTargets lists the recipes, at their repository version, that
// already have at least one native aarch64 package on the mirror.
func nativeSyncTargets(remoteIndex []RepoEntry) []syncPackage {
	supportedOnMirror := make(map[string]bool)
	for _, entry := range remoteIndex {
		if entry.Arch == "aarch64" {
			supportedOnMirror[entry.Name] = true
		}
	}

	var targets []syncPackage
	seen := make(map[string]bool)
	for _, base := range filepath.SplitList(repoPaths) {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			pkgName := e.Name()
			if !e.IsDir() || seen[pkgName] || !supportedOnMirror[pkgName] {
				continue
			}
			version, revision, ok := readRecipeVersion(filepath.Join(base, pkgName))
			if !ok {
				continue
			}
			targets = append(targets, syncPackage{Full: pkgName, Base: pkgName, Version: version, Revision: revision})
			seen[pkgName] = true
		}
	}
	return targets
}

// crossSystemSyncTargets lists the cross-system packages published on the
// mirror (aarch64-<recipe>), each at its recipe's current version, so the
// toolchain stays current without being installed anywhere. Packages whose
// recipe is gone are skipped.
func crossSystemSyncTargets(remoteIndex []RepoEntry) []syncPackage {
	var targets []syncPackage
	seen := make(map[string]bool)
	for _, entry := range remoteIndex {
		if entry.Type == "meta" || entry.Arch != "aarch64" || !strings.HasPrefix(entry.Name, crossSyncPrefix) || seen[entry.Name] {
			continue
		}
		seen[entry.Name] = true
		base := strings.TrimPrefix(entry.Name, crossSyncPrefix)
		pkgDir, err := findPackageMetadataDir(base)
		if err != nil {
			debugf("cross-sync: no recipe for %s, skipping\n", entry.Name)
			continue
		}
		version, revision, ok := readRecipeVersion(pkgDir)
		if !ok {
			continue
		}
		targets = append(targets, syncPackage{Full: entry.Name, Base: base, Version: version, Revision: revision})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Full < targets[j].Full })
	return targets
}

// missingSyncPackages returns the targets with no aarch64 package of exactly
// their version, neither in the local binary cache nor on the mirror.
func missingSyncPackages(targets []syncPackage, remoteIndex []RepoEntry) []syncPackage {
	var missing []syncPackage
	for _, pkg := range targets {
		found := false
		for _, variant := range []string{"optimized", "generic"} {
			filename := StandardizeRemoteName(pkg.Full, pkg.Version, pkg.Revision, "aarch64", variant)
			if _, err := os.Stat(filepath.Join(BinDir, filename)); err == nil {
				found = true
				break
			}
		}
		for i := 0; !found && i < len(remoteIndex); i++ {
			entry := remoteIndex[i]
			found = entry.Name == pkg.Full && entry.Version == pkg.Version && entry.Revision == pkg.Revision && entry.Arch == "aarch64"
		}
		if !found {
			missing = append(missing, pkg)
		}
	}
	return missing
}

// readRecipeVersion reads a recipe's "version revision" file; the revision
// defaults to 1.
func readRecipeVersion(pkgDir string) (version, revision string, ok bool) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		return "", "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", "", false
	}
	revision = "1"
	if len(fields) >= 2 {
		revision = fields[1]
	}
	return fields[0], revision, true
}

func getInstalledVersionAndRevision(pkgName string) (string, string, error) {
	versionFile := filepath.Join(Installed, pkgName, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "", "", fmt.Errorf("empty version file")
	}
	version := fields[0]
	revision := "1"
	if len(fields) >= 2 {
		revision = fields[1]
	}
	return version, revision, nil
}
