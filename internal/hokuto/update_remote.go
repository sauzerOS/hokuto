package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gookit/color"
	"golang.org/x/term"
)

func bestRemoteUpdateEntry(pkgName string, cfg *Config, remoteIndex []RepoEntry) (RepoEntry, bool, bool) {
	targetArch := GetSystemArchForPackage(cfg, pkgName)
	preferredVariant := GetSystemVariantForPackage(cfg, pkgName)
	fallbackVariant := ""
	if !strings.Contains(preferredVariant, "generic") {
		fallbackVariant = "generic"
		if strings.HasPrefix(preferredVariant, "multi-") {
			fallbackVariant = "multi-generic"
		}
	}

	var best *RepoEntry
	archiveName := canonicalParallelPackageName(pkgName)
	for _, entry := range remoteIndex {
		if entry.Type == "meta" || entry.Name != archiveName || entry.Arch != targetArch {
			continue
		}
		if entry.Variant != preferredVariant && (fallbackVariant == "" || entry.Variant != fallbackVariant) {
			continue
		}
		if best == nil || isNewer(entry, *best) ||
			(entry.Version == best.Version && entry.Revision == best.Revision &&
				entry.Variant == preferredVariant && best.Variant != preferredVariant) {
			candidate := entry
			best = &candidate
		}
	}
	if best == nil {
		return RepoEntry{}, false, false
	}
	return *best, true, fallbackVariant != "" && best.Variant == fallbackVariant
}

func remoteUpgradeCandidates(installedPackages map[string]Package, cfg *Config, remoteIndex []RepoEntry) ([]Package, map[string]RepoEntry, map[string]bool) {
	var upgrades []Package
	targets := make(map[string]RepoEntry)
	fallbacks := make(map[string]bool)
	for name, pkg := range installedPackages {
		// ABI/version-line packages are historical dependency instances created
		// to satisfy a constraint (for example glibmm-2.66). They are not rolling
		// update targets: replacing one from the canonical remote archive can jump
		// to another ABI line and defeat the constraint that kept it installed.
		// Normal source updates already leave these instances alone.
		if _, _, versioned := splitVersionedPackageName(name); versioned {
			continue
		}
		remoteEntry, found, usingFallback := bestRemoteUpdateEntry(name, cfg, remoteIndex)
		if !found {
			continue
		}
		targets[name] = remoteEntry
		pkg.RepoVersion = remoteEntry.Version
		pkg.RepoRevision = remoteEntry.Revision
		if !isNewer(remoteEntry, RepoEntry{Version: pkg.InstalledVersion, Revision: pkg.InstalledRevision}) {
			continue
		}
		if usingFallback {
			pkg.RepoVersion += " (generic fallback)"
			fallbacks[name] = true
		}
		upgrades = append(upgrades, pkg)
	}
	return upgrades, targets, fallbacks
}

func remoteUpdateDependencyPlan(pkgName string, cfg *Config, remoteIndex []RepoEntry) ([]string, error) {
	deps, found, err := resolveBinaryDependenciesFromArchive(pkgName, cfg, remoteIndex, true)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("dependency metadata for %s is unavailable", pkgName)
	}

	visited := map[string]bool{pkgName: true}
	var plan []string
	if err := resolveDependencyList(pkgName, deps, visited, &plan, false, true, cfg, remoteIndex, true); err != nil {
		return nil, err
	}
	return plan, nil
}

// checkForRemoteUpgrades implements 'hokuto update --remote'
// It compares installed packages against the remote index and updates them if newer versions exist.
func checkForRemoteUpgrades(_ context.Context, cfg *Config, yes bool) error {
	colArrow.Print("-> ")
	colSuccess.Println("Checking for Remote Package Upgrades (Binary Mirror)")

	// 1. Fetch Remote Index
	remoteIndex, err := FetchRemoteIndex(cfg)
	if err != nil {
		return fmt.Errorf("failed to fetch remote index: %w", err)
	}

	// 2. Get Installed Packages
	output, err := getInstalledPackageOutput("")
	if err != nil {
		return fmt.Errorf("could not retrieve installed packages: %w", err)
	}
	installedPackages, err := parsePackageList(output)
	if err != nil {
		return fmt.Errorf("failed to parse package list: %w", err)
	}

	// 3. Identify Upgrades
	upgradeList, targets, fallbackMap := remoteUpgradeCandidates(installedPackages, cfg, remoteIndex)

	if len(upgradeList) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No remote upgrades available.")
		return nil
	}

	// Sort upgrade list alphabetically
	sort.SliceStable(upgradeList, func(i, j int) bool {
		return upgradeList[i].Name < upgradeList[j].Name
	})

	fmt.Println()
	colSuccess.Printf("--- %d Remote Package(s) to Upgrade ---\n", len(upgradeList))
	for i, pkg := range upgradeList {
		colArrow.Print("-> ")
		fmt.Printf("%2d) ", i+1)
		color.Bold.Printf("%s", pkg.Name)
		fmt.Print(": ")
		colNote.Printf("%s %s -> %s %s\n",
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
	}

	// 4. Prompt User; -y updates everything, as hokuto-builder rebuild expects.
	var indices []int
	if yes {
		for i := range upgradeList {
			indices = append(indices, i)
		}
	} else {
		var ok bool
		indices, ok = AskForSelection("Update (a)ll, (q)uit, or pick packages to update/ignore (numbers or -numbers):", len(upgradeList))
		if !ok {
			colNote.Println("Upgrade canceled by user.")
			return nil
		}
	}

	var pkgNames []string
	for _, idx := range indices {
		pkgNames = append(pkgNames, upgradeList[idx].Name)
	}

	// 4a. Specific confirmation for fallbacks
	var fallbacksFound []string
	for name := range fallbackMap {
		fallbacksFound = append(fallbacksFound, name)
	}

	if len(fallbacksFound) > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("No optimized variants found for: %v\n", fallbacksFound)
		if !yes && !askForConfirmation(colSuccess, "Use generic fallbacks for these packages?") {
			cPrintln(colNote, "Upgrade canceled by user.")
			return nil
		}
	}

	// 5. Prioritize hokuto update
	hokutoInUpdates := false
	for _, pkg := range upgradeList {
		if pkg.Name == "hokuto" {
			hokutoInUpdates = true
			break
		}
	}

	if hokutoInUpdates {
		colArrow.Printf("-> ")
		colSuccess.Println("Updating Hokuto")
		pkgNames = []string{"hokuto"}
	}

	// As pacman does: what the update downloads and how much the installed
	// size grows or shrinks, then confirm. Only on a terminal, so scripts
	// keep working; -y skips it.
	printRemoteUpdateSizes(computeRemoteUpdateSizes(pkgNames, targets, cfg, remoteIndex))
	if !yes && term.IsTerminal(int(os.Stdin.Fd())) {
		colArrow.Print("-> ")
		if !askForConfirmation(colSuccess, "Proceed with installation?") {
			colArrow.Print("-> ")
			colWarn.Println("Upgrade canceled.")
			return nil
		}
	}

	// 6. Execute Updates
	// The whole run is planned first: each update after the dependencies it
	// brings that are not installed. Everything is downloaded at once, then
	// installed in order as "hokuto install" does: each package quietly
	// under one bar, the global post-install tasks once at the end.
	type remoteStep struct {
		name   string
		target string // the update this step is for
		isDep  bool
	}
	var steps []remoteStep
	var failed []string
	planned := make(map[string]bool)
	for _, pkgName := range pkgNames {
		depPlan, err := remoteUpdateDependencyPlan(pkgName, cfg, remoteIndex)
		if err != nil {
			color.Danger.Printf("Failed to resolve dependencies for %s: %v\n", pkgName, err)
			failed = append(failed, fmt.Sprintf("%s (dependency resolution: %v)", pkgName, err))
			continue
		}
		for _, dep := range depPlan {
			if !planned[dep] {
				planned[dep] = true
				steps = append(steps, remoteStep{name: dep, target: pkgName, isDep: true})
			}
		}
		planned[pkgName] = true
		steps = append(steps, remoteStep{name: pkgName, target: pkgName})
	}

	var entries []RepoEntry
	for _, step := range steps {
		if entry, err := remoteUpdateEntry(step.name, cfg, remoteIndex); err == nil {
			entries = append(entries, entry)
		}
	}
	prefetchRepoEntries(entries, cfg)

	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)

	var progress *installProgress
	if !Debug {
		progress = newInstallProgress(len(steps))
	}
	fast := progress != nil

	totalUpdated := 0
	targetFailed := make(map[string]bool)
	for i, step := range steps {
		if targetFailed[step.target] {
			// A dependency of this update failed: it is not installed.
			progress.advance()
			continue
		}
		if fast {
			progress.start(step.name)
		} else {
			colArrow.Print("\n-> ")
			if step.isDep {
				colSuccess.Printf("Installing dependency %s for %s (%d/%d)\n", step.name, step.target, i+1, len(steps))
			} else {
				colSuccess.Printf("Updating %s (%d/%d)\n", step.name, i+1, len(steps))
			}
		}
		if err := installRemotePackage(step.name, cfg, remoteIndex, yes, fast); err != nil {
			progress.endLine()
			targetFailed[step.target] = true
			if step.isDep {
				color.Danger.Printf("Failed to install dependency %s: %v\n", step.name, err)
				failed = append(failed, fmt.Sprintf("%s (dependency %s: %v)", step.target, step.name, err))
			} else {
				color.Danger.Printf("Failed to update %s: %v\n", step.name, err)
				failed = append(failed, fmt.Sprintf("%s: %v", step.name, err))
			}
			progress.advance()
			continue
		}
		progress.advance()
		if !step.isDep {
			totalUpdated++
			if !fast {
				colArrow.Print("-> ")
				colSuccess.Printf("Package %s updated successfully.\n", step.name)
			}
		}
	}
	progress.finish(len(failed) == 0)
	if fast && len(steps) > 0 {
		// Installed in fast mode, which leaves these to the end.
		colArrow.Print("-> ")
		colSuccess.Println("Running post-install tasks")
		if err := PostInstallTasks(RootExec, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Global post-install tasks failed: %v\n", err)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("some remote packages failed to update: %s", strings.Join(failed, "; "))
	}

	if hokutoInUpdates && len(upgradeList) > 1 {
		colArrow.Print("-> ")
		colSuccess.Println("Hokuto has been updated. Run 'hokuto update' again to complete the remaining updates.")
		return nil
	}

	colArrow.Print("\n-> ")
	colSuccess.Printf("Remote update complete. Updated %d packages.\n", totalUpdated)
	return nil
}

// remoteUpdateEntry is the index entry a remote update installs for
// pkgName: the newest release of the preferred variant, or of the generic
// one when only that exists.
func remoteUpdateEntry(pkgName string, cfg *Config, remoteIndex []RepoEntry) (RepoEntry, error) {
	arch := GetSystemArchForPackage(cfg, pkgName)
	preferredVariant := GetSystemVariantForPackage(cfg, pkgName)
	fallbackVariant := ""
	if !strings.Contains(preferredVariant, "generic") {
		fallbackVariant = "generic"
		if strings.HasPrefix(preferredVariant, "multi-") {
			fallbackVariant = "multi-generic"
		}
	}

	var bestMatch *RepoEntry
	archivePkgName := canonicalParallelPackageName(pkgName)
	for _, e := range remoteIndex {
		if e.Name == archivePkgName && versionedPackageMajorMatches(pkgName, e.Version) && e.Arch == arch {
			if e.Variant == preferredVariant || (fallbackVariant != "" && e.Variant == fallbackVariant) {
				if bestMatch == nil || isNewer(e, *bestMatch) ||
					(e.Version == bestMatch.Version && e.Revision == bestMatch.Revision &&
						e.Variant == preferredVariant && bestMatch.Variant != preferredVariant) {
					entryCopy := e
					bestMatch = &entryCopy
				}
			}
		}
	}
	if bestMatch == nil {
		return RepoEntry{}, fmt.Errorf("package %s not in remote index for %s (preferred: %s)", pkgName, arch, preferredVariant)
	}
	return *bestMatch, nil
}

// installRemotePackage fetches and installs a package from the remote index.
// yes is the update's own -y: without it the installer asks what to do with
// a file modified on this system, as "hokuto install" does, instead of
// keeping it silently (a /usr/bin/hokuto copied in by hand stayed in place
// through a hokuto update). fast installs it quietly under the caller's
// progress bar, leaving the global post-install tasks to the caller.
func installRemotePackage(pkgName string, cfg *Config, remoteIndex []RepoEntry, yes, fast bool) error {
	entry, err := remoteUpdateEntry(pkgName, cfg, remoteIndex)
	if err != nil {
		return err
	}
	archivePkgName := canonicalParallelPackageName(pkgName)
	tarballName := StandardizeRemoteName(archivePkgName, entry.Version, entry.Revision, entry.Arch, entry.Variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	if _, err := os.Stat(tarballPath); err != nil {
		if err := fetchSpecificBinaryPackage(archivePkgName, entry.Version, entry.Revision, entry.Variant, cfg, fast, entry.B3Sum, false); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	}

	handlePreInstallUninstall(pkgName, cfg, RootExec, false, nil)
	if _, err := pkgInstallWithRemotePolicy(tarballPath, pkgName, cfg, RootExec, yes, fast, false, false, nil); err != nil {
		return err
	}
	return nil
}
