package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gookit/color"
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

// checkForRemoteUpgrades implements 'hokuto update --remote'
// It compares installed packages against the remote index and updates them if newer versions exist.
func checkForRemoteUpgrades(_ context.Context, cfg *Config) error {
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
	upgradeList, _, fallbackMap := remoteUpgradeCandidates(installedPackages, cfg, remoteIndex)

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

	// 4. Prompt User
	indices, ok := AskForSelection("Update (a)ll, (q)uit, or pick packages to update/ignore (numbers or -numbers):", len(upgradeList))
	if !ok {
		colNote.Println("Upgrade canceled by user.")
		return nil
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
		if !askForConfirmation(colSuccess, "Use generic fallbacks for these packages?") {
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

	// We'll iterate the upgrade list.
	// For each package, we'll first ensure its dependencies are met (installing missing ones).
	// Then we update the package itself.

	// 6. Execute Updates
	// Logic similar to checkForUpgrades loop but purely remote.

	// Track duplication to avoid re-checking in same run
	processedDeps := make(map[string]bool)
	visited := make(map[string]bool)

	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)

	totalUpdated := 0
	for i, pkgName := range pkgNames {
		colArrow.Print("\n-> ")
		colSuccess.Printf("Updating %s (%d/%d)\n", pkgName, i+1, len(pkgNames))

		// 6a. Resolve and Install Missing Dependencies
		// We can use resolveBinaryDependencies with force=false.
		// It will add MISSING deps to 'depPlan'.
		// We install them first.
		var depPlan []string
		// We need a fresh visited map for each root or shared? Shared is better to skip re-checks.
		// But resolveBinaryDependencies with visited will skip.
		// We can use the global visited for this run.
		if err := resolveBinaryDependencies(pkgName, visited, &depPlan, false, true, cfg, remoteIndex, true); err != nil {
			color.Danger.Printf("Failed to resolve dependencies for %s: %v\n", pkgName, err)
			continue // Skip this update?
		}

		// Install missing deps found
		for _, dep := range depPlan {
			if processedDeps[dep] {
				continue
			}
			// Install dep
			if err := installRemotePackage(dep, cfg, remoteIndex); err != nil {
				color.Danger.Printf("Failed to install dependency %s: %v\n", dep, err)
				// Determine if we should abort or continue
			} else {
				processedDeps[dep] = true
			}
		}

		// 6b. Install the Package Update (Target)
		if err := installRemotePackage(pkgName, cfg, remoteIndex); err != nil {
			color.Danger.Printf("Failed to update %s: %v\n", pkgName, err)
		} else {
			processedDeps[pkgName] = true
			totalUpdated++
			colArrow.Print("-> ")
			colSuccess.Printf("Package %s updated successfully.\n", pkgName)
		}
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

// installRemotePackage fetches and installs a package from the remote index
func installRemotePackage(pkgName string, cfg *Config, remoteIndex []RepoEntry) error {
	// Find entry
	var entry RepoEntry
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
		return fmt.Errorf("package %s not in remote index for %s (preferred: %s)", pkgName, arch, preferredVariant)
	}

	entry = *bestMatch

	version := entry.Version
	revision := entry.Revision
	// Note: entry.Arch and entry.Variant are the ones we FOUND
	tarballName := StandardizeRemoteName(archivePkgName, version, revision, entry.Arch, entry.Variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	if _, err := os.Stat(tarballPath); err != nil {
		if err := fetchSpecificBinaryPackage(archivePkgName, version, revision, entry.Variant, cfg, false, entry.B3Sum, false); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	}

	// Install
	handlePreInstallUninstall(pkgName, cfg, RootExec, false, nil)
	// We use 'true' for force/yes usually for updates? or pass explicit 'yes' flag?
	// Implicit 'yes' for updates usually.
	if _, err := pkgInstallWithRemotePolicy(tarballPath, pkgName, cfg, RootExec, true, false, false, false, nil); err != nil {
		return err
	}
	return nil
}
