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
	var upgradeList []Package
	targetPacketMap := make(map[string]RepoEntry)
	fallbackMap := make(map[string]bool)

	for name, pkg := range installedPackages {
		// Find matching entry in remote index with correct Arch/Variant
		// (Assume current system settings)
		// We filter remote index to find the entry matching pkg.Name
		var remoteEntry RepoEntry
		found := false

		// We need to match based on system arch/variant preferences
		targetArch := GetSystemArchForPackage(cfg, name)
		// Determine variant (generic/optimized/multilib)
		preferredVariant := GetSystemVariantForPackage(cfg, name)

		for _, entry := range remoteIndex {
			if entry.Name == name && entry.Arch == targetArch && entry.Variant == preferredVariant {
				remoteEntry = entry
				found = true
				break
			}
		}

		usingFallback := false
		if !found && !strings.Contains(preferredVariant, "generic") {
			// Try generic fallback
			fallbackVariant := "generic"
			if strings.HasPrefix(preferredVariant, "multi-") {
				fallbackVariant = "multi-generic"
			}

			for _, entry := range remoteIndex {
				if entry.Name == name && entry.Arch == targetArch && entry.Variant == fallbackVariant {
					remoteEntry = entry
					found = true
					usingFallback = true
					break
				}
			}
		}

		if !found {
			continue // Package not in remote repo
		}

		// If using fallback, prompt now or mark it?
		// Better to mark it in the version string or similar for the final table.
		repoVersionDisplay := remoteEntry.Version
		if usingFallback {
			repoVersionDisplay += " (generic fallback)"
		}

		// Store for later use
		targetPacketMap[name] = remoteEntry

		// Compare versions
		pkg.RepoVersion = remoteEntry.Version
		pkg.RepoRevision = remoteEntry.Revision

		currentEntry := RepoEntry{
			Version:  pkg.InstalledVersion,
			Revision: pkg.InstalledRevision,
		}
		if isNewer(remoteEntry, currentEntry) {
			// If it's a fallback, we need to ask permission specifically for this or inform the user
			pkg.RepoVersion = repoVersionDisplay // Hack to show fallback in the confirmation list
			upgradeList = append(upgradeList, pkg)
			if usingFallback {
				fallbackMap[name] = true
			}
		}
	}

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
	indices, ok := AskForSelection("Update (a)ll or pick packages to update/ignore (numbers or -numbers):", len(upgradeList))
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
		if err := resolveBinaryDependencies(pkgName, visited, &depPlan, false, true, cfg, remoteIndex); err != nil {
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
	found := false
	arch := GetSystemArchForPackage(cfg, pkgName)
	preferredVariant := GetSystemVariantForPackage(cfg, pkgName)

	var bestMatch *RepoEntry
	for _, e := range remoteIndex {
		if e.Name == pkgName && e.Arch == arch && e.Variant == preferredVariant {
			if bestMatch == nil || isNewer(e, *bestMatch) {
				bestMatch = &e
			}
		}
	}

	if bestMatch != nil {
		entry = *bestMatch
		found = true
	}

	// FALLBACK: Try generic
	if !found && !strings.Contains(preferredVariant, "generic") {
		fallbackVariant := "generic"
		if strings.HasPrefix(preferredVariant, "multi-") {
			fallbackVariant = "multi-generic"
		}

		for _, e := range remoteIndex {
			if e.Name == pkgName && e.Arch == arch && e.Variant == fallbackVariant {
				if bestMatch == nil || isNewer(e, *bestMatch) {
					bestMatch = &e
				}
			}
		}
		if bestMatch != nil {
			entry = *bestMatch
			found = true
		}
	}

	if !found {
		return fmt.Errorf("package %s not in remote index for %s (%s)", pkgName, arch, preferredVariant)
	}

	version := entry.Version
	revision := entry.Revision
	// Note: entry.Arch and entry.Variant are the ones we FOUND
	tarballName := StandardizeRemoteName(pkgName, version, revision, entry.Arch, entry.Variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	// Fetch if missing
	if _, err := os.Stat(tarballPath); err != nil {
		if err := fetchBinaryPackage(pkgName, version, revision, cfg); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	}

	// Install
	handlePreInstallUninstall(pkgName, cfg, RootExec)
	// We use 'true' for force/yes usually for updates? or pass explicit 'yes' flag?
	// Implicit 'yes' for updates usually.
	if err := pkgInstall(tarballPath, pkgName, cfg, RootExec, true); err != nil {
		return err
	}
	return nil
}
