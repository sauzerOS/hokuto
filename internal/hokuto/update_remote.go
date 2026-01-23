package hokuto

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gookit/color"
)

// checkForRemoteUpgrades implements 'hokuto update --remote'
// It compares installed packages against the remote index and updates them if newer versions exist.
func checkForRemoteUpgrades(ctx context.Context, cfg *Config) error {
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

	for name, pkg := range installedPackages {
		// Find matching entry in remote index with correct Arch/Variant
		// (Assume current system settings)
		// We filter remote index to find the entry matching pkg.Name
		var remoteEntry RepoEntry
		found := false

		// We need to match based on system arch/variant preferences
		targetArch := GetSystemArch(cfg)
		// Determine variant (generic/optimized/multilib)
		// Note: installed variant might differ, but we check what we WOULD install
		targetVariant := GetSystemVariantForPackage(cfg, name)

		for _, entry := range remoteIndex {
			if entry.Name == name && entry.Arch == targetArch && entry.Variant == targetVariant {
				remoteEntry = entry
				found = true
				break
			}
		}

		if !found {
			// Maybe generic fallback?
			if targetVariant != "generic" {
				targetVariant = "generic"
				for _, entry := range remoteIndex {
					if entry.Name == name && entry.Arch == targetArch && entry.Variant == targetVariant {
						remoteEntry = entry
						found = true
						break
					}
				}
			}
		}

		if !found {
			continue // Package not in remote repo
		}

		// Store for later use
		targetPacketMap[name] = remoteEntry

		// Compare versions
		// Using RepoEntry struct which has string Version/Revision
		pkg.RepoVersion = remoteEntry.Version
		pkg.RepoRevision = remoteEntry.Revision

		isVersionMismatch := pkg.InstalledVersion != pkg.RepoVersion
		isRevisionMismatch := pkg.InstalledRevision != pkg.RepoRevision

		if isVersionMismatch || isRevisionMismatch {
			// Check if new version is actually newer?
			// Using helper isNewer(remoteEntry, currentEntry) would be better if we constructed a RepoEntry for current.
			// Currently we trust textual difference triggers update?
			// Let's use compareVersions logic if possible, or build a temp RepoEntry
			currentEntry := RepoEntry{
				Version:  pkg.InstalledVersion,
				Revision: pkg.InstalledRevision,
			}
			if isNewer(remoteEntry, currentEntry) {
				upgradeList = append(upgradeList, pkg)
			}
		}
	}

	if len(upgradeList) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No remote upgrades available.")
		return nil
	}

	// 4. Prompt User
	cPrintf(colInfo, "\n--- %d Remote Package(s) to Upgrade ---\n", len(upgradeList))
	var pkgNames []string
	for _, pkg := range upgradeList {
		cPrintf(colInfo, "  - %s: %s %s -> %s %s\n",
			pkg.Name,
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
		pkgNames = append(pkgNames, pkg.Name)
	}

	if !askForConfirmation(colWarn, "Do you want to upgrade these packages from remote?") {
		cPrintln(colNote, "Upgrade canceled by user.")
		return nil
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
	for _, e := range remoteIndex {
		if e.Name == pkgName {
			entry = e
			found = true
			break
		}
	}
	if !found {
		// Should not happen if resolved via remoteIndex, but safe check
		return fmt.Errorf("package %s not in remote index", pkgName)
	}

	version := entry.Version
	revision := entry.Revision
	arch := entry.Arch
	variant := entry.Variant

	tarballName := StandardizeRemoteName(pkgName, version, revision, arch, variant)
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
