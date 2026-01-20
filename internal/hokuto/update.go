package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gookit/color"
)

// getRepoVersion reads pkgname/version from repoPaths and returns the version string.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// We only care about the first field (the version).

func getRepoVersion(pkgName string) (string, error) {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return "", fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
	}

	versionFile := filepath.Join(pkgDir, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", fmt.Errorf("could not read version file for %s at %s: %w", pkgName, versionFile, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("invalid version file format (empty file) for %s at %s", pkgName, versionFile)
	}
	return fields[0], nil
}

// getRepoVersion2 reads pkgname/version from repoPaths and returns the version string,
// the revision string, and an error.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// used for the update check

func getRepoVersion2(pkgName string) (version string, revision string, err error) {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return "", "", fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
	}

	versionFile := filepath.Join(pkgDir, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", "", fmt.Errorf("could not read version file for %s at %s: %w", pkgName, versionFile, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "", "", fmt.Errorf("invalid version file format (missing version) for %s at %s", pkgName, versionFile)
	}
	pkgVersion := fields[0]
	pkgRevision := "1" // Default revision if only one field is present
	if len(fields) >= 2 {
		pkgRevision = fields[1]
	}

	return pkgVersion, pkgRevision, nil
}

// getBaseRepoPath extracts the base repository path (e.g., "/repo/reponame1")
// from a longer path (e.g., "/repo/reponame1/one").

func getBaseRepoPath(fullPath string) string {
	parts := strings.Split(fullPath, "/")

	// Example: for "/repo/reponame1/one", parts is ["", "repo", "reponame1", "one"]

	// We need at least parts for "", "repo", "reponameX". Length >= 3.
	if len(parts) < 3 {
		return fullPath
	}

	// We explicitly construct the path to ensure the leading '/' is present.
	// parts[0] is "", parts[1] is "repo", parts[2] is "reponame1"
	// We want to join "repo" and "reponame1" and prepend "/"

	// Check if the path is absolute (starts with '/')
	isAbs := strings.HasPrefix(fullPath, "/")

	// The components we want to join are parts[1] and parts[2]
	repoDir := path.Join(parts[1], parts[2])

	if isAbs {
		// Prepend the "/" to make it absolute again
		return "/" + repoDir
	}

	return repoDir // Return the relative path if the original wasn't absolute (though it should be)
}

// updateRepos updates each unique repository found in repoPaths

func updateRepos() {
	// 1. Split the global repoPaths string by the path separator ":"
	paths := strings.Split(repoPaths, ":")

	// 2. Determine the unique base repository directories
	uniqueRepoDirs := make(map[string]struct{})
	for _, p := range paths {
		// Clean the path to get the base repository directory
		repoDir := getBaseRepoPath(p)

		if repoDir != "" {
			uniqueRepoDirs[repoDir] = struct{}{}
		}
	}
	colArrow.Print("-> ")
	colSuccess.Println("Unique repositories to update:")
	for dir := range uniqueRepoDirs {
		colArrow.Print("-> ")
		colSuccess.Printf("%s\n", dir)

		// 3. Execute 'git pull' in each unique directory
		// We use dir as the working directory for 'git pull'
		cmd := exec.Command("git", "pull")
		cmd.Dir = dir // Set the working directory for the command

		// Capture output for logging and error checking
		output, err := cmd.CombinedOutput()
		outputStr := strings.TrimSpace(string(output))

		if err != nil {
			// Check if the error is due to local changes that would be overwritten
			if strings.Contains(outputStr, "would be overwritten by merge") {
				colArrow.Print("-> ")
				colWarn.Printf("Repository %s has local changes that would be overwritten.\n", dir)
				colArrow.Print("-> ")
				fmt.Printf("Output:\n%s\n", outputStr)

				// Prompt user to discard local changes
				if askForConfirmation(colWarn, "Discard local changes and pull updates from remote?") {
					// Reset local changes
					resetCmd := exec.Command("git", "reset", "--hard", "HEAD")
					resetCmd.Dir = dir
					resetOutput, resetErr := resetCmd.CombinedOutput()
					if resetErr != nil {
						fmt.Printf("Error resetting repository %s: %v\nOutput:\n%s\n", dir, resetErr, strings.TrimSpace(string(resetOutput)))
						continue
					}

					// Clean untracked files that might conflict
					cleanCmd := exec.Command("git", "clean", "-fd")
					cleanCmd.Dir = dir
					cleanOutput, cleanErr := cleanCmd.CombinedOutput()
					if cleanErr != nil {
						fmt.Printf("Warning: Error cleaning repository %s: %v\nOutput:\n%s\n", dir, cleanErr, strings.TrimSpace(string(cleanOutput)))
					}

					// Retry git pull
					retryCmd := exec.Command("git", "pull")
					retryCmd.Dir = dir
					retryOutput, retryErr := retryCmd.CombinedOutput()
					retryOutputStr := strings.TrimSpace(string(retryOutput))

					if retryErr != nil {
						fmt.Printf("Error pulling repo %s after reset: %v\nOutput:\n%s\n", dir, retryErr, retryOutputStr)
					} else {
						colArrow.Print("-> ")
						colSuccess.Printf("Successfully pulled repo %s after discarding local changes\nOutput:\n%s\n", dir, retryOutputStr)
					}
				} else {
					colArrow.Print("-> ")
					colWarn.Printf("Skipping repository %s (local changes preserved)\n", dir)
				}
			} else {
				fmt.Printf("Error pulling repo %s: %v\nOutput:\n%s\n", dir, err, outputStr)
			}
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Successfully pulled repo %s\nOutput:\n%s\n", dir, outputStr)
		}
	}
}

// checkPackageExists checks if a specific package directory exists in the Installed path.
// It returns true if the package directory exists and is a directory, false otherwise.
// This is a direct, silent check, ideal for internal dependency resolution.

func checkPackageExists(pkgName string) bool {
	// Determine the full path to the package's installed directory
	pkgPath := filepath.Join(Installed, pkgName)

	// Check if the path exists and is a directory.
	info, err := os.Stat(pkgPath)
	if err != nil {
		// os.IsNotExist(err) covers the most common failure,
		// any other error (permission, etc.) is treated as "not installed" for safety.
		return false
	}

	// Ensure it's actually a directory (to exclude possible stray files)
	return info.IsDir()
}

// getInstalledPackageOutput reads installed package versions from the filesystem,
// filters them by searchTerm, and returns the list as a formatted byte slice.

func getInstalledPackageOutput(searchTerm string) ([]byte, error) {
	var outputBuilder strings.Builder

	// Step 1: Get the full list of installed package directories.
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			// If the directory doesn't exist, treat it as empty, no error.
			return []byte(""), nil
		}
		return nil, fmt.Errorf("failed to read installed directory %s: %w", Installed, err)
	}

	var allPkgs []string
	for _, e := range entries {
		if e.IsDir() {
			allPkgs = append(allPkgs, e.Name())
		}
	}

	// Step 2: Filter the list if a search term was provided.
	var pkgsToShow []string
	if searchTerm != "" {
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, show everything.
		pkgsToShow = allPkgs
	}

	// Step 3: Format and collect the information (instead of printing).
	// The format is expected to be: "<pkgName> <version> [revision]"
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown 0" // Default for unreadable file

		if data, err := os.ReadFile(versionFile); err == nil {
			// Use the full content of the version file (e.g., "1.0 1")
			versionInfo = strings.TrimSpace(string(data))
		}

		// Write the package name and its full version info to the buffer
		// Example line: "fcron 3.4.0 1"
		outputBuilder.WriteString(fmt.Sprintf("%s %s\n", p, versionInfo))
	}

	// Return the collected data as a byte slice.
	return []byte(outputBuilder.String()), nil
}

// Struct to hold package information
type Package struct {
	Name              string
	InstalledVersion  string
	InstalledRevision string
	RepoVersion       string
	RepoRevision      string
}

// parsePackageList converts the output of getInstalledPackageOutput into a map of packages.

func parsePackageList(output []byte) (map[string]Package, error) {
	packages := make(map[string]Package)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		// Expecting at least 3 parts: <name> <version> <revision>
		if len(parts) < 3 {
			// Allow for packages with missing revision (assume 0 or 1 for simplicity)
			// For now, let's strictly require 3 fields for accurate comparison
			return nil, fmt.Errorf("invalid package list format (expected name, version, revision): %s", line)
		}

		pkgName := parts[0]
		pkgVersion := parts[1]
		pkgRevision := parts[2] // EXTRACT THE REVISION

		packages[pkgName] = Package{
			Name:              pkgName,
			InstalledVersion:  pkgVersion,
			InstalledRevision: pkgRevision, // Store the revision
		}
	}
	return packages, scanner.Err()
}

// checkDependencyBlocks checks if any installed package depends on a lower version
// of the package being updated. Returns the blocking package name if found, empty string otherwise.

func checkDependencyBlocks(pkgName string, newVersion string, installedPackages map[string]Package) string {
	// Iterate through all installed packages
	for installedPkgName := range installedPackages {
		// Skip the package itself
		if installedPkgName == pkgName {
			continue
		}

		// Use findPackageDir to locate the package metadata.
		// This ensures we prioritize repository metadata (NEW depends) over installed metadata.
		pkgDir, err := findPackageDir(installedPkgName)
		if err != nil {
			// If we can't find metadata, skip it.
			continue
		}

		// Parse the dependencies using the established helper
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			continue
		}

		for _, dep := range deps {
			if dep.Name != pkgName {
				continue
			}

			// If there's a version constraint, check if the new version violates it
			if dep.Op != "" && dep.Version != "" {
				// We check if the new version satisfies the constraint.
				// If not, it's blocked.
				if !versionSatisfies(newVersion, dep.Op, dep.Version) {
					return installedPkgName
				}
			}
		}
	}

	return ""
}

// checkForUpgrades is the main function for the upgrade logic.

func checkForUpgrades(_ context.Context, cfg *Config) error {
	colArrow.Print("-> ")
	colSuccess.Println("Checking for Package Upgrades")

	// 1. Get list of installed packages
	output, err := getInstalledPackageOutput("")
	if err != nil {
		return fmt.Errorf("could not retrieve installed packages: %w", err)
	}

	installedPackages, err := parsePackageList(output)
	if err != nil {
		return fmt.Errorf("failed to parse package list: %w", err)
	}

	var upgradeList []Package

	// 2. Compare installed version + revision vs. repo version + revision
	for name, pkg := range installedPackages {
		// Updated call to getRepoVersion to capture both version and revision
		repoVersion, repoRevision, err := getRepoVersion2(name)
		if err != nil {
			// Log error but continue to the next package
			debugf("Warning: Could not get repo version for %s: %v\n", name, err)
			continue
		}

		// Store repo information on the package struct
		pkg.RepoVersion = repoVersion
		pkg.RepoRevision = repoRevision

		// Comparison Logic: Check for a mismatch in either version OR revision
		isVersionMismatch := pkg.InstalledVersion != pkg.RepoVersion
		isRevisionMismatch := pkg.InstalledRevision != pkg.RepoRevision

		// NOTE: A more complex system would compare versions numerically,
		// but for simple string equality checks, this is sufficient:
		if isVersionMismatch || isRevisionMismatch {
			// Add to upgrade list
			upgradeList = append(upgradeList, pkg)
		}
	}

	// 2.5. Filter upgrade list based on dependencies and lock file
	lockedPackages := readLockFile()
	var filteredUpgradeList []Package
	var blockedPackages []string

	for _, pkg := range upgradeList {
		shouldSkip := false
		blockReason := ""

		// Check if blocked by installed package dependencies
		blockingPkg := checkDependencyBlocks(pkg.Name, pkg.RepoVersion, installedPackages)
		if blockingPkg != "" {
			shouldSkip = true
			blockReason = fmt.Sprintf("%s update blocked by %s", pkg.Name, blockingPkg)
		}

		// Check if locked in /etc/hokuto/hokuto.lock
		if lockedVersion, isLocked := lockedPackages[pkg.Name]; isLocked {
			// If locked version is lower than the new version, block the update
			if compareVersions(lockedVersion, pkg.RepoVersion) < 0 {
				shouldSkip = true
				if blockReason != "" {
					blockReason += " and lock file"
				} else {
					blockReason = fmt.Sprintf("%s update blocked by lock file (locked at %s)", pkg.Name, lockedVersion)
				}
			}
		}

		if shouldSkip {
			blockedPackages = append(blockedPackages, blockReason)
		} else {
			filteredUpgradeList = append(filteredUpgradeList, pkg)
		}
	}

	// Print blocked packages if any
	if len(blockedPackages) > 0 {
		cPrintf(colWarn, "\n--- %d Package(s) Blocked from Update ---\n", len(blockedPackages))
		for _, reason := range blockedPackages {
			cPrintf(colWarn, "  - %s\n", reason)
		}
	}

	// 3. Handle upgrade list
	if len(filteredUpgradeList) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No packages to upgrade.")
		return nil
	}

	cPrintf(colInfo, "\n--- %d Package(s) to Upgrade ---\n", len(filteredUpgradeList))
	var pkgNames []string
	for _, pkg := range filteredUpgradeList {
		// Print full version/revision information for clarity
		cPrintf(colInfo, "  - %s: %s %s -> %s %s\n",
			pkg.Name,
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
		pkgNames = append(pkgNames, pkg.Name)
	}

	// 4. Prompt user for upgrade
	if !askForConfirmation(colWarn, "Do you want to upgrade these packages?") {
		cPrintln(colNote, "Upgrade canceled by user.")
		return nil
	}

	// 5. Build order and dependency resolution for the updates
	userRequestedMap := make(map[string]bool)
	for _, pkg := range pkgNames {
		userRequestedMap[pkg] = true
	}

	plan, err := resolveBuildPlan(pkgNames, userRequestedMap, false)
	if err != nil {
		return fmt.Errorf("failed to resolve upgrade plan: %w", err)
	}
	// Use the ordered plan instead of the unordered list
	pkgNames = plan.Order

	// Apply user-specified update order from /etc/hokuto/hokuto.update
	pkgNames = applyUpdateOrder(pkgNames)

	// Launch background prefetcher for SUBSEQUENT packages.
	if len(pkgNames) > 1 {
		go prefetchSources(pkgNames[1:])
	}

	// --- REFACTORED BUILD AND INSTALL LOGIC ---
	var failedPackages []string
	var totalUpdateDuration time.Duration // Accumulator for the whole update process
	totalToUpdate := len(pkgNames)

	for i, pkgName := range pkgNames {
		colArrow.Print("\n-> ")
		if userRequestedMap[pkgName] {
			colSuccess.Printf("Executing update for:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, totalToUpdate)
		} else {
			colSuccess.Printf("Installing dependency:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, totalToUpdate)
		}

		// 0. Check for binary package first (Local Cache or Mirror)
		version, revision, err := getRepoVersion2(pkgName)
		if err != nil {
			color.Danger.Printf("Failed to get version/revision for %s: %v\n", pkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}

		outputPkgName := getOutputPackageName(pkgName, cfg)
		arch := GetSystemArch(cfg)
		variant := GetSystemVariantForPackage(cfg, pkgName)
		tarballName := StandardizeRemoteName(outputPkgName, version, revision, arch, variant)
		tarballPath := filepath.Join(BinDir, tarballName)

		foundBinary := false
		if _, err := os.Stat(tarballPath); err == nil {
			colArrow.Print("-> ")
			colSuccess.Printf("Using cached binary package: %s\n", tarballName)
			foundBinary = true
		} else if BinaryMirror != "" {
			if err := fetchBinaryPackage(pkgName, version, revision, cfg); err == nil {
				foundBinary = true
			} else {
				colArrow.Print("-> ")
				colSuccess.Println("Binary not found on mirror, building package locally")
			}
		}

		if foundBinary {
			isCriticalAtomic.Store(1)
			handlePreInstallUninstall(outputPkgName, cfg, RootExec)
			colArrow.Print("-> ")
			colSuccess.Printf("Installing")
			colNote.Printf(" %s\n", outputPkgName)
			if err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, false); err != nil {
				isCriticalAtomic.Store(0)
				color.Danger.Printf("Binary installation failed for %s: %v. Falling back to build.\n", outputPkgName, err)
			} else {
				isCriticalAtomic.Store(0)
				colArrow.Print("-> ")
				if userRequestedMap[pkgName] {
					colSuccess.Printf("Package")
					colNote.Printf(" %s ", outputPkgName)
					colSuccess.Printf("updated from binary successfully.\n")
				} else {
					colSuccess.Printf("Dependency")
					colNote.Printf(" %s ", outputPkgName)
					colSuccess.Printf("installed successfully.\n")
				}
				// If it was a requested update, add to world
				if userRequestedMap[pkgName] {
					addToWorld(pkgName)
				}
				continue // Successfully updated from binary, move to next package
			}
		}

		// A. Fallback: Directly call pkgBuild within the current process
		duration, err := pkgBuild(pkgName, cfg, UserExec, false, i+1, totalToUpdate)
		if err != nil {
			color.Danger.Printf("Build failed for %s: %v\n", pkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}
		totalUpdateDuration += duration

		// B. If build is successful, install the package
		isCriticalAtomic.Store(1)
		handlePreInstallUninstall(outputPkgName, cfg, RootExec)
		colArrow.Print("-> ")
		colSuccess.Printf("Installing")
		colNote.Printf(" %s\n", outputPkgName)
		if err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, false); err != nil {
			isCriticalAtomic.Store(0)
			color.Danger.Printf("Installation failed for %s: %v\n", outputPkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}
		isCriticalAtomic.Store(0)

		colArrow.Print("-> ")
		if userRequestedMap[pkgName] {
			colSuccess.Printf("Package")
			colNote.Printf(" %s ", outputPkgName)
			colSuccess.Printf("updated successfully.\n")
		} else {
			colSuccess.Printf("Dependency")
			colNote.Printf(" %s ", outputPkgName)
			colSuccess.Printf("installed successfully.\n")
		}

		// Add to World if it was a requested update
		if userRequestedMap[pkgName] {
			addToWorld(pkgName)
		}
	}

	if len(failedPackages) > 0 {
		return fmt.Errorf("some packages failed to update: %s", strings.Join(failedPackages, ", "))
	}
	colArrow.Print("-> ")
	colSuccess.Printf("System update completed successfully (%d/%d) Total Time: %s\n", totalToUpdate, totalToUpdate, totalUpdateDuration.Truncate(time.Second))
	return nil
}

// applyUpdateOrder reorders the package list based on /etc/hokuto/hokuto.update
func applyUpdateOrder(pkgNames []string) []string {
	updateOrderFile := filepath.Join(rootDir, "etc", "hokuto", "hokuto.update")
	data, err := os.ReadFile(updateOrderFile)
	if err != nil {
		// If file doesn't exist or can't be read, return original order
		return pkgNames
	}

	// Map to store the priority of packages.
	// We use the order of appearance in the file to determine priority.
	priority := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	rank := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Each line can contain one or more packages separated by spaces
		pkgs := strings.Fields(line)
		for _, p := range pkgs {
			// Only assign priority if not already assigned (first occurrence wins)
			if _, exists := priority[p]; !exists {
				priority[p] = rank
				rank++
			}
		}
	}

	if len(priority) == 0 {
		return pkgNames
	}

	// Create a copy to avoid modifying the input slice if that's preferred,
	// but here we are re-assigning it anyway.
	result := make([]string, len(pkgNames))
	copy(result, pkgNames)

	// Sort the packages. We use a stable sort to maintain the relative order
	// provided by the dependency resolver for packages not mentioned in the update file
	// or for which no relative order is specified.
	sort.SliceStable(result, func(i, j int) bool {
		p1, ok1 := priority[result[i]]
		p2, ok2 := priority[result[j]]

		// If both packages are in the update order file, use their relative order.
		if ok1 && ok2 {
			return p1 < p2
		}

		// If only one is in the file or neither is, we preserve their original
		// relative order from the topological sort to avoid breaking dependencies.
		return false
	})

	return result
}

// resolveMissingDeps recursively finds all missing dependencies for a package.
// It assumes cfg is passed in, as it's needed for the recursive call.

func isPackageInstalled(pkgName string) bool {
	// Use findInstalledSatisfying to support renamed packages (pkg-MAJOR)
	// If it's already a renamed name, findInstalledSatisfying will catch it.
	// If it's a base name, findInstalledSatisfying will find ANY version of it.
	return findInstalledSatisfying(pkgName, "", "") != ""
}
