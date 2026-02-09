package hokuto

// Code in this file was split out of main.go/update.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Cache for resolved alternative dependencies to avoid prompting multiple times
var alternativeDepCache = make(map[string]string)

// MovePackageToFront moves a specific package to the beginning of the list if it exists.
func MovePackageToFront(list []string, pkgName string) []string {
	foundIdx := -1
	for i, name := range list {
		if name == pkgName {
			foundIdx = i
			break
		}
	}
	if foundIdx == -1 {
		return list
	}
	// Move it to the front
	newList := make([]string, 0, len(list))
	newList = append(newList, list[foundIdx])
	newList = append(newList, list[:foundIdx]...)
	newList = append(newList, list[foundIdx+1:]...)
	return newList
}

// resolveBinaryDependencies recursively finds missing dependencies for a package.
// It populates 'plan' with the names of packages that need to be installed, in topological order.
// 'visited' tracks packages processed in this specific resolution pass to prevent cycles.
// cfg is used to check if multilib is enabled and resolve package names accordingly.

func resolveBinaryDependencies(pkgName string, visited map[string]bool, plan *[]string, force bool, yes bool, cfg *Config, remoteIndex []RepoEntry) error {
	// 1. Cycle detection
	if visited[pkgName] {
		return nil
	}
	visited[pkgName] = true

	// 2. Check if already installed
	// If the package is already installed, we don't need to do anything for it
	// or its dependencies (assuming installed packages are consistent).
	// Skip this check if force is enabled.
	if !force && checkPackageExactMatch(pkgName) {
		return nil
	}

	// 3. Remote Resolution (Priority if remoteIndex is provided)
	// If the user requested --remote (implied by non-empty remoteIndex), we prioritize
	// the remote package's dependencies over the local source definition.
	if len(remoteIndex) > 0 {
		// Check if package exists in remote index
		found := false
		lookupName := pkgName
		if idx := strings.Index(pkgName, "@"); idx != -1 {
			lookupName = pkgName[:idx]
		}

		for _, entry := range remoteIndex {
			if entry.Name == lookupName {
				found = true
				break
			}
		}

		if found {
			// Unmark visited to allow resolveRemoteDependencies to handle it
			delete(visited, pkgName)
			if err := resolveRemoteDependencies(pkgName, visited, plan, force, yes, cfg, remoteIndex); err != nil {
				return fmt.Errorf("remote resolution failed for %s: %w", pkgName, err)
			}
			return nil
		}
		// If not found in remote, fall through to local source check
	}

	// 4. Find source directory to read 'depends' file
	// We rely on the source repo metadata to know what the binary dependencies are.
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}
	pkgDir, err := findPackageDir(lookupName)
	if err != nil {
		return fmt.Errorf("cannot resolve dependencies for %s: source not found in HOKUTO_PATH", pkgName)
	}

	// 4. Parse dependencies
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return fmt.Errorf("failed to parse depends for %s: %w", pkgName, err)
	}

	// 5. Recurse for each dependency
	for _, dep := range deps {
		// Skip build-time only dependencies
		if dep.Make {
			continue
		}

		// FILTER: Ignore 32-bit dependencies if multilib is disabled
		if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
			continue
		}

		// Resolve alternative dependencies if present
		depName := dep.Name
		if len(dep.Alternatives) > 0 {
			resolved, err := resolveAlternativeDep(dep, yes)
			if err != nil {
				return fmt.Errorf("failed to resolve alternative dependency for %s: %w", pkgName, err)
			}
			depName = resolved
		}

		// Check if any installed package (including name-MAJOR) satisfies the dependency
		if !force {
			satisfying := findInstalledSatisfying(depName, dep.Op, dep.Version)
			if satisfying != "" {
				// Dependency satisfied by an installed package
				continue
			}
		}

		if err := resolveBinaryDependencies(depName, visited, plan, force, yes, cfg, remoteIndex); err != nil {
			return err
		}
	}

	// 6. Add current package to plan (Post-order traversal)
	// This ensures dependencies are listed before the package that needs them.
	*plan = append(*plan, pkgName)
	return nil
}

// newPackage creates a minimal package skeleton in $newPackageDir/<pkg>.
// - creates directory $newPackageDir/<pkg>
// - creates build, version, sources files with the right modes and contents

func resolveMissingDeps(pkgName string, processed map[string]bool, missing *[]string, forceBuild map[string]bool, cfg *Config) error {

	// 1. Mark this package as processed to prevent infinite recursion
	if processed[pkgName] {
		return nil
	}
	processed[pkgName] = true

	// --- 3. Find the Package Source Directory (pkgDir) ---
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return err
	}

	// --- 4. Parse the depends file (Now that we have the confirmed pkgDir) ---

	// Check if a depends file exists in the located pkgDir.
	dependencies, err := parseDependsFile(pkgDir)
	if err != nil {
		return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
	}

	// --- 5. Recursively check all dependencies ---
	for _, dep := range dependencies {
		// New filtering: skip cross dependencies if not cross-compiling
		if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
			continue
		}

		// New filtering: skip crossnative dependencies unless we are in a cross-native build
		// (Cross-native build = HOKUTO_CROSS_ARCH set AND HOKUTO_CROSS_SYSTEM unset/empty)
		if dep.CrossNative {
			if cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
				continue // Skip on native
			}
			if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
				continue // Skip on cross-system (toolchain) build
			}
		}

		// FILTER: When in cross-mode, ignore dependencies that don't match the target architecture
		if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
			normalizedArch := cfg.Values["HOKUTO_CROSS_ARCH"]
			if normalizedArch == "arm64" {
				normalizedArch = "aarch64"
			}
			prefix := normalizedArch + "-"
			if !strings.HasPrefix(dep.Name, prefix) {
				continue
			}
		}

		depName := dep.Name

		// Resolve alternative dependencies if present
		if len(dep.Alternatives) > 0 {
			resolved, err := resolveAlternativeDep(dep, false) // resolveMissingDeps doesn't have yes flag, use false
			if err != nil {
				return fmt.Errorf("failed to resolve alternative dependency: %w", err)
			}
			depName = resolved
		}

		// Safety check: a package cannot depend on itself.
		if depName == pkgName {
			continue
		}

		// Skip Make dependencies if the package is installed and not forced to rebuild
		if dep.Make && isPackageInstalled(pkgName) && !forceBuild[pkgName] {
			continue
		}

		// FILTER: Ignore 32-bit dependencies if multilib is disabled
		if !EnableMultilib && strings.HasSuffix(depName, "-32") {
			continue
		}

		// CHECK VERSION CONSTRAINTS & FETCH IF NEEDED
		if dep.Op != "" && dep.Version != "" {
			// 1. Check if any satisfying package is ALREADY INSTALLED (including renamed ones)
			satisfyingPkg := findInstalledSatisfying(depName, dep.Op, dep.Version)
			if satisfyingPkg != "" {
				// Great, a satisfying version is already installed (maybe it's depName-MAJOR)
				depName = satisfyingPkg
			} else {
				// 2. Not installed or doesn't satisfy. Check the current repository version.
				repoVer, _, err := getRepoVersion2(depName)
				if err == nil {
					if !versionSatisfies(repoVer, dep.Op, dep.Version) {
						// Repo version doesn't satisfy. Fetch from git history.
						renamed, err := prepareVersionedPackage(fmt.Sprintf("%s@%s%s", depName, dep.Op, dep.Version))
						if err != nil {
							return fmt.Errorf("failed to prepare versioned package %s@%s%s: %w", depName, dep.Op, dep.Version, err)
						}
						depName = renamed
					}
				}
			}
		}

		if err := resolveMissingDeps(depName, processed, missing, forceBuild, cfg); err != nil {
			// Propagate the error up
			return err
		}
	}

	// --- 6. Add the missing package to the list ---
	// Only *after* checking all dependencies, we check if the
	// package itself is installed. If it is, we're done.
	if isPackageInstalled(pkgName) {
		return nil
	}

	// If it's not installed, *then* we add it to the list.
	*missing = append(*missing, pkgName)

	return nil
}

// isPackageInstalled checks if a package is currently installed.
// This is the function called by the dependency resolver (resolveMissingDeps).

func parseDependsFile(pkgDir string) ([]DepSpec, error) {
	dependsPath := filepath.Join(pkgDir, "depends")
	content, err := os.ReadFile(dependsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DepSpec{}, nil // No depends file is valid.
		}
		return nil, fmt.Errorf("failed to read depends file: %w", err)
	}
	return parseDependsData(content)
}

func resolveRemoteDependencies(pkgName string, visited map[string]bool, plan *[]string, force bool, yes bool, cfg *Config, remoteIndex []RepoEntry) error {
	// 1. Cycle detection
	if visited[pkgName] {
		return nil
	}
	visited[pkgName] = true

	// 2. Check installed (skip if force)
	if !force && checkPackageExactMatch(pkgName) {
		return nil
	}

	// 3. Find in remote index
	targetVersion := ""
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
		targetVersion = pkgName[idx+1:]
	}

	var entry RepoEntry
	found := false
	arch := GetSystemArchForPackage(cfg, lookupName)
	preferredVariant := GetSystemVariantForPackage(cfg, lookupName)

	var bestMatch *RepoEntry
	for i := range remoteIndex {
		e := &remoteIndex[i]
		if e.Name == lookupName && e.Arch == arch && e.Variant == preferredVariant {
			if targetVersion != "" {
				if e.Version == targetVersion {
					entry = *e
					found = true
					break
				}
				continue
			}

			if bestMatch == nil || isNewer(*e, *bestMatch) {
				bestMatch = e
			}
		}
	}

	if !found && bestMatch != nil {
		entry = *bestMatch
		found = true
	}

	// FALLBACK: Try generic if preferred variant not found
	if !found && !strings.Contains(preferredVariant, "generic") {
		fallbackVariant := "generic"
		if strings.HasPrefix(preferredVariant, "multi-") {
			fallbackVariant = "multi-generic"
		}

		for i := range remoteIndex {
			e := &remoteIndex[i]
			if e.Name == lookupName && e.Arch == arch && e.Variant == fallbackVariant {
				if targetVersion != "" {
					if e.Version == targetVersion {
						entry = *e
						found = true
						break
					}
					continue
				}

				if bestMatch == nil || isNewer(*e, *bestMatch) {
					bestMatch = e
				}
			}
		}
		if !found && bestMatch != nil {
			entry = *bestMatch
			found = true
		}
	}

	// FALLBACK 2: If we are looking for non-multi (e.g. optimized) but only multi- exists, try that.
	// This happens if local system is non-multilib but repo only has multilib package (which is compatible).
	if !found && !strings.HasPrefix(preferredVariant, "multi-") {
		// Try multi- + preferredVariant (e.g. "optimized" -> "multi-optimized")
		fallbackVariant := "multi-" + preferredVariant

		bestMatch = nil // Reset bestMatch for this new search
		for i := range remoteIndex {
			e := &remoteIndex[i]
			if e.Name == lookupName && e.Arch == arch && e.Variant == fallbackVariant {
				if targetVersion != "" {
					if e.Version == targetVersion {
						entry = *e
						found = true
						break
					}
					continue
				}

				if bestMatch == nil || isNewer(*e, *bestMatch) {
					bestMatch = e
				}
			}
		}
		if !found && bestMatch != nil {
			entry = *bestMatch
			found = true
		}

		// Also try multi-generic if multi-optimized failed
		if !found {
			fallbackVariant = "multi-generic"
			bestMatch = nil
			for i := range remoteIndex {
				e := &remoteIndex[i]
				if e.Name == lookupName && e.Arch == arch && e.Variant == fallbackVariant {
					if targetVersion != "" {
						if e.Version == targetVersion {
							entry = *e
							found = true
							break
						}
						continue
					}

					if bestMatch == nil || isNewer(*e, *bestMatch) {
						bestMatch = e
					}
				}
			}
			if !found && bestMatch != nil {
				entry = *bestMatch
				found = true
			}
		}
	}

	if !found {
		// If not in remote index, we can't do anything
		if targetVersion != "" {
			return fmt.Errorf("package %s@%s not found in remote index", lookupName, targetVersion)
		}
		return fmt.Errorf("package %s not found in remote index", pkgName)
	}

	var deps []DepSpec
	if len(entry.Depends) > 0 {
		// Optimization: Use pre-resolved dependencies from index
		for _, d := range entry.Depends {
			deps = append(deps, DepSpec{Name: d})
		}
	} else {
		// Fallback: Fetch binary package to read depends (older index or missing info)
		if err := fetchBinaryPackage(pkgName, entry.Version, entry.Revision, cfg, false, entry.B3Sum, false); err != nil {
			return fmt.Errorf("failed to fetch remote package for dependency resolution (%s): %v", pkgName, err)
		}

		arch := GetSystemArch(cfg)
		variant := GetSystemVariantForPackage(cfg, pkgName)
		tarballName := StandardizeRemoteName(pkgName, entry.Version, entry.Revision, arch, variant)
		tarballPath := filepath.Join(BinDir, tarballName)

		// 5. Scan metadata (pkginfo and depends)
		_, entryDeps, err := scanTarballMetadata(tarballPath)
		if err != nil {
			return fmt.Errorf("failed to scan metadata from %s: %w", tarballName, err)
		}

		for _, d := range entryDeps {
			deps = append(deps, DepSpec{Name: d})
		}
	}

	// 7. Recurse
	for _, dep := range deps {
		// Skip build-time only dependencies (Make=true)
		if dep.Make {
			continue
		}
		if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
			continue
		}

		depName := dep.Name
		if len(dep.Alternatives) > 0 {
			resolved, err := resolveAlternativeDep(dep, yes)
			if err != nil {
				return fmt.Errorf("failed to resolve alternative dependency for %s: %w", pkgName, err)
			}
			depName = resolved
		}

		if !force {
			if findInstalledSatisfying(depName, dep.Op, dep.Version) != "" {
				continue
			}
		}

		// Try to resolve using normal logic (local source preferred), fallback to remote is built-in
		if err := resolveBinaryDependencies(depName, visited, plan, force, yes, cfg, remoteIndex); err != nil {
			return err
		}
	}

	// 8. Add to plan
	*plan = append(*plan, pkgName)
	return nil
}

// resolveAlternativeDep resolves an alternative dependency by checking which alternatives are available
// and prompting the user to choose. Returns the chosen package name.
// Uses a cache to avoid prompting multiple times for the same alternative set.
func resolveAlternativeDep(dep DepSpec, yes bool) (string, error) {
	if len(dep.Alternatives) < 2 {
		// Not an alternative dependency, return the name as-is
		return dep.Name, nil
	}

	// Create a cache key from the sorted alternatives
	// This ensures the same set of alternatives always maps to the same key
	sortedAlts := make([]string, len(dep.Alternatives))
	copy(sortedAlts, dep.Alternatives)
	sort.Strings(sortedAlts)
	cacheKey := strings.Join(sortedAlts, "|")

	// Check cache first
	if cached, ok := alternativeDepCache[cacheKey]; ok {
		// Verify the cached choice is still available
		if isPackageInstalled(cached) {
			return cached, nil
		}
		// Check if can be found in repos
		if _, err := findPackageDir(cached); err == nil {
			return cached, nil
		}
		// Cached choice is no longer available, remove from cache and continue
		delete(alternativeDepCache, cacheKey)
	}

	// Check which alternatives are available (installed or can be found in repos)
	// Separate installed from available in repos for priority handling
	var installed []string
	var available []string
	for _, altName := range dep.Alternatives {
		// FILTER: Ignore 32-bit dependencies if multilib is disabled
		if !EnableMultilib && strings.HasSuffix(altName, "-32") {
			continue
		}

		// Check if installed first (prioritize installed)
		// Alternatives currently don't support version constraints, but we check if ANY version is installed
		if sat := findInstalledSatisfying(altName, "", ""); sat != "" {
			installed = append(installed, sat)
			available = append(available, sat)
			continue
		}
		// Check if can be found in repos
		if _, err := findPackageDir(altName); err == nil {
			available = append(available, altName)
		}
	}

	if len(available) == 0 {
		return "", fmt.Errorf("none of the alternative dependencies are available: %s", strings.Join(dep.Alternatives, ", "))
	}

	// If any are installed, automatically use the first installed one
	if len(installed) > 0 {
		alternativeDepCache[cacheKey] = installed[0]
		return installed[0], nil
	}

	// If only one is available (and not installed), use it automatically and cache it
	if len(available) == 1 {
		alternativeDepCache[cacheKey] = available[0]
		return available[0], nil
	}

	// Multiple alternatives available (none installed) - prompt user
	if yes {
		// In --yes mode, use the first available alternative and cache it
		alternativeDepCache[cacheKey] = available[0]
		return available[0], nil
	}

	// Prompt user to choose
	fmt.Printf("\nPackage requires one of the following dependencies:\n")
	for i, alt := range available {
		status := ""
		if isPackageInstalled(alt) {
			status = " (installed)"
		}
		fmt.Printf("  %d) %s%s\n", i+1, alt, status)
	}
	fmt.Printf("Choose dependency [1-%d] (default: 1): ", len(available))

	stdinReader := bufio.NewReader(os.Stdin)
	response, err := stdinReader.ReadString('\n')
	if err != nil {
		// Default to first option on read error
		alternativeDepCache[cacheKey] = available[0]
		return available[0], nil
	}

	response = strings.TrimSpace(response)
	if response == "" {
		// Default to first option
		alternativeDepCache[cacheKey] = available[0]
		return available[0], nil
	}

	choice, err := strconv.Atoi(response)
	if err != nil || choice < 1 || choice > len(available) {
		// Invalid choice, default to first option
		alternativeDepCache[cacheKey] = available[0]
		return available[0], nil
	}

	chosen := available[choice-1]
	alternativeDepCache[cacheKey] = chosen
	return chosen, nil
}

// parseDepToken parses tokens like "pkg", "pkg<=1.2.3 optional", "pkg rebuild" and returns name, op, version, and flags.

func parseDepToken(token string) (name string, op string, ver string, optional bool, rebuild bool, makeDep bool, cross bool, crossNative bool) {
	// Split by whitespace to separate package spec from flags
	parts := strings.Fields(token)
	if len(parts) == 0 {
		return "", "", "", false, false, false, false, false
	}

	pkgSpec := parts[0]
	// Check for flags in remaining parts
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "optional":
			optional = true
		case "rebuild":
			rebuild = true
		case "make":
			makeDep = true
		case "cross":
			cross = true
		case "crossnative":
			crossNative = true
			cross = true // Implies cross because it's only for cross-compilation scenarios
		}
	}

	// Parse version constraint from package spec
	ops := []string{"<=", ">=", "==", "<", ">"}
	for _, op := range ops {
		if idx := strings.Index(pkgSpec, op); idx != -1 {
			name := pkgSpec[:idx]
			ver := pkgSpec[idx+len(op):]
			return strings.TrimSpace(name), op, strings.TrimSpace(ver), optional, rebuild, makeDep || cross, cross, crossNative
		}
	}
	return pkgSpec, "", "", optional, rebuild, makeDep || cross, cross, crossNative
}

// BuildPlan represents the complete build plan with proper ordering

type BuildPlan struct {
	Order             []string            // Final build order
	SkippedPackages   map[string]string   // pkgName -> reason for skip
	RebuildPackages   map[string]bool     // Packages marked for rebuild
	PostRebuilds      map[string][]string // Packages needing a rebuild for optional deps
	PostBuildRebuilds map[string][]string // Stores post-build actions
	NoDeps            bool                // Skip dependency checking during execution
}

// resolveBuildPlan creates a dynamic, context-aware build plan.
// It correctly handles resolvable circular dependencies caused by optional dependencies.
// binaryAvailable is a map of package names that have a pre-built binary available (locally or remotely).
// If a package is in this map, its Make dependencies will be treated as if it were already installed.

func resolveBuildPlan(targetPackages []string, userRequestedPackages map[string]bool, withRebuilds bool, cfg *Config, binaryAvailable map[string]bool) (*BuildPlan, error) {
	plan := &BuildPlan{
		Order:             []string{},
		SkippedPackages:   make(map[string]string),
		RebuildPackages:   make(map[string]bool),
		PostRebuilds:      make(map[string][]string),
		PostBuildRebuilds: make(map[string][]string),
	}

	processed := make(map[string]bool)
	inProgress := make(map[string]bool)
	alreadyInOrder := make(map[string]bool)

	var processPkg func(pkgName string) error
	processPkg = func(pkgName string) error {
		// --- SMART CYCLE DETECTION ---
		// If we are already in the middle of processing this package, just return.
		// This breaks the recursive loop without erroring, allowing the original
		// call to eventually resolve the package in the correct order.
		if inProgress[pkgName] {
			return nil
		}
		if processed[pkgName] {
			return nil
		}

		inProgress[pkgName] = true
		defer func() { delete(inProgress, pkgName) }()

		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			return fmt.Errorf("package source not found for '%s': %w", pkgName, err)
		}

		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
		}

		// Process all dependencies recursively first.
		for _, dep := range deps {
			// New filtering: skip cross dependencies if not cross-compiling
			if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
				continue
			}

			// New filtering: skip crossnative dependencies unless we are in a cross-native build
			if dep.CrossNative {
				if cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
					continue
				}
				if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
					continue
				}
			}

			// FILTER: When in cross-mode, ignore dependencies that don't match the target architecture
			if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
				normalizedArch := cfg.Values["HOKUTO_CROSS_ARCH"]
				if normalizedArch == "arm64" {
					normalizedArch = "aarch64"
				}
				prefix := normalizedArch + "-"
				if !strings.HasPrefix(dep.Name, prefix) {
					continue
				}
			}

			depName := dep.Name

			// Resolve alternative dependencies if present
			if len(dep.Alternatives) > 0 {
				resolved, err := resolveAlternativeDep(dep, false) // Use false for build (no yes flag available)
				if err != nil {
					return fmt.Errorf("failed to resolve alternative dependency for %s: %w", pkgName, err)
				}
				depName = resolved
			}
			if depName == pkgName {
				continue
			}

			// Skip Make dependencies if:
			// 1. The package is already installed, OR
			// 2. A binary is available (locally or remotely) which we intend to use.
			// AND it's not a forced rebuild.
			hasBinary := binaryAvailable != nil && binaryAvailable[pkgName]
			isInstalled := isPackageInstalled(pkgName)

			if dep.Make {
				skip := false
				// Case 1: Binary Available (e.g. from update check).
				// We skip make deps even if userRequestedPackages is true (because update list counts as user requested),
				// unless specifically forced to rebuild (which update generally doesn't set).
				if hasBinary && !plan.RebuildPackages[pkgName] {
					skip = true
				}
				// Case 2: Installed and NOT requested by user.
				// If installed but user requested it (e.g. "build foo"), we do NOT skip make deps because we are rebuilding.
				if isInstalled && !userRequestedPackages[pkgName] && !plan.RebuildPackages[pkgName] {
					skip = true
				}

				if skip {
					continue
				}
			}
			if depName == pkgName {
				continue
			}

			// FILTER: Ignore 32-bit dependencies if multilib is disabled
			if !EnableMultilib && strings.HasSuffix(depName, "-32") {
				continue
			}

			// CHECK VERSION CONSTRAINTS & FETCH IF NEEDED
			// If the dependency has a specific version constraint (e.g. == 0.14.0),
			// and the current repo version doesn't match, we try to fetch it from history.
			if dep.Op != "" && dep.Version != "" {
				// 1. Check if any satisfying package is ALREADY INSTALLED (including renamed ones)
				satisfyingPkg := findInstalledSatisfying(depName, dep.Op, dep.Version)
				if satisfyingPkg != "" {
					// Great, a satisfying version is already installed (maybe it's depName-MAJOR)
					depName = satisfyingPkg
				} else {
					// 2. Not installed. Check the current repository version.
					// We now support all standard operators (==, <=, >=, <, >)
					repoVer, _, err := getRepoVersion2(depName)
					if err == nil {
						if !versionSatisfies(repoVer, dep.Op, dep.Version) {
							// The repo has a different version / doesn't satisfy constraint.
							// Attempt to fetch a satisfying version from git history.
							colArrow.Print("-> ")
							colSuccess.Printf("Repo version %s of %s does not match constraint %s%s. Fetching from git history\n", repoVer, depName, dep.Op, dep.Version)

							// Pass the full constraint (e.g. "pkg@<=5.0.0") to prepareVersionedPackage
							renamed, err := prepareVersionedPackage(fmt.Sprintf("%s@%s%s", depName, dep.Op, dep.Version))
							if err != nil {
								return fmt.Errorf("failed to prepare versioned package %s@%s%s: %w", depName, dep.Op, dep.Version, err)
							}
							depName = renamed
						}
					}
				}
			}

			// Conditionally handle the 'rebuild' flag
			if withRebuilds && dep.Rebuild {
				// This is a post-build action. Add it to the map for the current package.
				plan.PostBuildRebuilds[pkgName] = append(plan.PostBuildRebuilds[pkgName], depName)
				// Mark this package for rebuild so its make dependencies are processed
				plan.RebuildPackages[depName] = true

			} else if dep.Optional {
				if !isPackageInstalled(depName) {
					// Record that pkgName needs an inline rebuild because an optional dep is missing.
					plan.PostRebuilds[pkgName] = append(plan.PostRebuilds[pkgName], depName)
				}
			}

			// CRITICAL: Always process the dependency to ensure it gets into the build order at least once.
			// This covers normal deps, optional deps, and 'rebuild' deps (when withRebuilds is off).
			if err := processPkg(depName); err != nil {
				return err
			}
		}

		// Now, decide if the package itself needs to be in the build order.
		shouldBuild := false
		if userRequestedPackages[pkgName] {
			shouldBuild = true // User explicitly asked for it.
		} else if plan.RebuildPackages[pkgName] {
			shouldBuild = true // Another package marked it for rebuild.
		} else if !isPackageInstalled(pkgName) {
			shouldBuild = true // It's a dependency that isn't installed.
		}

		if shouldBuild {
			if !alreadyInOrder[pkgName] {
				plan.Order = append(plan.Order, pkgName)
				alreadyInOrder[pkgName] = true
			}
		}

		processed[pkgName] = true
		return nil
	}

	// Start the process for all initial targets.
	for _, target := range targetPackages {
		if err := processPkg(target); err != nil {
			return nil, err
		}
	}

	// CRITICAL: Always prioritize sauzeros-base if it's in the build plan
	plan.Order = MovePackageToFront(plan.Order, "sauzeros-base")

	return plan, nil
}

// findPackageDir locates the package source directory

func versionSatisfies(installed, op, ref string) bool {
	cmp := compareVersions(installed, ref)
	switch op {
	case "==":
		return cmp == 0
	case "<=":
		return cmp <= 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case ">":
		return cmp > 0
	default:
		return true
	}
}

// compareVersions compares two version strings split by dots. Numeric segments are compared numerically; non-numeric fall back to lexicographic.
// Returns -1 if a<b, 0 if equal, 1 if a>b.

func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(as) {
			av = as[i]
		} else {
			av = "0"
		}
		if i < len(bs) {
			bv = bs[i]
		} else {
			bv = "0"
		}

		// Try numeric compare
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if ai < bi {
				return -1
			}
			if ai > bi {
				return 1
			}
			continue
		}
		// Fallback string compare
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// getPackageDependenciesForward recursively collects all dependencies for a package
// in forward order (as they appear in depends files).
// Duplicates are only allowed for "gcc" - all other packages are added once.
// This is used with the --alldeps flag to rebuild everything including duplicates.

func getPackageDependenciesForward(pkgName string) ([]string, error) {
	var result []string
	seen := make(map[string]bool)       // Track non-gcc packages to avoid duplicates
	inProgress := make(map[string]bool) // Track packages currently being processed to prevent infinite recursion

	// Helper function for recursive traversal
	var collectDeps func(string) error
	collectDeps = func(currentPkg string) error {
		// Check if we're already processing this package (prevents infinite recursion)
		if inProgress[currentPkg] {
			return nil
		}

		// Mark as in-progress
		inProgress[currentPkg] = true
		defer func() {
			// Unmark when done (allows gcc to be processed multiple times in different branches)
			delete(inProgress, currentPkg)
		}()
		// --- Find the Package Source Directory (pkgDir) ---
		paths := strings.Split(repoPaths, ":")
		var pkgDir string
		var found bool

		for _, repoPath := range paths {
			repoPath = strings.TrimSpace(repoPath)
			if repoPath == "" {
				continue
			}
			currentPkgDir := filepath.Join(repoPath, currentPkg)
			if info, err := os.Stat(currentPkgDir); err == nil && info.IsDir() {
				pkgDir = currentPkgDir
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("package source not found in any repository path for %s", currentPkg)
		}

		// --- Parse the depends file ---
		dependencies, err := parseDependsFile(pkgDir)
		if err != nil {
			return fmt.Errorf("failed to parse dependencies for %s: %w", currentPkg, err)
		}

		// --- Recursively collect dependencies in forward order ---
		for _, dep := range dependencies {
			depName := dep.Name

			// Resolve alternative dependencies if present
			if len(dep.Alternatives) > 0 {
				resolved, err := resolveAlternativeDep(dep, false) // Use false for build (no yes flag available)
				if err != nil {
					return fmt.Errorf("failed to resolve alternative dependency: %w", err)
				}
				depName = resolved
			}

			// Safety check: a package cannot depend on itself
			if depName == currentPkg {
				continue
			}

			// FILTER: Ignore 32-bit dependencies if multilib is disabled
			if !EnableMultilib && strings.HasSuffix(depName, "-32") {
				continue
			}

			// Version constraint checking (same as resolveMissingDeps)
			if dep.Op != "" && isPackageInstalled(depName) {
				if installedVer, ok := getInstalledVersion(depName); ok {
					if !versionSatisfies(installedVer, dep.Op, dep.Version) {
						switch dep.Op {
						case "<=":
							return fmt.Errorf("error %s version %s or lower required for build (installed %s)", depName, dep.Version, installedVer)
						case ">=":
							return fmt.Errorf("error %s version %s or higher required for build (installed %s)", depName, dep.Version, installedVer)
						case "==":
							return fmt.Errorf("error %s version exactly %s required for build (installed %s)", depName, dep.Version, installedVer)
						case "<":
							return fmt.Errorf("error %s version lower than %s required for build (installed %s)", depName, dep.Version, installedVer)
						case ">":
							return fmt.Errorf("error %s version greater than %s required for build (installed %s)", depName, dep.Version, installedVer)
						default:
							return fmt.Errorf("error %s version constraint %s%s not satisfied (installed %s)", depName, dep.Op, dep.Version, installedVer)
						}
					}
				}
			}

			// Recursively collect dependencies of this dependency
			if err := collectDeps(depName); err != nil {
				return err
			}

			// Add the dependency itself AFTER its dependencies (forward order)
			// Special handling: gcc can be added multiple times, all others only once
			if depName == "gcc" {
				// Always add gcc, allowing duplicates
				result = append(result, depName)
			} else {
				// For non-gcc packages, only add if not seen before
				if !seen[depName] {
					seen[depName] = true
					result = append(result, depName)
				}
			}
		}

		return nil
	}

	// Start the recursive collection
	if err := collectDeps(pkgName); err != nil {
		return nil, err
	}

	// CRITICAL: Always prioritize sauzeros-base if it's in the dependency list
	result = MovePackageToFront(result, "sauzeros-base")

	return result, nil
}

// getInstalledDeps returns the list of dependencies for an *installed* package
// by reading the /var/db/hokuto/installed/<pkg>/depends file.
func getInstalledDeps(pkgName string) ([]string, error) {
	depFile := filepath.Join(Installed, pkgName, "depends")
	data, err := os.ReadFile(depFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var deps []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Parse "pkgname>=1.0" -> "pkgname"
		name, _, _, _, _, _, _, _ := parseDepToken(line)
		if name != "" && name != pkgName {
			// FILTER: Ignore 32-bit dependencies if multilib is disabled
			if !EnableMultilib && strings.HasSuffix(name, "-32") {
				continue
			}
			deps = append(deps, name)
		}
	}
	return deps, nil
}

type DepSpec struct {
	Name         string
	Op           string // one of: "<=", ">=", "==", "<", ">", or empty for no constraint
	Version      string
	Optional     bool
	Rebuild      bool
	Make         bool     // True if dependency is only needed at build time
	Cross        bool     // True if dependency is only for cross-compilation
	CrossNative  bool     // True if dependency is only for cross-compilation AND NOT cross-system
	Alternatives []string // List of alternative package names (e.g., ["rust", "rustup"] for "rust | rustup")
}

func ShowPackageDependencies(pkgName string, reverse bool, cfg *Config) error {
	if reverse {
		return showReverseDependencies(pkgName)
	}
	return showForwardDependencies(pkgName)
}

func showForwardDependencies(pkgName string) error {
	// Try installed first
	dependsPath := filepath.Join(Installed, pkgName, "depends")
	data, err := os.ReadFile(dependsPath)
	if err != nil {
		// Try repo
		pkgDir, findErr := findPackageDir(pkgName)
		if findErr != nil {
			return fmt.Errorf("package %s not found (installed or in repos)", pkgName)
		}
		dependsPath = filepath.Join(pkgDir, "depends")
		data, err = os.ReadFile(dependsPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Package %s has no dependencies.\n", pkgName)
				return nil
			}
			return fmt.Errorf("failed to read depends file: %v", err)
		}
	}

	if len(data) == 0 {
		fmt.Printf("Package %s has no dependencies.\n", pkgName)
		return nil
	}
	colArrow.Printf("-> ")
	colSuccess.Printf("Dependencies for %s:\n", pkgName)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		colArrow.Printf("-> ")
		colNote.Println(line)
	}
	return nil
}

func showReverseDependencies(targetPkg string) error {
	foundIn := make(map[string]bool)

	// Scan installed
	installedEntries, _ := os.ReadDir(Installed)
	for _, entry := range installedEntries {
		if !entry.IsDir() {
			continue
		}
		dependsPath := filepath.Join(Installed, entry.Name(), "depends")
		if containsDep(dependsPath, targetPkg) {
			foundIn[entry.Name()] = true
		}
	}

	// Scan repos
	paths := strings.Split(repoPaths, ":")
	for _, repo := range paths {
		repoEntries, _ := os.ReadDir(repo)
		for _, entry := range repoEntries {
			if !entry.IsDir() {
				continue
			}
			dependsPath := filepath.Join(repo, entry.Name(), "depends")
			if containsDep(dependsPath, targetPkg) {
				foundIn[entry.Name()] = true
			}
		}
	}

	if len(foundIn) == 0 {
		fmt.Printf("No reverse dependencies found for %s.\n", targetPkg)
		return nil
	}

	colArrow.Printf("-> ")
	colSuccess.Printf("Packages depending on %s:\n", targetPkg)
	var sorted []string
	for k := range foundIn {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, p := range sorted {
		colArrow.Printf("-> ")
		colNote.Println(p)
	}
	return nil
}

func containsDep(dependsPath, targetPkg string) bool {
	content, err := os.ReadFile(dependsPath)
	if err != nil {
		return false
	}
	deps, err := parseDependsData(content)
	if err != nil {
		return false
	}
	for _, dep := range deps {
		if dep.Name == targetPkg {
			return true
		}
		for _, alt := range dep.Alternatives {
			if alt == targetPkg {
				return true
			}
		}
	}
	return false
}
