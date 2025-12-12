package hokuto

// Code in this file was split out of main.go/update.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func resolveBinaryDependencies(pkgName string, visited map[string]bool, plan *[]string) error {
	// 1. Cycle detection
	if visited[pkgName] {
		return nil
	}
	visited[pkgName] = true

	// 2. Check if already installed
	// If the package is already installed, we don't need to do anything for it
	// or its dependencies (assuming installed packages are consistent).
	if checkPackageExactMatch(pkgName) {
		return nil
	}

	// 3. Find source directory to read 'depends' file
	// We rely on the source repo metadata to know what the binary dependencies are.
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		// If we can't find the source, we can't resolve dependencies.
		// However, for 'install', maybe the user just has a binary and no source.
		// In that case, we can't auto-resolve. We return an error.
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

		if err := resolveBinaryDependencies(dep.Name, visited, plan); err != nil {
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

func resolveMissingDeps(pkgName string, processed map[string]bool, missing *[]string) error {

	// 1. Mark this package as processed to prevent infinite recursion
	if processed[pkgName] {
		return nil
	}
	processed[pkgName] = true

	// 2. [OLD POSITION - REMOVED]
	// The check for isPackageInstalled(pkgName) was here.
	// It must be moved to the end.

	// --- 3. Find the Package Source Directory (pkgDir) ---
	// Assuming repoPaths comes from cfg.RepoPaths or a global var,
	// and we must find the package in one of them.

	paths := strings.Split(repoPaths, ":") // Use cfg if available
	var pkgDir string
	var found bool

	for _, repoPath := range paths {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}

		currentPkgDir := filepath.Join(repoPath, pkgName)

		// Check if the package source exists at this location.
		if info, err := os.Stat(currentPkgDir); err == nil && info.IsDir() {
			pkgDir = currentPkgDir
			found = true
			break // Found it! Stop checking other repoPaths.
		}
	}

	if !found {
		// If we checked all repoPaths and didn't find the source, return an error.
		return fmt.Errorf("package source not found in any repository path for %s", pkgName)
	}

	// --- 4. Parse the depends file (Now that we have the confirmed pkgDir) ---

	// Check if a depends file exists in the located pkgDir.
	dependencies, err := parseDependsFile(pkgDir)
	if err != nil {
		return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
	}

	// --- 5. Recursively check all dependencies ---
	// This loop will now run even for installed packages, allowing the
	// version check to happen.
	for _, dep := range dependencies {
		depName := dep.Name
		// Safety check: a package cannot depend on itself.
		if depName == pkgName {
			continue
		}

		// If a version constraint exists and the dependency is already installed,
		// enforce the constraint before proceeding.
		if dep.Op != "" && isPackageInstalled(depName) {
			if installedVer, ok := getInstalledVersion(depName); ok {
				if !versionSatisfies(installedVer, dep.Op, dep.Version) {
					// Build an error message tailored to the operator
					switch dep.Op {
					case "<=":
						return fmt.Errorf("error %s version %s or lower required for build (installed %s)", depName, dep.Version, installedVer)
					case ">=":
						return fmt.Errorf("error %s version %s or higher required for build (installed %s)", depName, dep.Version, installedVer)
					case "==":
						// This case will now be triggered for python-sip
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

		if err := resolveMissingDeps(depName, processed, missing); err != nil {
			// Propagate the error up
			return err
		}
	}

	// --- 6. Add the missing package to the list ---
	// [NEW POSITION]
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

	var dependencies []DepSpec
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Correctly capture all return values from the updated token parser.
		name, op, ver, optional, rebuild, makeDep := parseDepToken(line)
		if name != "" {
			dependencies = append(dependencies, DepSpec{
				Name:     name,
				Op:       op,
				Version:  ver,
				Optional: optional, // Correctly assign the 'optional' flag.
				Rebuild:  rebuild,
				Make:     makeDep,
			})
		}
	}

	return dependencies, nil
}

// parseDepToken parses tokens like "pkg", "pkg<=1.2.3 optional", "pkg rebuild" and returns name, op, version, and flags.

func parseDepToken(token string) (string, string, string, bool, bool, bool) {
	// Split by whitespace to separate package spec from flags
	parts := strings.Fields(token)
	if len(parts) == 0 {
		return "", "", "", false, false, false
	}

	pkgSpec := parts[0]
	var optional, rebuild, makeDep bool

	// Check for flags in remaining parts
	for i := 1; i < len(parts); i++ {
		switch parts[i] {
		case "optional":
			optional = true
		case "rebuild":
			rebuild = true
		case "make":
			makeDep = true
		}
	}

	// Parse version constraint from package spec
	ops := []string{"<=", ">=", "==", "<", ">"}
	for _, op := range ops {
		if idx := strings.Index(pkgSpec, op); idx != -1 {
			name := pkgSpec[:idx]
			ver := pkgSpec[idx+len(op):]
			return strings.TrimSpace(name), op, strings.TrimSpace(ver), optional, rebuild, makeDep
		}
	}
	return pkgSpec, "", "", optional, rebuild, makeDep
}

// BuildPlan represents the complete build plan with proper ordering

type BuildPlan struct {
	Order             []string            // Final build order
	SkippedPackages   map[string]string   // pkgName -> reason for skip
	RebuildPackages   map[string]bool     // Packages marked for rebuild
	PostRebuilds      map[string][]string // Packages needing a rebuild for optional deps
	PostBuildRebuilds map[string][]string // Stores post-build actions
}

// resolveBuildPlan creates a dynamic, context-aware build plan.
// It correctly handles resolvable circular dependencies caused by optional dependencies.

func resolveBuildPlan(targetPackages []string, userRequestedPackages map[string]bool, withRebuilds bool) (*BuildPlan, error) {
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
			if dep.Name == pkgName {
				continue
			}

			// Conditionally handle the 'rebuild' flag
			if withRebuilds && dep.Rebuild {
				// This is a post-build action. Add it to the map for the current package.
				plan.PostBuildRebuilds[pkgName] = append(plan.PostBuildRebuilds[pkgName], dep.Name)

			} else if dep.Optional {
				if !isPackageInstalled(dep.Name) {
					// Record that pkgName needs an inline rebuild because an optional dep is missing.
					plan.PostRebuilds[pkgName] = append(plan.PostRebuilds[pkgName], dep.Name)
				}
			}

			// CRITICAL: Always process the dependency to ensure it gets into the build order at least once.
			// This covers normal deps, optional deps, and 'rebuild' deps (when withRebuilds is off).
			if err := processPkg(dep.Name); err != nil {
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

// stripPackage recursively walks outputDir and runs the 'strip' command on every executable file found,
// executing the stripping concurrently to maximize speed.

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

			// Safety check: a package cannot depend on itself
			if depName == currentPkg {
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
		name, _, _, _, _, _ := parseDepToken(line)
		if name != "" && name != pkgName {
			deps = append(deps, name)
		}
	}
	return deps, nil
}

// executeMountCommand accepts the FULL destination path (e.g., /var/tmp/lfs/dev/tty)

type DepSpec struct {
	Name     string
	Op       string // one of: "<=", ">=", "==", "<", ">", or empty for no constraint
	Version  string
	Optional bool
	Rebuild  bool
	Make     bool // True if dependency is only needed at build time
}

// parseDependsFile reads the package's depends file and returns a list of dependency specs.
