package hokuto

// Code in this file was split out of main.go/update.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/schollz/progressbar/v3"
)

// Cache for resolved alternative dependencies to avoid prompting multiple times
var alternativeDepCache = make(map[string]string)

var dependencyBinaryVersionlessLogOnce sync.Map

var runtimeDependencyInstallInProgress sync.Map

var suppressRuntimeDependencyAutoInstall atomic.Int32

// binaryOnlyRuntimeDependencyInstall is enabled while handling a build command.
// Runtime dependencies are useful when a freshly built package is installed, but
// they must never expand the source build graph. In this mode we install an
// available binary and otherwise leave the runtime dependency unresolved.
var binaryOnlyRuntimeDependencyInstall atomic.Int32

func suppressRuntimeDependencyAutoInstallScope() func() {
	suppressRuntimeDependencyAutoInstall.Add(1)
	return func() {
		suppressRuntimeDependencyAutoInstall.Add(-1)
	}
}

func binaryOnlyRuntimeDependencyInstallScope() func() {
	binaryOnlyRuntimeDependencyInstall.Add(1)
	return func() {
		binaryOnlyRuntimeDependencyInstall.Add(-1)
	}
}

var develInstallMu sync.Mutex

var dependencyInstallProgress = struct {
	sync.Mutex
	bars []*progressbar.ProgressBar
}{}

var baseDevelPackages = []string{
	"autoconf",
	"automake",
	"binutils",
	"bison",
	"file",
	"findutils",
	"flex",
	"gawk",
	"gcc",
	"gettext",
	"grep",
	"gzip",
	"libtool",
	"m4",
	"make",
	"patch",
	"pkgconf",
	"sed",
	"texinfo",
	"which",
}

var multilibDevelPackages = []string{
	"lib32-glibc",
	"lib32-gcc-libs",
}

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

func multilibEnabled(cfg *Config) bool {
	return EnableMultilib || (cfg != nil && cfg.Values["HOKUTO_MULTILIB"] == "1")
}

func isMultilibPackageDepName(name string) bool {
	return strings.HasPrefix(name, "lib32-") || strings.HasSuffix(name, "-32")
}

func shouldSkipMultilibMakeDep(dep DepSpec, name string, cfg *Config) bool {
	return dep.Make && !multilibEnabled(cfg) && isMultilibPackageDepName(name)
}

func dependencyVariantCandidates(pkgName string, cfg *Config) []string {
	preferred := GetSystemVariantForPackage(cfg, pkgName)
	candidates := []string{preferred}
	add := func(v string) {
		for _, existing := range candidates {
			if existing == v {
				return
			}
		}
		candidates = append(candidates, v)
	}

	switch preferred {
	case "optimized":
		add("generic")
		if isMultilibPackage(pkgName) {
			add("multi-optimized")
			add("multi-generic")
		}
	case "generic":
		add("optimized")
		if isMultilibPackage(pkgName) {
			add("multi-generic")
			add("multi-optimized")
		}
	case "multi-optimized":
		add("multi-generic")
		add("optimized")
		add("generic")
	case "multi-generic":
		add("multi-optimized")
		add("generic")
		add("optimized")
	}

	return candidates
}

func findCachedBinaryTarball(pkgName string, cfg *Config) string {
	for _, variant := range dependencyVariantCandidates(pkgName, cfg) {
		tarballPath, _, _ := findNewestTarball(pkgName, variant)
		if tarballPath != "" {
			return tarballPath
		}
	}
	return ""
}

func findCachedBinaryTarballVersion(pkgName, version, revision string, cfg *Config) string {
	arch := GetSystemArchForPackage(cfg, pkgName)
	for _, variant := range dependencyVariantCandidates(pkgName, cfg) {
		tarballPath := filepath.Join(BinDir, StandardizeRemoteName(pkgName, version, revision, arch, variant))
		if _, err := os.Stat(tarballPath); err == nil {
			return tarballPath
		}
	}
	return ""
}

func splitVersionedPackageName(pkgName string) (baseName, major string, ok bool) {
	lastDash := strings.LastIndex(pkgName, "-")
	if lastDash == -1 || lastDash == len(pkgName)-1 {
		return "", "", false
	}
	major = pkgName[lastDash+1:]
	if _, err := strconv.Atoi(major); err != nil {
		return "", "", false
	}
	return pkgName[:lastDash], major, true
}

// findSourcePackageSatisfying resolves a constrained logical package name to a
// source package in the repositories. Besides the exact name, it recognizes the
// pkg-MAJOR layout used for parallel-installable ABI versions (for example,
// webrtc-audio-processing-1 satisfying webrtc-audio-processing<2.0).
func findSourcePackageSatisfying(name, op, refVersion string) string {
	if op == "" || refVersion == "" {
		return ""
	}

	type sourceCandidate struct {
		name    string
		version string
	}
	seen := make(map[string]bool)
	var candidates []sourceCandidate
	consider := func(candidate, pkgDir string) {
		if candidate == "" || seen[candidate] {
			return
		}
		if candidate != name {
			base, _, ok := splitVersionedPackageName(candidate)
			if !ok || base != name {
				return
			}
		}
		data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
		if err != nil {
			return
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 || !versionSatisfies(fields[0], op, refVersion) {
			return
		}
		seen[candidate] = true
		candidates = append(candidates, sourceCandidate{name: candidate, version: fields[0]})
	}

	for pkgName, pkgDir := range versionedPkgDirs {
		consider(pkgName, pkgDir)
	}
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		consider(name, filepath.Join(repoPath, name))
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			continue
		}
		prefix := name + "-"
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
				consider(entry.Name(), filepath.Join(repoPath, entry.Name()))
			}
		}
	}

	best := ""
	bestVersion := ""
	for _, candidate := range candidates {
		if best == "" || compareVersions(candidate.version, bestVersion) > 0 ||
			(compareVersions(candidate.version, bestVersion) == 0 && candidate.name == name) {
			best = candidate.name
			bestVersion = candidate.version
		}
	}
	return best
}

func revisionCompare(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		default:
			return 0
		}
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func findCachedVersionedBinaryTarball(pkgName string, cfg *Config) (string, bool) {
	_, major, ok := splitVersionedPackageName(pkgName)
	if !ok {
		return "", false
	}

	arch := GetSystemArchForPackage(cfg, pkgName)
	for _, variant := range dependencyVariantCandidates(pkgName, cfg) {
		pattern := filepath.Join(BinDir, fmt.Sprintf("%s-*-*-*-%s.tar.zst", pkgName, variant))
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		var bestPath, bestVersion, bestRevision string
		for _, match := range matches {
			metadata, _, err := scanTarballMetadata(match)
			if err != nil {
				debugf("Skipping cached tarball %s: failed to read metadata: %v\n", match, err)
				continue
			}
			if metadata["name"] != pkgName {
				continue
			}
			if metadata["arch"] != "" && metadata["arch"] != arch {
				continue
			}
			if IdentifyVariant(metadata["name"], metadata["generic"] == "1", metadata["multilib"] == "1") != variant {
				continue
			}
			version := metadata["version"]
			if strings.Split(version, ".")[0] != major {
				continue
			}
			revision := metadata["revision"]
			if revision == "" {
				revision = "1"
			}
			if bestPath == "" || compareVersions(version, bestVersion) > 0 ||
				(compareVersions(version, bestVersion) == 0 && revisionCompare(revision, bestRevision) > 0) {
				bestPath = match
				bestVersion = version
				bestRevision = revision
			}
		}
		if bestPath != "" {
			return bestPath, true
		}
	}

	return "", false
}

func depSpecsFromNames(names []string) []DepSpec {
	deps := make([]DepSpec, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) != "" {
			deps = append(deps, DepSpec{Name: name})
		}
	}
	return deps
}

func resolveBinaryDependenciesFromArchive(pkgName string, cfg *Config, remoteIndex []RepoEntry, allowRemote bool) ([]DepSpec, bool, error) {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if tarballPath := findCachedBinaryTarball(lookupName, cfg); tarballPath != "" {
		deps, err := scanTarballDependencySpecs(tarballPath)
		if err != nil {
			return nil, true, fmt.Errorf("failed to scan dependencies from %s: %w", filepath.Base(tarballPath), err)
		}
		return deps, true, nil
	}

	if !allowRemote {
		return nil, false, nil
	}

	if allowRemote && len(remoteIndex) == 0 && BinaryMirror != "" {
		if idx, err := GetCachedRemoteIndex(cfg); err == nil {
			remoteIndex = idx
		} else {
			debugf("Failed to fetch remote index for %s dependency fallback: %v\n", lookupName, err)
		}
	}

	if len(remoteIndex) == 0 {
		return nil, false, nil
	}

	entryRef, err := GetRemotePackageEntry(lookupName, cfg, remoteIndex)
	if err != nil {
		return nil, false, nil
	}
	entry := *entryRef

	if len(entry.Depends) > 0 {
		return depSpecsFromNames(entry.Depends), true, nil
	}

	if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
		return nil, true, fmt.Errorf("failed to fetch %s for dependency resolution: %w", lookupName, err)
	}

	arch := GetSystemArchForPackage(cfg, entry.Name)
	tarballName := StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, arch, entry.Variant)
	tarballPath := filepath.Join(BinDir, tarballName)
	deps, err := scanTarballDependencySpecs(tarballPath)
	if err != nil {
		return nil, true, fmt.Errorf("failed to scan dependencies from %s: %w", tarballName, err)
	}
	return deps, true, nil
}

func splitDependencySourceCandidates(pkgName string) []string {
	var candidates []string
	add := func(name string) {
		if name == "" || name == pkgName {
			return
		}
		for _, existing := range candidates {
			if existing == name {
				return
			}
		}
		candidates = append(candidates, name)
	}

	if strings.HasPrefix(pkgName, "lib32-") {
		add(strings.TrimPrefix(pkgName, "lib32-"))
	}
	return candidates
}

func splitPackageNamesFromDir(pkgDir string) []string {
	seen := make(map[string]bool)
	var names []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}

	if entries, err := os.ReadDir(pkgDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if name, ok := strings.CutPrefix(entry.Name(), "depends."); ok {
				add(name)
			}
		}
	}

	splitDir := filepath.Join(pkgDir, "split")
	if entries, err := os.ReadDir(splitDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dependsPath := filepath.Join(splitDir, entry.Name(), "depends")
			if fi, err := os.Stat(dependsPath); err == nil && !fi.IsDir() {
				add(entry.Name())
			}
		}
	}

	sort.Strings(names)
	return names
}

func findSplitPackageSource(pkgName string) (sourcePkg string, sourceDir string, ok bool) {
	lookupNames := []string{pkgName}
	for _, prefix := range []string{"aarch64-", "x86_64-"} {
		if strings.HasPrefix(pkgName, prefix) {
			lookupNames = append(lookupNames, strings.TrimPrefix(pkgName, prefix))
			break
		}
	}

	paths := filepath.SplitList(repoPaths)
	for _, repoPath := range paths {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgDir := filepath.Join(repoPath, entry.Name())
			for _, splitName := range splitPackageNamesFromDir(pkgDir) {
				for _, lookupName := range lookupNames {
					if splitName == lookupName {
						return entry.Name(), pkgDir, true
					}
				}
			}
		}
	}
	return "", "", false
}

func findSplitDependencySource(pkgName string) (string, bool) {
	if sourcePkg, _, ok := findSplitPackageSource(pkgName); ok {
		return sourcePkg, true
	}
	for _, candidate := range splitDependencySourceCandidates(pkgName) {
		if _, err := findPackageMetadataDir(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func dependencyBinaryAvailable(pkgName string, cfg *Config, noRemote bool) bool {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if _, ok := findCachedVersionedBinaryTarball(lookupName, cfg); ok {
		return true
	}

	if version, revision, err := getRepoVersion2(lookupName); err == nil {
		outputName := getOutputPackageName(lookupName, cfg)
		if findCachedBinaryTarballVersion(outputName, version, revision, cfg) != "" {
			return true
		}
	} else if findCachedBinaryTarball(lookupName, cfg) != "" {
		logKey := strings.Join([]string{BinDir, repoPaths, BinaryMirror, lookupName, err.Error()}, "\x00")
		if _, loaded := dependencyBinaryVersionlessLogOnce.LoadOrStore(logKey, true); !loaded {
			debugf("Using versionless cached binary availability check for %s: %v\n", lookupName, err)
		}
		return true
	}
	if noRemote || BinaryMirror == "" {
		return false
	}

	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		debugf("Skipping remote binary availability check for %s: %v\n", lookupName, err)
		return false
	}
	_, err = GetRemotePackageEntry(lookupName, cfg, index)
	return err == nil
}

func resolveDependencyList(parentPkg string, deps []DepSpec, visited map[string]bool, plan *[]string, force bool, yes bool, cfg *Config, remoteIndex []RepoEntry, allowRemote bool) error {
	for _, dep := range deps {
		if dep.Make || dep.Optional || dep.Rebuild || dep.Suggest {
			continue
		}

		depName := dep.Name
		if len(dep.Alternatives) > 0 {
			resolved, err := resolveAlternativeDep(dep, yes, cfg)
			if err != nil {
				return fmt.Errorf("failed to resolve alternative dependency for %s: %w", parentPkg, err)
			}
			depName = resolved
		}

		if !force {
			if findInstalledSatisfying(depName, dep.Op, dep.Version) != "" {
				continue
			}
		}

		if err := resolveBinaryDependencies(depName, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
			return err
		}
	}
	return nil
}

// resolveBinaryDependencies recursively finds missing dependencies for a package.
// It populates 'plan' with the names of packages that need to be installed, in topological order.
// 'visited' tracks packages processed in this specific resolution pass to prevent cycles.
// cfg is used to check if multilib is enabled and resolve package names accordingly.

func resolveBinaryDependencies(pkgName string, visited map[string]bool, plan *[]string, force bool, yes bool, cfg *Config, remoteIndex []RepoEntry, allowRemote bool) error {
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
	if !force && isMetaPackageInstalled(pkgName) {
		return nil
	}

	if meta, ok := findMetaPackage(pkgName); ok {
		if err := resolveDependencyList(pkgName, meta.Depends, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
			return err
		}
		return nil
	}
	if meta, ok := findRemoteMetaPackage(pkgName, cfg, remoteIndex, allowRemote); ok {
		if err := resolveDependencyList(pkgName, meta.Depends, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
			return err
		}
		return nil
	}

	// 3. Remote Resolution (Priority if remoteIndex is provided)
	// If the user requested --remote (implied by non-empty remoteIndex), we prioritize
	// the remote package's dependencies over the local source definition.
	if allowRemote && len(remoteIndex) > 0 {
		// Check if package exists in remote index
		found := false
		lookupName := pkgName
		if idx := strings.Index(pkgName, "@"); idx != -1 {
			lookupName = pkgName[:idx]
		}

		for _, entry := range remoteIndex {
			if entry.Type == "meta" {
				continue
			}
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
	pkgDir, err := findPackageMetadataDir(lookupName)
	if err != nil {
		if _, sourceDir, ok := findSplitPackageSource(lookupName); ok {
			deps, err := parsePackageDependsFile(sourceDir, lookupName)
			if err != nil {
				return fmt.Errorf("failed to parse depends for split package %s: %w", pkgName, err)
			}
			if err := resolveDependencyList(pkgName, deps, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
				return err
			}
			if !force && findInstalledSatisfying(pkgName, "", "") != "" {
				return nil
			}
			*plan = append(*plan, pkgName)
			return nil
		}
		if sourcePkg, ok := findSplitDependencySource(pkgName); ok {
			if err := resolveBinaryDependencies(sourcePkg, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
				return err
			}
			if !force && findInstalledSatisfying(pkgName, "", "") != "" {
				return nil
			}
			*plan = append(*plan, pkgName)
			return nil
		}
		deps, found, depErr := resolveBinaryDependenciesFromArchive(pkgName, cfg, remoteIndex, allowRemote)
		if depErr != nil {
			return depErr
		}
		if !found {
			return fmt.Errorf("cannot resolve dependencies for %s: source not found in HOKUTO_PATH", pkgName)
		}
		if err := resolveDependencyList(pkgName, deps, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
			return err
		}
		*plan = append(*plan, pkgName)
		return nil
	}

	// 4. Parse dependencies
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return fmt.Errorf("failed to parse depends for %s: %w", pkgName, err)
	}

	// 5. Recurse for each dependency
	if err := resolveDependencyList(pkgName, deps, visited, plan, force, yes, cfg, remoteIndex, allowRemote); err != nil {
		return err
	}

	// 6. Add current package to plan (Post-order traversal)
	// This ensures dependencies are listed before the package that needs them.
	*plan = append(*plan, pkgName)
	return nil
}

// newPackage creates a minimal package skeleton in $newPackageDir/<pkg>.
// - creates directory $newPackageDir/<pkg>
// - creates build, version, sources files with the right modes and contents

func resolveMissingDeps(pkgName string, processed map[string]bool, missing *[]string, forceBuild map[string]bool, cfg *Config, noRemote bool) error {

	// 1. Mark this package as processed to prevent infinite recursion
	if processed[pkgName] {
		return nil
	}
	processed[pkgName] = true

	if !forceBuild[pkgName] && isPackageInstalled(pkgName) {
		return nil
	}
	if !forceBuild[pkgName] && isMetaPackageInstalled(pkgName) {
		return nil
	}

	if meta, ok := findMetaPackage(pkgName); ok {
		for _, dep := range meta.Depends {
			if dep.Make || dep.Optional || dep.Rebuild || dep.Suggest {
				continue
			}
			depName := dep.Name
			if len(dep.Alternatives) > 0 {
				resolved, err := resolveAlternativeDep(dep, false, cfg)
				if err != nil {
					return fmt.Errorf("failed to resolve alternative dependency: %w", err)
				}
				depName = resolved
			}
			if err := resolveMissingDeps(depName, processed, missing, forceBuild, cfg, noRemote); err != nil {
				return err
			}
		}
		return nil
	}

	binaryAvailableForPkg := !forceBuild[pkgName] && dependencyBinaryAvailable(pkgName, cfg, noRemote)

	// --- 3. Find the Package Source Directory (pkgDir) ---
	pkgDir, err := findPackageMetadataDir(pkgName)
	var dependencies []DepSpec
	if err != nil {
		archiveDeps, found, depErr := resolveBinaryDependenciesFromArchive(pkgName, cfg, nil, !noRemote)
		if depErr != nil {
			return depErr
		}
		if !found {
			if sourcePkg, ok := findSplitDependencySource(pkgName); ok {
				if err := resolveMissingDeps(sourcePkg, processed, missing, forceBuild, cfg, noRemote); err != nil {
					return err
				}
				if !isPackageInstalled(pkgName) {
					*missing = append(*missing, pkgName)
				}
				return nil
			}
			return err
		}
		dependencies = archiveDeps
	} else {
		// --- 4. Parse the depends file (Now that we have the confirmed pkgDir) ---
		// Check if a depends file exists in the located pkgDir.
		dependencies, err = parseDependsFile(pkgDir)
		if err != nil {
			return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
		}
	}

	// --- 5. Recursively check all dependencies ---
	for _, dep := range dependencies {
		if dep.RuntimeOnly || dep.Suggest {
			continue
		}
		if dep.Optional && !forceBuild[pkgName] {
			continue
		}

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
			resolved, err := resolveAlternativeDep(dep, false, cfg) // resolveMissingDeps doesn't have yes flag, use false
			if err != nil {
				return fmt.Errorf("failed to resolve alternative dependency: %w", err)
			}
			depName = resolved
		}

		// Safety check: a package cannot depend on itself.
		if depName == pkgName {
			continue
		}

		// Skip Make dependencies if this package will not be built from source.
		if dep.Make && (isPackageInstalled(pkgName) || binaryAvailableForPkg) && !forceBuild[pkgName] {
			continue
		}

		if shouldSkipMultilibMakeDep(dep, depName, cfg) {
			continue
		}

		// CHECK VERSION CONSTRAINTS & FETCH IF NEEDED
		if dep.Op != "" && dep.Version != "" {
			// 1. Check if any satisfying package is ALREADY INSTALLED (including renamed ones)
			satisfyingPkg := findInstalledSatisfying(depName, dep.Op, dep.Version)
			if satisfyingPkg != "" {
				// Great, a satisfying version is already installed (maybe it's depName-MAJOR)
				depName = satisfyingPkg
			} else if satisfyingSource := findSourcePackageSatisfying(depName, dep.Op, dep.Version); satisfyingSource != "" {
				depName = satisfyingSource
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

		if err := resolveMissingDeps(depName, processed, missing, forceBuild, cfg, noRemote); err != nil {
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

func parsePackageDependsFile(pkgDir, pkgName string) ([]DepSpec, error) {
	dependsPath := findPackageMetadataFile(pkgDir, pkgName, "depends")
	content, err := os.ReadFile(dependsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DepSpec{}, nil
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
	entryRef, err := GetRemotePackageEntry(pkgName, cfg, remoteIndex)
	if err != nil {
		return err // Error now contains specific "not found" message
	}
	// Copy to local variable since we use entry a lot
	var entry = *entryRef

	var deps []DepSpec
	if len(entry.Depends) > 0 {
		// Optimization: Use pre-resolved dependencies from index
		for _, d := range entry.Depends {
			deps = append(deps, DepSpec{Name: d})
		}
	} else {
		// Fallback: Fetch binary package to read depends (older index or missing info)
		if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, false, entry.B3Sum, false); err != nil {
			return fmt.Errorf("failed to fetch remote package for dependency resolution (%s): %v", pkgName, err)
		}

		arch := GetSystemArch(cfg)
		variant := GetSystemVariantForPackage(cfg, entry.Name)
		tarballName := StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, arch, variant)
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
	if err := resolveDependencyList(pkgName, deps, visited, plan, force, yes, cfg, remoteIndex, true); err != nil {
		return err
	}

	// 8. Add to plan
	*plan = append(*plan, pkgName)
	return nil
}

// resolveAlternativeDep resolves an alternative dependency by checking which alternatives are available
// and prompting the user to choose. Returns the chosen package name.
// Uses a cache to avoid prompting multiple times for the same alternative set.
func resolveAlternativeDep(dep DepSpec, yes bool, cfg *Config) (string, error) {
	if len(dep.Alternatives) < 2 {
		// Not an alternative dependency, return the name as-is
		return dep.Name, nil
	}

	cacheKey := alternativeDepCacheKey(dep)

	// Check cache first
	if cached, ok := cachedAlternativeDep(dep); ok {
		return cached, nil
	}

	// Check which alternatives are available (installed or can be found in repos)
	// Separate installed from available in repos for priority handling
	var installed []string
	var available []string
	for _, altName := range dep.Alternatives {
		if shouldSkipMultilibMakeDep(dep, altName, cfg) {
			continue
		}

		// Check if installed first (prioritize installed).
		// Alternatives currently don't support version constraints, but for this
		// explicit alternative selection any installed ABI-suffixed variant counts.
		if sat := findInstalledPackageVariant(altName); sat != "" {
			installed = append(installed, sat)
			available = append(available, sat)
			continue
		}
		// Check if can be found in repos
		if _, err := findPackageMetadataDir(altName); err == nil {
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

func alternativeDepCacheKey(dep DepSpec) string {
	sortedAlts := make([]string, len(dep.Alternatives))
	copy(sortedAlts, dep.Alternatives)
	sort.Strings(sortedAlts)
	return strings.Join(sortedAlts, "|")
}

func cachedAlternativeDep(dep DepSpec) (string, bool) {
	if len(dep.Alternatives) < 2 {
		return dep.Name, true
	}
	cacheKey := alternativeDepCacheKey(dep)
	cached, ok := alternativeDepCache[cacheKey]
	if !ok {
		return "", false
	}
	if isPackageInstalled(cached) {
		return cached, true
	}
	if _, err := findPackageMetadataDir(cached); err == nil {
		return cached, true
	}
	delete(alternativeDepCache, cacheKey)
	return "", false
}

func resolvedBuildDependencyCandidates(dep DepSpec, yes bool, cfg *Config) ([]string, error) {
	resolved := dep.Name
	if len(dep.Alternatives) > 0 {
		if cached, ok := cachedAlternativeDep(dep); ok {
			resolved = cached
		} else {
			var err error
			resolved, err = resolveAlternativeDep(dep, yes, cfg)
			if err != nil {
				return nil, err
			}
		}
	}
	if dep.Op != "" && dep.Version != "" {
		if installed := findInstalledSatisfying(resolved, dep.Op, dep.Version); installed != "" {
			return []string{installed}, nil
		}
		if source := findSourcePackageSatisfying(resolved, dep.Op, dep.Version); source != "" {
			return []string{source}, nil
		}
	}
	return []string{resolved}, nil
}

// parseDepToken parses tokens like "pkg", "pkg<=1.2.3 optional", "pkg rebuild",
// and "pkg suggest Optional support" and returns name, op, version, flags, and
// optional suggestion text.

func parseDepToken(token string) (name string, op string, ver string, optional bool, rebuild bool, makeDep bool, cross bool, crossNative bool, runtimeOnly bool, suggest bool, suggestText string) {
	// Split by whitespace to separate package spec from flags
	parts := strings.Fields(token)
	if len(parts) == 0 {
		return "", "", "", false, false, false, false, false, false, false, ""
	}

	pkgSpec := parts[0]
	// Check for flags in remaining parts
	for i := 1; i < len(parts); i++ {
		switch strings.ToLower(parts[i]) {
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
		case "runtime", "runtime-only", "runtimeonly":
			runtimeOnly = true
		case "suggest", "suggested", "optional-runtime", "runtime-optional":
			suggest = true
			if i+1 < len(parts) {
				suggestText = strings.Join(parts[i+1:], " ")
				if unquoted, err := strconv.Unquote(suggestText); err == nil {
					suggestText = unquoted
				}
				suggestText = strings.TrimSpace(suggestText)
			}
			i = len(parts)
		}
	}

	// Parse version constraint from package spec
	ops := []string{"<=", ">=", "==", "<", ">"}
	for _, op := range ops {
		if idx := strings.Index(pkgSpec, op); idx != -1 {
			name := pkgSpec[:idx]
			ver := pkgSpec[idx+len(op):]
			return strings.TrimSpace(name), op, strings.TrimSpace(ver), optional, rebuild, makeDep || cross, cross, crossNative, runtimeOnly, suggest, suggestText
		}
	}
	return pkgSpec, "", "", optional, rebuild, makeDep || cross, cross, crossNative, runtimeOnly, suggest, suggestText
}

// BuildPlan represents the complete build plan with proper ordering

type BuildPlan struct {
	Order             []string            // Final build order
	SkippedPackages   map[string]string   // pkgName -> reason for skip
	RebuildPackages   map[string]bool     // Packages marked for rebuild
	PostRebuilds      map[string][]string // Packages needing a rebuild for optional deps
	PostBuildRebuilds map[string][]string // Stores post-build actions
	ManualPrereqs     map[string][]string // pkgs that MUST be completed before this one (from /etc/hokuto/hokuto.update)
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
		ManualPrereqs:     make(map[string][]string),
	}

	processed := make(map[string]bool)
	inProgress := make(map[string]bool)
	alreadyInOrder := make(map[string]bool)
	sourceBuildPackages := make(map[string]bool, len(targetPackages))
	for _, pkgName := range targetPackages {
		sourceBuildPackages[pkgName] = true
	}

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
			// If it's already in the order, we definitely don't need to process it again.
			// If it's NOT in the order, but it's now marked for rebuild, we MUST process it
			// to ensure it and its make-dependencies are added.
			if !plan.RebuildPackages[pkgName] || alreadyInOrder[pkgName] {
				return nil
			}
		}

		inProgress[pkgName] = true
		defer func() { delete(inProgress, pkgName) }()

		isInstalled := isPackageInstalled(pkgName)
		if isInstalled && !sourceBuildPackages[pkgName] && !plan.RebuildPackages[pkgName] {
			processed[pkgName] = true
			plan.SkippedPackages[pkgName] = "already installed"
			return nil
		}

		pkgDir, err := findPackageMetadataDir(pkgName)
		if err != nil {
			if sourcePkg, ok := findSplitDependencySource(pkgName); ok {
				sourceBuildPackages[sourcePkg] = true
				if processed[sourcePkg] && !alreadyInOrder[sourcePkg] {
					delete(processed, sourcePkg)
					delete(plan.SkippedPackages, sourcePkg)
				}
				return processPkg(sourcePkg)
			}
			return fmt.Errorf("package source not found for '%s': %w", pkgName, err)
		}

		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
		}

		// Process all dependencies recursively first.
		for _, dep := range deps {
			if dep.RuntimeOnly || dep.Suggest {
				continue
			}

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
				resolved, err := resolveAlternativeDep(dep, false, cfg) // Use false for build (no yes flag available)
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

			if shouldSkipMultilibMakeDep(dep, depName, cfg) {
				continue
			}

			if dep.Optional {
				if !isPackageInstalled(depName) {
					plan.PostRebuilds[pkgName] = append(plan.PostRebuilds[pkgName], depName)
				}
				if !sourceBuildPackages[pkgName] && !plan.RebuildPackages[pkgName] {
					continue
				}
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
				} else if satisfyingSource := findSourcePackageSatisfying(depName, dep.Op, dep.Version); satisfyingSource != "" {
					depName = satisfyingSource
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

			}

			// Process required dependencies so they get into the build order at least once.
			// Optional dependencies are advisory and are handled by PostRebuilds only if they
			// become available through another required edge in this build.
			if err := processPkg(depName); err != nil {
				return err
			}
		}

		// Now, decide if the package itself needs to be in the build order.
		shouldBuild := false
		if sourceBuildPackages[pkgName] {
			shouldBuild = true // This package is scheduled to be built from source in this plan.
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
	prunePostRebuilds(plan)

	return plan, nil
}

func prunePostRebuilds(plan *BuildPlan) {
	if len(plan.PostRebuilds) == 0 {
		return
	}

	inOrder := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inOrder[pkgName] = true
	}

	for parent, deps := range plan.PostRebuilds {
		filtered := deps[:0]
		for _, dep := range deps {
			keep := inOrder[dep]
			if !keep {
				if sourcePkg, ok := findSplitDependencySource(dep); ok && inOrder[sourcePkg] {
					keep = true
				}
			}
			if keep {
				filtered = append(filtered, dep)
			}
		}
		if len(filtered) == 0 {
			delete(plan.PostRebuilds, parent)
			continue
		}
		plan.PostRebuilds[parent] = filtered
	}
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

func getPackageDependenciesForward(pkgName string, cfg *Config) ([]string, error) {
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
			if dep.RuntimeOnly || dep.Suggest {
				continue
			}
			// FILTER: skip cross dependencies if not cross-compiling
			if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
				continue
			}

			// FILTER: skip crossnative dependencies unless we are in a cross-native build
			if dep.CrossNative {
				if cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
					continue
				}
			}

			depName := dep.Name

			// Resolve alternative dependencies if present
			if len(dep.Alternatives) > 0 {
				resolved, err := resolveAlternativeDep(dep, false, cfg) // Use false for build (no yes flag available)
				if err != nil {
					return fmt.Errorf("failed to resolve alternative dependency: %w", err)
				}
				depName = resolved
			}

			// Safety check: a package cannot depend on itself
			if depName == currentPkg {
				continue
			}

			if shouldSkipMultilibMakeDep(dep, depName, cfg) {
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
		name, _, _, _, _, _, _, _, _, _, _ := parseDepToken(line)
		if name != "" && name != pkgName {
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
	RuntimeOnly  bool     // True if dependency is needed after install but not for the build graph
	Suggest      bool     // True if dependency should be suggested after install, not required
	SuggestText  string   // Human-readable explanation shown with suggested dependencies
	Alternatives []string // List of alternative package names (e.g., ["rust", "rustup"] for "rust | rustup")
}

func ShowPackageDependencies(pkgName string, reverse bool, cfg *Config) error {
	if reverse {
		return showReverseDependencies(pkgName)
	}
	return showForwardDependencies(pkgName)
}

func showForwardDependencies(pkgName string) error {
	if meta, ok := findMetaPackage(pkgName); ok {
		lines := metaPackageDependsLines(meta)
		if len(lines) == 0 {
			fmt.Printf("Meta package %s has no dependencies.\n", pkgName)
			return nil
		}
		colArrow.Printf("-> ")
		colSuccess.Printf("Dependencies for meta package %s:\n", pkgName)
		for _, line := range lines {
			colArrow.Printf("-> ")
			fmt.Println(line)
		}
		return nil
	}

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

// installBuildDependencies identifies and installs all missing build-time dependencies for a package.
// It returns a list of packages that were newly installed, which can later be uninstalled.
func installBuildDependencies(pkgName string, cfg *Config, noRemote bool) ([]string, error) {
	return installBuildDependenciesWithOptions(pkgName, cfg, noRemote, false)
}

func installBuildDependenciesWithOptions(pkgName string, cfg *Config, noRemote bool, quiet bool) ([]string, error) {
	var newlyInstalled []string

	// Collect ALL missing dependencies (both runtime and build-time)
	var missing []string
	masterProcessed := make(map[string]bool)
	userRequested := map[string]bool{pkgName: true}

	if err := resolveMissingDeps(pkgName, masterProcessed, &missing, userRequested, cfg, false); err != nil {
		return newlyInstalled, fmt.Errorf("failed to resolve dependencies for %s: %v", pkgName, err)
	}

	if len(missing) == 0 {
		return nil, nil
	}

	// Ensure base is first
	missing = MovePackageToFront(missing, "sauzeros-base")

	var installQueue []string
	for _, depPkg := range missing {
		if depPkg == pkgName || isPackageInstalled(depPkg) {
			continue
		}
		installQueue = append(installQueue, depPkg)
	}

	bar := newDependencyInstallProgress(len(installQueue), "Installing Build Dependencies", quiet)
	deactivateProgress := activateDependencyInstallProgress(bar)
	defer deactivateProgress()
	for _, depPkg := range installQueue {
		// Try to install from binary or build
		describeDependencyInstallProgress(bar, depPkg)
		installed, err := installAvailableBuildDependencyBinaryWithOptions(depPkg, cfg, noRemote, quiet, false)
		if err == nil && !installed {
			installed, err = ensurePackageInstalledWithOptions(depPkg, cfg, noRemote, nil, quiet)
		}
		if err != nil {
			return newlyInstalled, err
		}
		advanceDependencyInstallProgress(bar)
		if installed {
			outputName := getOutputPackageName(depPkg, cfg)
			newlyInstalled = append(newlyInstalled, outputName)
		}
	}

	return newlyInstalled, nil
}

// ensurePackageInstalled handles the "fetch binary OR build and then install" logic for a single package.
func ensurePackageInstalled(pkgName string, cfg *Config, noRemote bool) (bool, error) {
	return ensurePackageInstalledWithOptions(pkgName, cfg, noRemote, nil, false)
}

func ensurePackageInstalledWithSeen(pkgName string, cfg *Config, noRemote bool, seen map[string]bool) (bool, error) {
	return ensurePackageInstalledWithOptions(pkgName, cfg, noRemote, seen, false)
}

func ensurePackageInstalledWithOptions(pkgName string, cfg *Config, noRemote bool, seen map[string]bool, quiet bool) (bool, error) {
	if isPackageInstalled(pkgName) {
		return false, nil
	}
	if quiet {
		describeActiveDependencyInstallProgress(pkgName)
	}
	if _, inProgress := runtimeDependencyInstallInProgress.Load(pkgName); inProgress {
		debugf("Skipping recursive install for in-progress dependency %s\n", pkgName)
		return false, nil
	}
	runtimeDependencyInstallInProgress.Store(pkgName, true)
	defer runtimeDependencyInstallInProgress.Delete(pkgName)

	if _, err := findPackageMetadataDir(pkgName); err != nil {
		if sourcePkg, _, ok := findSplitPackageSource(pkgName); ok {
			return ensureSplitPackageInstalled(sourcePkg, pkgName, cfg, noRemote, seen, quiet)
		}
	}

	if installName, tarballPath, ok, err := availableBinaryPackageTarball(pkgName, cfg, noRemote); err != nil {
		return false, err
	} else if ok {
		if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(installName, cfg, noRemote, seen, quiet); err != nil {
			return false, err
		}
		return installBinaryTarballWithOptions(tarballPath, installName, cfg, quiet)
	}

	// 1. Get repo version
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return ensureBinaryOnlyPackageInstalled(pkgName, cfg, noRemote)
	}

	outputPkgName := getOutputPackageName(pkgName, cfg)
	arch := GetSystemArchForPackage(cfg, pkgName)
	variant := GetSystemVariantForPackage(cfg, pkgName)
	tarballName := StandardizeRemoteName(outputPkgName, version, revision, arch, variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	foundBinary := false
	if _, err := os.Stat(tarballPath); err == nil {
		foundBinary = true
	} else if !noRemote && BinaryMirror != "" {
		// Try to fetch binary
		index, _ := GetCachedRemoteIndex(cfg)
		var expectedSum string
		shouldTryDownload := true
		if index != nil {
			shouldTryDownload = false
			for _, entry := range index {
				if entry.Name == pkgName && entry.Version == version && entry.Revision == revision && entry.Arch == arch && entry.Variant == variant {
					shouldTryDownload = true
					expectedSum = entry.B3Sum
					break
				}
			}
		}
		if shouldTryDownload {
			if err := fetchBinaryPackage(pkgName, version, revision, cfg, true, expectedSum, false); err == nil {
				foundBinary = true
			}
		}
	}

	if foundBinary {
		if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(pkgName, cfg, noRemote, seen, quiet); err != nil {
			return false, err
		}
		logger, fast := dependencyInstallLogger(quiet)
		isCriticalAtomic.Store(1)
		defer isCriticalAtomic.Store(0)
		handlePreInstallUninstall(outputPkgName, cfg, RootExec, true, logger)
		if _, err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true, fast, false, logger); err != nil {
			return false, fmt.Errorf("failed to install binary %s: %v", pkgName, err)
		}
		return true, nil
	}

	// 2. Build from source
	if err := installSourceFallbackBuildDependenciesWithOptions(pkgName, cfg, noRemote, quiet); err != nil {
		return false, err
	}
	buildOpts := BuildOptions{Quiet: true}
	if quiet {
		buildOpts.LogWriter = io.Discard
	}
	_, err = pkgBuild(pkgName, cfg, UserExec, buildOpts)
	if err != nil {
		return false, fmt.Errorf("failed to build %s: %v", pkgName, err)
	}

	// 3. Install after build
	logger, fast := dependencyInstallLogger(quiet)
	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)
	handlePreInstallUninstall(outputPkgName, cfg, RootExec, true, logger)
	if _, err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true, fast, false, logger); err != nil {
		return false, fmt.Errorf("failed to install built package %s: %v", pkgName, err)
	}
	return true, nil
}

func ensureSplitPackageInstalled(sourcePkg, splitPkg string, cfg *Config, noRemote bool, seen map[string]bool, quiet bool) (bool, error) {
	if isPackageInstalled(splitPkg) {
		return false, nil
	}

	version, revision, err := getRepoVersion2(sourcePkg)
	if err != nil {
		return false, err
	}

	sourceDir, err := findPackageMetadataDir(sourcePkg)
	if err != nil {
		return false, err
	}
	options := loadBuildOptions(sourceDir)
	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]
	arch := GetSystemArchForPackage(cfg, sourcePkg)
	variant := IdentifyVariant(splitPkg, isGeneric, isMultilibPackage(splitPkg))
	tarballName := StandardizeRemoteName(splitPkg, version, revision, arch, variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	foundBinary := false
	if _, err := os.Stat(tarballPath); err == nil {
		foundBinary = true
	} else if !noRemote && BinaryMirror != "" {
		index, _ := GetCachedRemoteIndex(cfg)
		var expectedSum string
		shouldTryDownload := true
		if index != nil {
			shouldTryDownload = false
			for _, entry := range index {
				if entry.Name == splitPkg && entry.Version == version && entry.Revision == revision && entry.Arch == arch && entry.Variant == variant {
					shouldTryDownload = true
					expectedSum = entry.B3Sum
					break
				}
			}
		}
		if shouldTryDownload {
			if err := fetchBinaryPackage(splitPkg, version, revision, cfg, true, expectedSum, false); err == nil {
				foundBinary = true
			}
		}
	}

	if foundBinary {
		if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(splitPkg, cfg, noRemote, seen, quiet); err != nil {
			return false, err
		}
		return installBinaryTarballWithOptions(tarballPath, splitPkg, cfg, quiet)
	}

	if err := installSourceFallbackBuildDependenciesWithOptions(sourcePkg, cfg, noRemote, quiet); err != nil {
		return false, err
	}
	buildOpts := BuildOptions{Quiet: true}
	if quiet {
		buildOpts.LogWriter = io.Discard
	}
	if _, err := pkgBuild(sourcePkg, cfg, UserExec, buildOpts); err != nil {
		return false, fmt.Errorf("failed to build %s for split package %s: %v", sourcePkg, splitPkg, err)
	}
	if err := installBuiltSplitDependencyWithOptions(sourcePkg, splitPkg, cfg, quiet); err != nil {
		return false, fmt.Errorf("failed to install split package %s from %s: %w", splitPkg, sourcePkg, err)
	}
	return true, nil
}

func installAvailableSplitDependencyBinary(sourcePkg, splitPkg string, cfg *Config, noRemote bool, seen map[string]bool, quiet bool) (bool, error) {
	if isPackageInstalled(splitPkg) {
		return false, nil
	}

	version, revision, err := getRepoVersion2(sourcePkg)
	if err != nil {
		return false, err
	}

	sourceDir, err := findPackageMetadataDir(sourcePkg)
	if err != nil {
		return false, err
	}
	options := loadBuildOptions(sourceDir)
	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]
	arch := GetSystemArchForPackage(cfg, sourcePkg)
	variant := IdentifyVariant(splitPkg, isGeneric, isMultilibPackage(splitPkg))
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(splitPkg, version, revision, arch, variant))

	if _, err := os.Stat(tarballPath); err != nil {
		if noRemote || BinaryMirror == "" {
			return false, nil
		}

		index, _ := GetCachedRemoteIndex(cfg)
		var expectedSum string
		shouldTryDownload := true
		if index != nil {
			shouldTryDownload = false
			for _, entry := range index {
				if entry.Name == splitPkg && entry.Version == version && entry.Revision == revision && entry.Arch == arch && entry.Variant == variant {
					shouldTryDownload = true
					expectedSum = entry.B3Sum
					break
				}
			}
		}
		if !shouldTryDownload {
			return false, nil
		}
		if err := fetchBinaryPackage(splitPkg, version, revision, cfg, true, expectedSum, false); err != nil {
			return false, err
		}
		if _, err := os.Stat(tarballPath); err != nil {
			return false, nil
		}
	}

	if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(splitPkg, cfg, noRemote, seen, quiet); err != nil {
		return false, err
	}
	return installBinaryTarballWithOptions(tarballPath, splitPkg, cfg, quiet)
}

func binaryRuntimeDependencySpecs(pkgName string, cfg *Config, noRemote bool) ([]DepSpec, error) {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if pkgDir, err := findPackageMetadataDir(lookupName); err == nil {
		return parseDependsFile(pkgDir)
	}

	deps, found, err := resolveBinaryDependenciesFromArchive(pkgName, cfg, nil, !noRemote)
	if err != nil {
		return nil, err
	}
	if found {
		return deps, nil
	}
	return nil, nil
}

func ensureBinaryRuntimeDependenciesInstalled(pkgName string, cfg *Config, noRemote bool, seen map[string]bool) error {
	return ensureBinaryRuntimeDependenciesInstalledWithOptions(pkgName, cfg, noRemote, seen, false)
}

func ensureBinaryRuntimeDependenciesInstalledWithOptions(pkgName string, cfg *Config, noRemote bool, seen map[string]bool, quiet bool) error {
	if seen == nil {
		seen = make(map[string]bool)
	}
	if seen[pkgName] {
		return nil
	}
	seen[pkgName] = true

	deps, err := binaryRuntimeDependencySpecs(pkgName, cfg, noRemote)
	if err != nil {
		return fmt.Errorf("failed to resolve runtime dependencies for %s: %w", pkgName, err)
	}

	for _, dep := range deps {
		if dep.Make || dep.Optional || dep.Rebuild || dep.Suggest {
			continue
		}
		if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
			continue
		}
		if dep.CrossNative && (cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1") {
			continue
		}

		depName := dep.Name
		if len(dep.Alternatives) > 0 {
			resolved, err := resolveAlternativeDep(dep, true, cfg)
			if err != nil {
				return fmt.Errorf("failed to resolve alternative runtime dependency for %s: %w", pkgName, err)
			}
			depName = resolved
		}
		if depName == "" || depName == pkgName || shouldSkipMultilibMakeDep(dep, depName, cfg) {
			continue
		}
		if findInstalledSatisfying(depName, dep.Op, dep.Version) != "" {
			continue
		}
		if binaryOnlyRuntimeDependencyInstall.Load() > 0 {
			installed, err := installRuntimeDependencyBinaryOnly(depName, cfg, noRemote, seen, quiet)
			if err != nil {
				return fmt.Errorf("failed to install binary runtime dependency %s for %s: %w", depName, pkgName, err)
			}
			if !installed {
				debugf("Skipping runtime dependency %s for %s during build: no binary available\n", depName, pkgName)
			}
			continue
		}

		if quiet {
			describeActiveDependencyInstallProgress(depName)
		}
		if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(depName, cfg, noRemote, seen, quiet); err != nil {
			return err
		}
		if findInstalledSatisfying(depName, dep.Op, dep.Version) != "" {
			continue
		}
		if _, err := ensurePackageInstalledWithOptions(depName, cfg, noRemote, seen, quiet); err != nil {
			return fmt.Errorf("failed to install runtime dependency %s for %s: %w", depName, pkgName, err)
		}
	}
	return nil
}

// installRuntimeDependencyBinaryOnly installs pkgName only when a binary is
// available. It deliberately has no source-build fallback. Runtime dependencies
// of that binary are handled recursively under the same policy.
func installRuntimeDependencyBinaryOnly(pkgName string, cfg *Config, noRemote bool, seen map[string]bool, quiet bool) (bool, error) {
	if isPackageInstalled(pkgName) {
		return false, nil
	}
	if seen == nil {
		seen = make(map[string]bool)
	}
	if seen[pkgName] {
		return false, nil
	}

	installName, tarballPath, ok, err := availableBinaryPackageTarball(pkgName, cfg, noRemote)
	if err != nil || !ok {
		return false, err
	}
	if err := ensureBinaryRuntimeDependenciesInstalledWithOptions(installName, cfg, noRemote, seen, quiet); err != nil {
		return false, err
	}

	// pkgInstall also scans the installed depends file. Suppress that second pass;
	// the recursive binary-only pass above has already handled it.
	defer suppressRuntimeDependencyAutoInstallScope()()
	return installBinaryTarballWithOptions(tarballPath, installName, cfg, quiet)
}

func dependencyInstallLogger(quiet bool) (io.Writer, bool) {
	if quiet {
		return io.Discard, true
	}
	return nil, false
}

func newDependencyInstallProgress(total int, description string, quiet bool) *progressbar.ProgressBar {
	if !quiet || total <= 0 {
		return nil
	}
	return progressbar.Default(int64(total), colArrow.Sprint("-> ")+colSuccess.Sprint(description))
}

func activateDependencyInstallProgress(bar *progressbar.ProgressBar) func() {
	if bar == nil {
		return func() {}
	}
	dependencyInstallProgress.Lock()
	dependencyInstallProgress.bars = append(dependencyInstallProgress.bars, bar)
	dependencyInstallProgress.Unlock()
	return func() {
		dependencyInstallProgress.Lock()
		if len(dependencyInstallProgress.bars) > 0 {
			dependencyInstallProgress.bars = dependencyInstallProgress.bars[:len(dependencyInstallProgress.bars)-1]
		}
		dependencyInstallProgress.Unlock()
	}
}

func describeDependencyInstallProgress(bar *progressbar.ProgressBar, pkgName string) {
	if bar != nil {
		bar.Describe(colArrow.Sprint("-> ") + colSuccess.Sprint("Installing ") + colNote.Sprint(pkgName))
	}
}

func describeDependencyCheckProgress(bar *progressbar.ProgressBar, pkgName string) {
	if bar != nil {
		bar.Describe(colArrow.Sprint("-> ") + colSuccess.Sprint("Checking ") + colNote.Sprint(pkgName))
	}
}

func clearDependencyInstallProgress(bar *progressbar.ProgressBar) {
	if bar != nil {
		_ = bar.Clear()
		fmt.Fprint(os.Stderr, "\n")
	}
}

func describeActiveDependencyInstallProgress(pkgName string) {
	dependencyInstallProgress.Lock()
	var bar *progressbar.ProgressBar
	if len(dependencyInstallProgress.bars) > 0 {
		bar = dependencyInstallProgress.bars[len(dependencyInstallProgress.bars)-1]
	}
	dependencyInstallProgress.Unlock()
	describeDependencyInstallProgress(bar, pkgName)
}

func advanceDependencyInstallProgress(bar *progressbar.ProgressBar) {
	if bar != nil {
		_ = bar.Add(1)
	}
}

func installBinaryTarball(tarballPath, pkgName string, cfg *Config) (bool, error) {
	return installBinaryTarballWithOptions(tarballPath, pkgName, cfg, false)
}

func installBinaryTarballWithOptions(tarballPath, pkgName string, cfg *Config, quiet bool) (bool, error) {
	if quiet {
		describeActiveDependencyInstallProgress(pkgName)
	}
	logger, fast := dependencyInstallLogger(quiet)
	execCtx := RootExec
	if quiet {
		execCtx = &Executor{
			Context:         RootExec.Context,
			ShouldRunAsRoot: RootExec.ShouldRunAsRoot,
			Interactive:     false,
			Stdout:          io.Discard,
			Stderr:          io.Discard,
		}
	}
	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)
	handlePreInstallUninstall(pkgName, cfg, execCtx, true, logger)
	if _, err := pkgInstall(tarballPath, pkgName, cfg, execCtx, true, fast, false, logger); err != nil {
		return false, fmt.Errorf("failed to install binary %s: %v", pkgName, err)
	}
	return true, nil
}

func ensureBinaryOnlyPackageInstalled(pkgName string, cfg *Config, noRemote bool) (bool, error) {
	if tarballPath := findCachedBinaryTarball(pkgName, cfg); tarballPath != "" {
		if err := ensureBinaryRuntimeDependenciesInstalled(pkgName, cfg, noRemote, nil); err != nil {
			return false, err
		}
		return installBinaryTarball(tarballPath, pkgName, cfg)
	}

	if noRemote || BinaryMirror == "" {
		return false, fmt.Errorf("source not found for %s and no cached binary package is available", pkgName)
	}

	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return false, fmt.Errorf("source not found for %s and failed to fetch remote index: %w", pkgName, err)
	}

	entryRef, err := GetRemotePackageEntry(pkgName, cfg, index)
	if err != nil {
		return false, fmt.Errorf("source not found for %s and no remote binary package is available: %w", pkgName, err)
	}
	entry := *entryRef
	if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
		return false, fmt.Errorf("failed to fetch binary %s: %w", pkgName, err)
	}

	arch := GetSystemArchForPackage(cfg, entry.Name)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, arch, entry.Variant))
	if err := ensureBinaryRuntimeDependenciesInstalled(entry.Name, cfg, noRemote, nil); err != nil {
		return false, err
	}
	return installBinaryTarball(tarballPath, entry.Name, cfg)
}

func fetchExactBinaryTarballIfAvailable(pkgName, version, revision, variant string, cfg *Config, noRemote bool) (string, bool, error) {
	if noRemote || BinaryMirror == "" {
		return "", false, nil
	}

	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		debugf("Skipping remote binary install check for %s: %v\n", pkgName, err)
		return "", false, nil
	}

	arch := GetSystemArchForPackage(cfg, pkgName)
	for _, entry := range index {
		if entry.Name != pkgName || entry.Version != version || entry.Revision != revision || entry.Arch != arch || entry.Variant != variant {
			continue
		}
		if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
			return "", false, err
		}
		tarballPath := filepath.Join(BinDir, StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant))
		return tarballPath, true, nil
	}

	return "", false, nil
}

func availableBinaryPackageTarball(pkgName string, cfg *Config, noRemote bool) (installName, tarballPath string, ok bool, err error) {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if tarballPath, ok := findCachedVersionedBinaryTarball(lookupName, cfg); ok {
		return lookupName, tarballPath, true, nil
	}

	if _, sourceErr := findPackageMetadataDir(lookupName); sourceErr != nil {
		if sourcePkg, sourceDir, splitOK := findSplitPackageSource(lookupName); splitOK {
			version, revision, err := getRepoVersion2(sourcePkg)
			if err != nil {
				return "", "", false, err
			}

			options := loadBuildOptions(sourceDir)
			isGeneric := options["generic"]
			if cfg != nil && cfg.Values["HOKUTO_GENERIC"] == "1" {
				isGeneric = true
			}
			arch := GetSystemArchForPackage(cfg, lookupName)
			variant := IdentifyVariant(lookupName, isGeneric, isMultilibPackage(lookupName))
			tarballName := StandardizeRemoteName(lookupName, version, revision, arch, variant)
			tarballPath := filepath.Join(BinDir, tarballName)
			if _, err := os.Stat(tarballPath); err == nil {
				return lookupName, tarballPath, true, nil
			}
			tarballPath, ok, err := fetchExactBinaryTarballIfAvailable(lookupName, version, revision, variant, cfg, noRemote)
			if err != nil || ok {
				return lookupName, tarballPath, ok, err
			}
			return "", "", false, nil
		}

		if tarballPath := findCachedBinaryTarball(lookupName, cfg); tarballPath != "" {
			return lookupName, tarballPath, true, nil
		}
		if noRemote || BinaryMirror == "" {
			return "", "", false, nil
		}
		index, err := GetCachedRemoteIndex(cfg)
		if err != nil {
			debugf("Skipping remote binary install check for %s: %v\n", lookupName, err)
			return "", "", false, nil
		}
		entryRef, err := GetRemotePackageEntry(lookupName, cfg, index)
		if err != nil {
			return "", "", false, nil
		}
		entry := *entryRef
		if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
			return "", "", false, err
		}
		arch := GetSystemArchForPackage(cfg, entry.Name)
		tarballPath := filepath.Join(BinDir, StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, arch, entry.Variant))
		return entry.Name, tarballPath, true, nil
	}

	version, revision, err := getRepoVersion2(lookupName)
	if err != nil {
		return "", "", false, nil
	}
	outputName := getOutputPackageName(lookupName, cfg)
	if tarballPath := findCachedBinaryTarballVersion(outputName, version, revision, cfg); tarballPath != "" {
		return outputName, tarballPath, true, nil
	}

	variant := GetSystemVariantForPackage(cfg, lookupName)
	if tarballPath, ok, err := fetchExactBinaryTarballIfAvailable(outputName, version, revision, variant, cfg, noRemote); err != nil || ok {
		return outputName, tarballPath, ok, err
	}
	if outputName != lookupName {
		if tarballPath, ok, err := fetchExactBinaryTarballIfAvailable(lookupName, version, revision, variant, cfg, noRemote); err != nil || ok {
			return lookupName, tarballPath, ok, err
		}
	}

	return "", "", false, nil
}

func releaseIsOlder(version, revision, currentVersion, currentRevision string) bool {
	if cmp := compareVersions(version, currentVersion); cmp != 0 {
		return cmp < 0
	}
	return revisionCompare(revision, currentRevision) < 0
}

// availableBuildDependencyBinaryTarball first uses the normal exact-version
// lookup. If the source repository has moved ahead of the binary repository, it
// falls back to the newest older binary. This policy is intentionally limited to
// temporary build dependencies; requested packages still require an exact build.
func availableBuildDependencyBinaryTarball(pkgName string, cfg *Config, noRemote bool) (installName, tarballPath string, ok bool, err error) {
	if installName, tarballPath, ok, err = availableBinaryPackageTarball(pkgName, cfg, noRemote); err != nil || ok {
		return installName, tarballPath, ok, err
	}

	lookupName := pkgName
	if idx := strings.Index(lookupName, "@"); idx != -1 {
		lookupName = lookupName[:idx]
	}
	currentVersion, currentRevision, versionErr := getRepoVersion2(lookupName)
	if versionErr != nil {
		if sourcePkg, _, splitOK := findSplitPackageSource(lookupName); splitOK {
			currentVersion, currentRevision, versionErr = getRepoVersion2(sourcePkg)
		}
	}
	if versionErr != nil {
		return "", "", false, nil
	}

	outputName := getOutputPackageName(lookupName, cfg)
	names := []string{outputName}
	if outputName != lookupName {
		names = append(names, lookupName)
	}
	arch := GetSystemArchForPackage(cfg, lookupName)
	variantRank := make(map[string]int)
	for i, variant := range dependencyVariantCandidates(lookupName, cfg) {
		variantRank[variant] = i
	}

	type candidate struct {
		name, path, version, revision, variant string
		entry                                  *RepoEntry
	}
	var best *candidate
	consider := func(c candidate) {
		if !releaseIsOlder(c.version, c.revision, currentVersion, currentRevision) {
			return
		}
		if _, accepted := variantRank[c.variant]; !accepted {
			return
		}
		if best == nil || compareVersions(c.version, best.version) > 0 ||
			(compareVersions(c.version, best.version) == 0 && revisionCompare(c.revision, best.revision) > 0) ||
			(compareVersions(c.version, best.version) == 0 && revisionCompare(c.revision, best.revision) == 0 && variantRank[c.variant] < variantRank[best.variant]) {
			copy := c
			best = &copy
		}
	}

	for _, name := range names {
		for variant := range variantRank {
			pattern := filepath.Join(BinDir, fmt.Sprintf("%s-*-*-*-%s.tar.zst", name, variant))
			matches, _ := filepath.Glob(pattern)
			for _, match := range matches {
				metadata, _, scanErr := scanTarballMetadata(match)
				if scanErr != nil || metadata["name"] != name {
					continue
				}
				if metadata["arch"] != "" && metadata["arch"] != arch {
					continue
				}
				consider(candidate{name: name, path: match, version: metadata["version"], revision: metadata["revision"], variant: variant})
			}
		}
	}

	if !noRemote && BinaryMirror != "" {
		if index, indexErr := GetCachedRemoteIndex(cfg); indexErr == nil {
			for i := range index {
				entry := &index[i]
				nameMatch := false
				for _, name := range names {
					if entry.Name == name {
						nameMatch = true
						break
					}
				}
				if entry.Type == "meta" || !nameMatch || entry.Arch != arch {
					continue
				}
				consider(candidate{name: entry.Name, version: entry.Version, revision: entry.Revision, variant: entry.Variant, entry: entry})
			}
		}
	}

	if best == nil {
		return "", "", false, nil
	}
	if best.entry != nil {
		entry := best.entry
		if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
			return "", "", false, err
		}
		best.path = filepath.Join(BinDir, StandardizeRemoteName(entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant))
	}
	debugf("Using older binary %s %s-%s as build dependency; repository version is %s-%s\n", best.name, best.version, best.revision, currentVersion, currentRevision)
	return best.name, best.path, true, nil
}

func installAvailableBuildDependencyBinaryWithOptions(pkgName string, cfg *Config, noRemote bool, quiet bool, installRuntimeDeps bool) (bool, error) {
	if isPackageInstalled(pkgName) {
		return false, nil
	}
	installName, tarballPath, ok, err := availableBuildDependencyBinaryTarball(pkgName, cfg, noRemote)
	if err != nil || !ok {
		return false, err
	}
	if !installRuntimeDeps {
		defer suppressRuntimeDependencyAutoInstallScope()()
	}
	return installBinaryTarballWithOptions(tarballPath, installName, cfg, quiet)
}

func installAvailableBinaryPackageOnly(pkgName string, cfg *Config, noRemote bool) (bool, error) {
	return installAvailableBinaryPackageOnlyWithOptions(pkgName, cfg, noRemote, false)
}

func installAvailableBinaryPackageOnlyWithOptions(pkgName string, cfg *Config, noRemote bool, quiet bool) (bool, error) {
	return installAvailableBinaryPackageWithRuntimeDepsOption(pkgName, cfg, noRemote, quiet, false)
}

func installAvailableBinaryPackageWithRuntimeDepsOption(pkgName string, cfg *Config, noRemote bool, quiet bool, installRuntimeDeps bool) (bool, error) {
	if isPackageInstalled(pkgName) {
		return false, nil
	}

	installName, tarballPath, ok, err := availableBinaryPackageTarball(pkgName, cfg, noRemote)
	if err != nil || !ok {
		return false, err
	}

	if !installRuntimeDeps {
		defer suppressRuntimeDependencyAutoInstallScope()()
	}
	return installBinaryTarballWithOptions(tarballPath, installName, cfg, quiet)
}

func requiredDevelPackages(cfg *Config, includeMultilib bool) []string {
	required := append([]string{}, baseDevelPackages...)
	if includeMultilib && multilibEnabled(cfg) {
		required = append(required, multilibDevelPackages...)
	}
	return required
}

func isRequiredDevelPackage(pkgName string, cfg *Config) bool {
	for _, develPkg := range requiredDevelPackages(cfg, true) {
		if pkgName == develPkg || pkgName == getOutputPackageName(develPkg, cfg) {
			return true
		}
	}
	return false
}

func installSourceFallbackBuildDependencies(pkgName string, cfg *Config, noRemote bool) error {
	return installSourceFallbackBuildDependenciesWithOptions(pkgName, cfg, noRemote, false)
}

func installSourceFallbackBuildDependenciesWithOptions(pkgName string, cfg *Config, noRemote bool, quiet bool) error {
	if cfg != nil && cfg.Values["HOKUTO_BOOTSTRAP"] != "1" && !isRequiredDevelPackage(pkgName, cfg) {
		includeMultilib := packageSetHasBuildOption([]string{pkgName}, "multilib")
		if _, err := ensureDevelPackagesInstalledWithOptions(cfg, includeMultilib, noRemote, quiet); err != nil {
			return fmt.Errorf("failed to prepare devel packages for %s: %w", pkgName, err)
		}
	}

	if _, err := installBuildDependenciesWithOptions(pkgName, cfg, noRemote, quiet); err != nil {
		return err
	}
	return nil
}

func ensureDevelPackagesInstalled(cfg *Config, includeMultilib bool, noRemote bool) ([]string, error) {
	return ensureDevelPackagesInstalledWithOptions(cfg, includeMultilib, noRemote, false)
}

func ensureDevelPackagesInstalledWithOptions(cfg *Config, includeMultilib bool, noRemote bool, quiet bool) ([]string, error) {
	develInstallMu.Lock()
	defer develInstallMu.Unlock()

	var missing []string
	for _, pkgName := range requiredDevelPackages(cfg, includeMultilib) {
		if isPackageInstalled(pkgName) {
			continue
		}
		missing = append(missing, pkgName)
	}
	if len(missing) == 0 {
		return nil, nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Installing missing devel packages: %s\n", strings.Join(missing, ", "))

	var newlyInstalled []string
	bar := newDependencyInstallProgress(len(missing), "Installing Build Dependencies", quiet)
	deactivateProgress := activateDependencyInstallProgress(bar)
	defer deactivateProgress()
	for _, pkgName := range missing {
		describeDependencyInstallProgress(bar, pkgName)
		installed, err := installAvailableBuildDependencyBinaryWithOptions(pkgName, cfg, noRemote, quiet, true)
		if err != nil {
			return newlyInstalled, err
		}
		if !installed && !isPackageInstalled(pkgName) {
			return newlyInstalled, fmt.Errorf("required devel package %s has no available binary package; install it manually or build it in bootstrap mode", pkgName)
		}
		advanceDependencyInstallProgress(bar)
		if installed {
			outputName := getOutputPackageName(pkgName, cfg)
			newlyInstalled = append(newlyInstalled, outputName)
		}
	}

	return newlyInstalled, nil
}

// uninstallBuildDependencies uninstalls a list of packages in reverse order.
func uninstallBuildDependencies(packages []string, cfg *Config) {
	uninstallBuildDependenciesWithOptions(packages, cfg, false)
}

func uninstallBuildDependenciesWithOptions(packages []string, cfg *Config, quiet bool) int {
	if len(packages) == 0 {
		return 0
	}
	if activeSessions := otherActiveHokutoBuildSessions(); len(activeSessions) > 0 {
		colArrow.Print("-> ")
		colWarn.Printf("Skipping temporary build dependency cleanup; another Hokuto build is active (pid %s)\n", joinPIDs(activeSessions))
		return 0
	}

	removedCount := 0
	remaining := append([]string(nil), packages...)

	for len(remaining) > 0 {
		removedThisPass := false
		var stillNeeded []string
		removing := make(map[string]bool, len(remaining))
		for _, pkgName := range remaining {
			removing[pkgName] = true
		}

		// Uninstall in reverse order, then retry skipped packages after their
		// temporary dependents may have been removed.
		for i := len(remaining) - 1; i >= 0; i-- {
			pkgName := remaining[i]
			if len(installedDependents(pkgName, cfg, removing)) > 0 {
				stillNeeded = append(stillNeeded, pkgName)
				continue
			}
			logger, _ := dependencyInstallLogger(quiet)
			if !quiet {
				colArrow.Print("-> ")
				colSuccess.Print("Removing build dependency: ")
				colNote.Println(pkgName)
			}
			if err := pkgUninstallWithRemovalSet(pkgName, cfg, RootExec, false, true, logger, removing); err != nil {
				if quiet {
					debugf("Warning: failed to uninstall build dependency %s: %v\n", pkgName, err)
				} else {
					colWarn.Printf("Warning: failed to uninstall build dependency %s: %v\n", pkgName, err)
				}
				continue
			}
			removedCount++
			removeFromWorld(pkgName)
			removeFromWorldMake(pkgName)
			removedThisPass = true
		}

		if !removedThisPass {
			break
		}
		remaining = stillNeeded
	}

	if quiet && removedCount > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("Removed %d temporary build dependencies\n", removedCount)
	}
	return removedCount
}
