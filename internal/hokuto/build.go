package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"archive/tar"
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
	"github.com/ulikunitz/xz"
)

// loadBuildOptions reads the 'options' file from the package directory
// and returns a map of enabled tweaks.
func loadBuildOptions(pkgDir string) map[string]bool {
	options := make(map[string]bool)
	loadOptionsFile(filepath.Join(pkgDir, "options"), options, nil)
	return options
}

func loadOptionsFile(path string, options map[string]bool, allow map[string]bool) {
	loadOptionsFileWithOverrides(path, options, allow, false)
}

// loadOptionsOverrideFile loads additive options and !option removals.
func loadOptionsOverrideFile(path string, options map[string]bool, allow map[string]bool) {
	loadOptionsFileWithOverrides(path, options, allow, true)
}

func loadOptionsFileWithOverrides(path string, options map[string]bool, allow map[string]bool, allowOverrides bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, field := range strings.Fields(line) {
			disable := allowOverrides && strings.HasPrefix(field, "!")
			option := field
			if disable {
				option = strings.TrimPrefix(field, "!")
			}
			if option == "" || (allow != nil && !allow[option]) {
				continue
			}
			if disable {
				delete(options, option)
				continue
			}
			options[option] = true
		}
	}
}

var splitPostBuildOptions = map[string]bool{
	"nostrip":    true,
	"staticlibs": true,
}

func loadSplitPackagePostBuildOptions(pkgDir, splitName, outputSplitName string, parentOptions map[string]bool) map[string]bool {
	options := maps.Clone(parentOptions)
	candidates := []string{splitName}
	if outputSplitName != "" && outputSplitName != splitName {
		candidates = append(candidates, outputSplitName)
	}
	for _, name := range candidates {
		loadOptionsOverrideFile(filepath.Join(pkgDir, "options."+name), options, splitPostBuildOptions)
	}
	return options
}

func packageSetHasBuildOption(pkgNames []string, option string) bool {
	for _, pkgName := range pkgNames {
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			debugf("Skipping %s option check for %s: %v\n", option, pkgName, err)
			continue
		}
		if loadBuildOptions(pkgDir)[option] {
			return true
		}
	}
	return false
}

func packageSetNeedsDevelPackages(pkgNames []string) bool {
	for _, pkgName := range pkgNames {
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			// Be conservative when recipe metadata cannot be inspected.
			debugf("Unable to check binary/nodevel options for %s: %v\n", pkgName, err)
			return true
		}
		options := loadBuildOptions(pkgDir)
		if !options["binary"] && !options["nodevel"] {
			return true
		}
	}
	return false
}

func missingDevelPackagesForBuildSet(cfg *Config, pkgNames []string) []string {
	if !packageSetNeedsDevelPackages(pkgNames) {
		return nil
	}
	return missingDevelPackagesForBuild(cfg, packageSetHasBuildOption(pkgNames, "multilib"))
}

func buildPackageNames(packageSet map[string]bool) []string {
	pkgNames := make([]string, 0, len(packageSet))
	for pkgName := range packageSet {
		pkgNames = append(pkgNames, pkgName)
	}
	sort.Strings(pkgNames)
	return pkgNames
}

func missingDevelPackagesForBuild(cfg *Config, includeMultilib bool) []string {
	var missing []string
	for _, pkgName := range requiredDevelPackages(cfg, includeMultilib) {
		if !isPackageInstalled(pkgName) {
			missing = append(missing, getOutputPackageName(pkgName, cfg))
		}
	}
	sort.Strings(missing)
	return missing
}

func appendUniquePackage(pkgNames []string, seen map[string]bool, pkgName string) []string {
	if pkgName == "" || seen[pkgName] {
		return pkgNames
	}
	seen[pkgName] = true
	return append(pkgNames, pkgName)
}

func plannedBinaryInstallsForMissingDeps(missingDeps []string, forceBuildMap map[string]bool, cfg *Config, noRemote bool) []string {
	seen := make(map[string]bool)
	var installs []string
	for _, depPkg := range missingDeps {
		if forceBuildMap[depPkg] {
			continue
		}
		if _, err := findPackageMetadataDir(depPkg); err != nil {
			if isPackageInstalled(depPkg) {
				continue
			}
			if _, ok := findSplitDependencySource(depPkg); ok && dependencyBinaryAvailable(depPkg, cfg, noRemote) {
				installs = appendUniquePackage(installs, seen, depPkg)
				continue
			}
			if dependencyBinaryAvailable(depPkg, cfg, noRemote) {
				installs = appendUniquePackage(installs, seen, getOutputPackageName(depPkg, cfg))
			}
			continue
		}

		version, revision, err := getRepoVersion2(depPkg)
		if err != nil {
			continue
		}
		outputDepPkg := getOutputPackageName(depPkg, cfg)
		if tarballPath := findCachedBinaryTarballVersion(outputDepPkg, version, revision, cfg); tarballPath != "" {
			installs = appendUniquePackage(installs, seen, outputDepPkg)
			continue
		}
		if dependencyBinaryAvailable(depPkg, cfg, noRemote) {
			installs = appendUniquePackage(installs, seen, outputDepPkg)
		}
	}
	sort.Strings(installs)
	return installs
}

func previewBuildSetForMissingDeps(missingDeps []string, forceBuildMap map[string]bool, cfg *Config, noRemote bool) map[string]bool {
	buildSet := make(map[string]bool)
	for pkgName := range forceBuildMap {
		buildSet[pkgName] = true
	}
	for _, depPkg := range missingDeps {
		if buildSet[depPkg] {
			continue
		}
		if _, err := findPackageMetadataDir(depPkg); err != nil {
			if isPackageInstalled(depPkg) {
				continue
			}
			if sourcePkg, ok := findSplitDependencySource(depPkg); ok {
				if !dependencyBinaryAvailable(depPkg, cfg, noRemote) {
					buildSet[sourcePkg] = true
				}
				continue
			}
			if !dependencyBinaryAvailable(depPkg, cfg, noRemote) {
				buildSet[depPkg] = true
			}
			continue
		}

		version, revision, err := getRepoVersion2(depPkg)
		if err == nil {
			outputDepPkg := getOutputPackageName(depPkg, cfg)
			if tarballPath := findCachedBinaryTarballVersion(outputDepPkg, version, revision, cfg); tarballPath != "" {
				continue
			}
		}
		if !dependencyBinaryAvailable(depPkg, cfg, noRemote) {
			buildSet[depPkg] = true
		}
	}
	return buildSet
}

func confirmBuildPlanWithAsk(buildOrder []string, depsToInstall []string, postRebuilds map[string][]string) bool {
	colArrow.Print("-> ")
	colSuccess.Println("Build preview (--ask)")

	if len(buildOrder) == 0 {
		colArrow.Print("-> ")
		colNote.Println("Packages to build: none")
	} else {
		colArrow.Print("-> ")
		colNote.Printf("Packages to build (%d): %s\n", len(buildOrder), strings.Join(buildOrder, " -> "))
	}

	if len(depsToInstall) == 0 {
		colArrow.Print("-> ")
		colNote.Println("Dependencies to install: none")
	} else {
		seenDeps := make(map[string]bool)
		sortedDeps := make([]string, 0, len(depsToInstall))
		for _, dep := range depsToInstall {
			sortedDeps = appendUniquePackage(sortedDeps, seenDeps, dep)
		}
		sort.Strings(sortedDeps)
		colArrow.Print("-> ")
		colNote.Printf("Dependencies to install (%d): %s\n", len(sortedDeps), strings.Join(sortedDeps, ", "))
	}

	if len(postRebuilds) > 0 {
		var rebuilds []string
		for parent, deps := range postRebuilds {
			rebuilds = append(rebuilds, fmt.Sprintf("%s (for %s)", parent, strings.Join(deps, ",")))
		}
		sort.Strings(rebuilds)
		colArrow.Print("-> ")
		colWarn.Printf("Inline rebuilds: %s\n", strings.Join(rebuilds, ", "))
	}

	return askForConfirmationDefaultNo(colWarn, "Proceed with build?")
}

func printResolvedBuildSummary(plan *BuildPlan) {
	buildOrder := append([]string(nil), plan.Order...)
	colArrow.Print("-> ")
	colSuccess.Printf("Packages to build (%d):", len(buildOrder))
	colNote.Printf(" %s\n", strings.Join(buildOrder, " -> "))

	var rebuilds []string
	for parent, deps := range plan.PostRebuilds {
		rebuilds = append(rebuilds, fmt.Sprintf("%s (for %s)", parent, strings.Join(deps, ",")))
	}
	for trigger, packages := range plan.PostBuildRebuilds {
		for _, pkgName := range packages {
			rebuilds = append(rebuilds, fmt.Sprintf("%s (after %s)", pkgName, trigger))
		}
	}
	sort.Strings(rebuilds)
	if len(rebuilds) > 0 {
		colArrow.Print("-> ")
		colWarn.Printf("Rebuilds (%d): %s\n", len(rebuilds), strings.Join(rebuilds, ", "))
	}
}

func resolveRequestedBuildTarget(pkgName string) (sourcePkg string, split bool, err error) {
	if sourcePkg, _, ok := findSplitPackageSource(pkgName); ok {
		return sourcePkg, true, nil
	}
	if _, err := findPackageDir(pkgName); err == nil {
		return pkgName, false, nil
	}
	return "", false, fmt.Errorf("package not found in any repository")
}

func activeBuildDependency(dep DepSpec, cfg *Config, includeOptional bool) bool {
	if dep.RuntimeOnly || dep.Suggest {
		return false
	}
	if dep.Optional && !includeOptional {
		return false
	}
	if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
		return false
	}
	if dep.CrossNative && (cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1") {
		return false
	}
	if shouldSkipMultilibMakeDep(dep, dep.Name, cfg) {
		return false
	}
	return true
}

func plannedBuildDisplayOrder(plan *BuildPlan, cfg *Config, noRemote bool) []string {
	remaining := append([]string{}, plan.Order...)
	built := make(map[string]bool, len(plan.Order))
	inPlan := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inPlan[pkgName] = true
	}
	var display []string

	postRebuilds := make(map[string][]string, len(plan.PostRebuilds))
	for parent, deps := range plan.PostRebuilds {
		postRebuilds[parent] = append([]string{}, deps...)
	}

	addReadyRebuilds := func() {
		if len(postRebuilds) == 0 {
			return
		}
		parents := make([]string, 0, len(postRebuilds))
		for parent := range postRebuilds {
			parents = append(parents, parent)
		}
		sort.Strings(parents)
		for _, parent := range parents {
			if !built[parent] {
				continue
			}
			deps := postRebuilds[parent]
			allBuilt := true
			for _, dep := range deps {
				depBuilt := built[dep]
				if !depBuilt {
					if sourcePkg, ok := findSplitDependencySource(dep); ok && built[sourcePkg] {
						depBuilt = true
					}
				}
				if !depBuilt {
					allBuilt = false
					break
				}
			}
			if !allBuilt {
				continue
			}
			display = append(display, fmt.Sprintf("%s (rebuild for %s)", parent, strings.Join(deps, ",")))
			delete(postRebuilds, parent)
		}
	}

	depAvailable := func(dep DepSpec) bool {
		candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
		if err != nil {
			return false
		}
		for _, name := range candidates {
			depBuilt := built[name]
			if !depBuilt {
				if sourcePkg, ok := findSplitDependencySource(name); ok && built[sourcePkg] {
					depBuilt = true
				}
			}
			if depBuilt || findInstalledSatisfying(name, dep.Op, dep.Version) != "" {
				return true
			}
			if !inPlan[name] && dependencyBinaryAvailable(name, cfg, noRemote) {
				return true
			}
		}
		return false
	}

	canBuild := func(pkgName string) bool {
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			return true
		}
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			return true
		}
		for _, dep := range deps {
			if !activeBuildDependency(dep, cfg, false) {
				continue
			}
			if !depAvailable(dep) {
				return false
			}
		}
		return true
	}

	for len(remaining) > 0 {
		progress := false
		var next []string
		for _, pkgName := range remaining {
			if !canBuild(pkgName) {
				next = append(next, pkgName)
				continue
			}
			display = append(display, pkgName)
			built[pkgName] = true
			addReadyRebuilds()
			progress = true
		}
		if !progress {
			display = append(display, next...)
			break
		}
		remaining = next
	}

	return display
}

func addMappedSplitDependency(splitDepsBySource map[string][]string, sourcePkg, splitPkg string) {
	if sourcePkg == "" || splitPkg == "" {
		return
	}
	for _, existing := range splitDepsBySource[sourcePkg] {
		if existing == splitPkg {
			return
		}
	}
	splitDepsBySource[sourcePkg] = append(splitDepsBySource[sourcePkg], splitPkg)
}

func addPostRebuildSplitDependencies(plan *BuildPlan, splitDepsBySource map[string][]string) {
	if len(plan.PostRebuilds) == 0 {
		return
	}
	inOrder := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inOrder[pkgName] = true
	}
	for _, deps := range plan.PostRebuilds {
		for _, dep := range deps {
			sourcePkg, ok := findSplitDependencySource(dep)
			if !ok || !inOrder[sourcePkg] {
				continue
			}
			addMappedSplitDependency(splitDepsBySource, sourcePkg, dep)
		}
	}
}

func collectSplitDependenciesForPlan(plan *BuildPlan, cfg *Config) map[string][]string {
	splitDepsBySource := make(map[string][]string)
	if plan == nil {
		return splitDepsBySource
	}

	inPlan := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inPlan[pkgName] = true
	}

	for _, pkgName := range plan.Order {
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			continue
		}
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if !activeBuildDependency(dep, cfg, false) {
				continue
			}
			candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
			if err != nil {
				continue
			}
			for _, cand := range candidates {
				if shouldSkipMultilibMakeDep(dep, cand, cfg) {
					continue
				}
				sourcePkg, ok := findSplitDependencySource(cand)
				if !ok || !inPlan[sourcePkg] {
					continue
				}
				addMappedSplitDependency(splitDepsBySource, sourcePkg, cand)
			}
		}
	}

	addPostRebuildSplitDependencies(plan, splitDepsBySource)
	return splitDepsBySource
}

func installBuiltSplitDependencyWithOptions(sourcePkg, splitPkg string, cfg *Config, quiet bool) error {
	logger, fast := dependencyInstallLogger(quiet)
	return installBuiltSplitDependencyWithLogger(sourcePkg, splitPkg, cfg, logger, fast)
}

func installBuiltSplitDependencyWithLogger(sourcePkg, splitPkg string, cfg *Config, logger io.Writer, fast bool) error {
	return installBuiltSplitPackageWithLogger(sourcePkg, splitPkg, cfg, logger, fast, false)
}

func installBuiltSplitTargetWithLogger(sourcePkg, splitPkg string, cfg *Config, logger io.Writer, fast bool) error {
	return installBuiltSplitPackageWithLogger(sourcePkg, splitPkg, cfg, logger, fast, true)
}

func installBuiltSplitPackageWithLogger(sourcePkg, splitPkg string, cfg *Config, logger io.Writer, fast bool, force bool) error {
	if !force && isPackageInstalled(splitPkg) {
		return nil
	}
	version, revision, err := getRepoVersion2(sourcePkg)
	if err != nil {
		return err
	}
	pkgDir, err := findPackageMetadataDir(sourcePkg)
	if err != nil {
		return err
	}
	options := loadBuildOptions(pkgDir)
	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]
	arch := GetSystemArchForPackage(cfg, sourcePkg)
	variant := IdentifyVariant(splitPkg, isGeneric, isMultilibPackage(splitPkg))
	archiveSplitName := canonicalParallelPackageName(splitPkg)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveSplitName, version, revision, arch, variant))
	if _, err := os.Stat(tarballPath); err != nil {
		return fmt.Errorf("expected split package tarball missing: %s", tarballPath)
	}

	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)
	installExec := RootExec
	if logger != nil {
		installExec = &Executor{
			Context:         RootExec.Context,
			ShouldRunAsRoot: RootExec.ShouldRunAsRoot,
			Interactive:     false,
			Stdout:          logger,
			Stderr:          logger,
		}
	}
	handlePreInstallUninstall(splitPkg, cfg, installExec, true, logger)
	if _, err := pkgInstall(tarballPath, splitPkg, cfg, installExec, true, fast, false, logger); err != nil {
		return err
	}
	return nil
}

func useAvailableBuildDependencyBinary(prompt bool, format string, args ...any) bool {
	if !prompt {
		return true
	}
	return askForConfirmation(colInfo, format, args...)
}

func packageHasSelfBuildDependency(pkgName string, cfg *Config) bool {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return false
	}
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return false
	}
	for _, dep := range deps {
		if !dep.Make || !activeBuildDependency(dep, cfg, false) {
			continue
		}
		candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			// Historical sources are planned as pkg-MAJOR while their depends
			// files retain the canonical constraint (for example,
			// java-openjdk-17 depending on java-openjdk==17*).
			if candidate == pkgName {
				return true
			}
		}
	}
	return false
}

func installAvailableBinaryBuildDeps(plan *BuildPlan, userRequested, declined map[string]bool, cfg *Config, addTemporaryBuildDep func(string), noRemote bool, prompt bool, quiet bool) (bool, error) {
	installedAny := false
	type binaryBuildDep struct {
		name          string
		outputPkgName string
		tarballPath   string
		selfBootstrap bool
	}
	var candidates []binaryBuildDep
	for _, pkgName := range plan.Order {
		selfBuildDependency := userRequested[pkgName] && packageHasSelfBuildDependency(pkgName, cfg)
		if (userRequested[pkgName] && !selfBuildDependency) || declined[pkgName] || plan.RebuildPackages[pkgName] || isPackageInstalled(pkgName) {
			continue
		}

		outputPkgName, tarballPath, ok, err := availableBuildDependencyBinaryTarball(pkgName, cfg, noRemote)
		if err != nil || !ok {
			continue
		}

		candidates = append(candidates, binaryBuildDep{
			name:          pkgName,
			outputPkgName: outputPkgName,
			tarballPath:   tarballPath,
			selfBootstrap: selfBuildDependency,
		})
	}

	bar := newDependencyInstallProgress(len(candidates), "Installing Build Dependencies", quiet && !prompt)
	deactivateProgress := activateDependencyInstallProgress(bar)
	defer deactivateProgress()
	for _, cand := range candidates {
		if !useAvailableBuildDependencyBinary(prompt, "Dependency '%s' is missing. Use available binary package?", cand.name) {
			declined[cand.name] = true
			advanceDependencyInstallProgress(bar)
			continue
		}

		describeDependencyInstallProgress(bar, cand.outputPkgName)
		isCriticalAtomic.Store(1)
		logger, fast := dependencyInstallLogger(quiet)
		handlePreInstallUninstall(cand.outputPkgName, cfg, RootExec, false, logger)
		if _, err := pkgInstall(cand.tarballPath, cand.outputPkgName, cfg, RootExec, false, fast, false, logger); err != nil {
			isCriticalAtomic.Store(0)
			return installedAny, fmt.Errorf("fatal error installing binary %s: %w", cand.name, err)
		}
		isCriticalAtomic.Store(0)
		advanceDependencyInstallProgress(bar)
		if !cand.selfBootstrap {
			addTemporaryBuildDep(cand.outputPkgName)
		}
		declined[cand.name] = true
		installedAny = true
	}
	return installedAny, nil
}

// getScriptExitCode extracts the exit code from a script log file
// script writes: "Script done on ... [COMMAND_EXIT_CODE="1"]"
// Returns 0 if exit code cannot be determined (assume success)
func getScriptExitCode(logPath string) int {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return 0 // Can't read file, assume success
	}

	content := string(data)
	// Look for COMMAND_EXIT_CODE="N" pattern
	idx := strings.LastIndex(content, "COMMAND_EXIT_CODE=\"")
	if idx == -1 {
		return 0 // Pattern not found, assume success
	}

	// Extract the exit code
	start := idx + len("COMMAND_EXIT_CODE=\"")
	end := strings.Index(content[start:], "\"")
	if end == -1 {
		return 0 // Malformed, assume success
	}

	exitCodeStr := content[start : start+end]
	exitCode := 0
	fmt.Sscanf(exitCodeStr, "%d", &exitCode)
	return exitCode
}

// sanitizeFlagsForCrossCompilation removes -march=native and -mtune=native from flags
// and replaces them with appropriate target architecture flags when cross-compiling
func sanitizeFlagsForCrossCompilation(flags string, _ string) string {
	if flags == "" {
		return flags
	}

	// Split flags into individual tokens to handle them properly
	flagList := strings.Fields(flags)
	var sanitizedFlags []string

	// Remove -march=native and -mtune=native, and also remove any x86-64 specific flags
	for _, flag := range flagList {
		if flag == "-march=native" || flag == "-mtune=native" {
			continue // Skip these flags
		}
		// Also remove x86-64 specific flags when cross-compiling
		if strings.HasPrefix(flag, "-march=x86-64-v2") || strings.HasPrefix(flag, "-march=x86_64-v2") {
			continue
		}
		sanitizedFlags = append(sanitizedFlags, flag)
	}

	flags = strings.Join(sanitizedFlags, " ")

	// If cross-compiling to ARM64, we do NOT add specific flags anymore.
	// The build script might use the host compiler, which wouldn't understand -march=armv8-a if the host is x86.
	// We want generic flags only.

	return strings.TrimSpace(flags)
}

// getOutputPackageName returns the output package name, which may be renamed for cross-system builds
func getOutputPackageName(pkgName string, cfg *Config) string {
	// Only apply renaming for cross-system builds (system-wide toolchain packages)
	// cross-simple is just a build strategy and shouldn't affect the output package name
	if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" && cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		// Rename package for cross-system builds: aarch64-pkgname
		normalizedArch := cfg.Values["HOKUTO_CROSS_ARCH"]
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		prefix := normalizedArch + "-"
		if strings.HasPrefix(pkgName, prefix) {
			return pkgName
		}
		return prefix + pkgName
	}
	return pkgName
}

// getArchivePackageName returns the stable package identity used by binary
// archives and the remote index. Historical pkg-MAJOR names exist only while
// planning/building and after installation; they do not alter archive names.
func getArchivePackageName(pkgName string, cfg *Config) string {
	if baseName := canonicalParallelPackageName(pkgName); baseName != pkgName {
		pkgName = baseName
	}
	return getOutputPackageName(pkgName, cfg)
}

func sameSourcePackage(a, b string) bool {
	return canonicalParallelPackageName(a) == canonicalParallelPackageName(b)
}

func registerParallelPackageName(installName, archiveName string) {
	if installName == "" || archiveName == "" || installName == archiveName {
		return
	}
	versionedPkgBaseMu.Lock()
	versionedPkgBaseNames[installName] = archiveName
	versionedPkgBaseMu.Unlock()
}

func registerParallelPackageVersion(installName, version string) {
	if installName == "" || version == "" {
		return
	}
	versionedPkgBaseMu.Lock()
	versionedPkgVersions[installName] = version
	versionedPkgBaseMu.Unlock()
}

func parallelPackageVersion(name string) string {
	versionedPkgBaseMu.RLock()
	version := versionedPkgVersions[name]
	versionedPkgBaseMu.RUnlock()
	return version
}

func canonicalParallelPackageName(name string) string {
	versionedPkgBaseMu.RLock()
	baseName := versionedPkgBaseNames[name]
	versionedPkgBaseMu.RUnlock()
	if baseName != "" {
		return baseName
	}
	if data, err := os.ReadFile(filepath.Join(Installed, name, "pkginfo")); err == nil {
		if installedName := ParsePkgInfo(data)["name"]; installedName != "" {
			return installedName
		}
	}
	return name
}

func parallelInstallPackageName(pkgName, version string, cfg *Config) string {
	outputName := getOutputPackageName(pkgName, cfg)
	major := strings.SplitN(strings.TrimSpace(version), ".", 2)[0]
	if major == "" {
		return outputName
	}
	if _, err := strconv.Atoi(major); err != nil {
		return outputName
	}
	installName := outputName + "-" + major
	registerParallelPackageName(installName, outputName)
	registerParallelPackageVersion(installName, version)
	return installName
}

// buildRustFlags constructs RUSTFLAGS based on CFLAGS and CPU flags
// This mirrors the C/C++ optimization strategy for Rust builds
func buildRustFlags(cflags string, cpuFlags string, buildDir string, isGeneric bool) string {
	// Always include path remapping for reproducible builds
	rustflags := fmt.Sprintf("--remap-path-prefix=%s=.", buildDir)

	// In generic mode, use generic target-cpu
	if isGeneric {
		return rustflags
	}

	// Parse CFLAGS to extract -march and -mtune values
	var targetCPU string

	// Check for -march flag in CFLAGS
	if strings.Contains(cflags, "-march=native") {
		targetCPU = "native"
	} else if strings.Contains(cflags, "-march=") {
		// Extract specific march value (e.g., -march=alderlake, -march=x86-64-v3)
		parts := strings.Fields(cflags)
		for _, part := range parts {
			if strings.HasPrefix(part, "-march=") {
				marchValue := strings.TrimPrefix(part, "-march=")
				// Map GCC march values to Rust target-cpu values
				switch {
				// x86-64 variants
				case marchValue == "x86-64":
					targetCPU = "x86-64"
				case marchValue == "x86-64-v2":
					targetCPU = "x86-64-v2"
				case marchValue == "x86-64-v3":
					targetCPU = "x86-64-v3"
				case marchValue == "x86-64-v4":
					targetCPU = "x86-64-v4"
				// x86 specific CPUs
				case marchValue == "alderlake":
					targetCPU = "alderlake"
				case marchValue == "skylake":
					targetCPU = "skylake"
				case marchValue == "haswell":
					targetCPU = "haswell"
				case marchValue == "broadwell":
					targetCPU = "broadwell"
				case marchValue == "znver1":
					targetCPU = "znver1"
				case marchValue == "znver2":
					targetCPU = "znver2"
				case marchValue == "znver3":
					targetCPU = "znver3"
				case marchValue == "znver4":
					targetCPU = "znver4"
				case marchValue == "generic":
					targetCPU = "generic"
				// ARM march values - Rust doesn't support GCC-style ARM march values
				case strings.HasPrefix(marchValue, "armv8"):
					// armv8-a, armv8-a+crc, etc. -> use cortex-a72 for Raspberry Pi 4
					// This provides proper optimizations for ARMv8-A architecture
					targetCPU = "cortex-a72"
				case marchValue == "cortex-a72", marchValue == "cortex-a53", marchValue == "cortex-a57":
					// Specific ARM cores
					targetCPU = "cortex-a72"
				default:
					// For unknown values, don't set target-cpu
					targetCPU = ""
				}
				break
			}
		}
	}

	// If we found a target CPU from march, use it
	if targetCPU != "" && targetCPU != "generic" {
		rustflags = fmt.Sprintf("-C target-cpu=%s %s", targetCPU, rustflags)
	}

	// Add CPU feature flags if specified
	// Convert CPU_FLAGS_X86 format (space-separated) to Rust target-feature format
	if cpuFlags != "" {
		features := strings.Fields(cpuFlags)
		if len(features) > 0 {
			var rustFeatures []string
			for _, feature := range features {
				// Map x86 CPU flags to Rust target features
				switch feature {
				case "aes":
					rustFeatures = append(rustFeatures, "+aes")
				case "avx":
					rustFeatures = append(rustFeatures, "+avx")
				case "avx2":
					rustFeatures = append(rustFeatures, "+avx2")
				case "fma":
					rustFeatures = append(rustFeatures, "+fma")
				case "pclmul", "pclmulqdq":
					rustFeatures = append(rustFeatures, "+pclmulqdq")
				case "popcnt":
					rustFeatures = append(rustFeatures, "+popcnt")
				case "sha":
					rustFeatures = append(rustFeatures, "+sha")
				case "sse":
					rustFeatures = append(rustFeatures, "+sse")
				case "sse2":
					rustFeatures = append(rustFeatures, "+sse2")
				case "sse3":
					rustFeatures = append(rustFeatures, "+sse3")
				case "sse4_1", "sse4.1":
					rustFeatures = append(rustFeatures, "+sse4.1")
				case "sse4_2", "sse4.2":
					rustFeatures = append(rustFeatures, "+sse4.2")
				case "ssse3":
					rustFeatures = append(rustFeatures, "+ssse3")
				// ARM features
				case "neon":
					rustFeatures = append(rustFeatures, "+neon")
				case "crypto":
					rustFeatures = append(rustFeatures, "+crypto")
				case "crc":
					rustFeatures = append(rustFeatures, "+crc")
				// Skip mmx as it's legacy and not typically used in Rust
				case "mmx":
					continue
				}
			}

			if len(rustFeatures) > 0 {
				featureString := strings.Join(rustFeatures, ",")
				rustflags = fmt.Sprintf("-C target-feature=%s %s", featureString, rustflags)
			}
		}
	}

	return rustflags
}

// BuildOptions encapsulates parameters for the build process
type BuildOptions struct {
	Bootstrap     bool
	CurrentIndex  int
	TotalCount    int
	Quiet         bool      // If true, suppress standard output logging (except errors/warnings)
	LogWriter     io.Writer // Optional: redirect output to this writer (e.g., for parallel builds)
	UpdateWebsite bool      // If true, update the github.io status table
}

// reserveBuildTempDir atomically claims the first available numbered build
// directory. Mkdir is the reservation, so parallel builds of the same package
// cannot select the same path.
func reserveBuildTempDir(parent, pkgName string) (string, error) {
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("failed to create build temporary directory %s: %w", parent, err)
	}
	for suffix := 1; ; suffix++ {
		path := filepath.Join(parent, fmt.Sprintf("%s-%02d", pkgName, suffix))
		if err := os.Mkdir(path, 0o755); err == nil {
			return path, nil
		} else if !os.IsExist(err) {
			return "", fmt.Errorf("failed to reserve build temporary directory %s: %w", path, err)
		}
	}
}

func formatBuildDependency(dep DepSpec) string {
	name := dep.Name
	if len(dep.Alternatives) > 0 {
		name = strings.Join(dep.Alternatives, "|")
	}
	if dep.Op != "" && dep.Version != "" {
		name += dep.Op + dep.Version
	}
	return name
}

func buildLogDependencies(pkgDir string, cfg *Config, optionalState optionalBuildSnapshot) (declared, installed []string) {
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return []string{"<unavailable: " + err.Error() + ">"}, nil
	}
	seenInstalled := make(map[string]bool)
	addInstalled := func(name string) {
		if name == "" || seenInstalled[name] {
			return
		}
		version, revision, err := getInstalledVersionAndRevision(name)
		if err != nil {
			return
		}
		seenInstalled[name] = true
		installed = append(installed, fmt.Sprintf("%s-%s-%s", name, version, revision))
	}
	options := loadBuildOptions(pkgDir)
	for _, develPkg := range requiredDevelPackages(cfg, options["multilib"]) {
		installedName := getOutputPackageName(develPkg, cfg)
		if !checkPackageExactMatch(installedName) {
			installedName = findInstalledPackageVariant(installedName)
		}
		addInstalled(installedName)
	}
	for _, dep := range deps {
		if dep.Optional {
			if !activeBuildDependency(dep, cfg, true) {
				continue
			}
			optionalInstalled := optionalState.Present[formatBuildDependency(dep)]
			if len(optionalInstalled) == 0 {
				continue
			}
			declared = append(declared, formatBuildDependency(dep))
			for _, installedName := range optionalInstalled {
				addInstalled(installedName)
			}
			continue
		}
		if !activeBuildDependency(dep, cfg, false) {
			continue
		}
		declared = append(declared, formatBuildDependency(dep))
		candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
		if err != nil {
			continue
		}
		for _, candidate := range candidates {
			installedName := candidate
			if dep.Op != "" && dep.Version != "" {
				installedName = findInstalledSatisfying(candidate, dep.Op, dep.Version)
			} else if !checkPackageExactMatch(candidate) {
				installedName = findInstalledPackageVariant(candidate)
			}
			addInstalled(installedName)
		}
	}
	sort.Strings(installed)
	return declared, installed
}

func writeBuildLogHeader(path, pkgName, version, revision string, started time.Time, declared, installed []string) error {
	declaredText := "(none)"
	if len(declared) > 0 {
		declaredText = strings.Join(declared, " ")
	}
	installedText := "(none)"
	if len(installed) > 0 {
		installedText = strings.Join(installed, " ")
	}
	var b strings.Builder
	prefix := colArrow.Sprint(">>> ")
	packageText := colNote.Sprint(pkgName)
	fmt.Fprintf(&b, "%s%s%s%s%s%s\r\n",
		prefix,
		packageText,
		colSuccess.Sprint(": Building "),
		colNote.Sprintf("%s %s-%s", pkgName, version, revision),
		colSuccess.Sprint(" started "),
		colNote.Sprint(started.UTC().Format(time.RFC1123Z)))
	fmt.Fprintf(&b, "%s%s%s%s\r\n",
		prefix, packageText, colSuccess.Sprint(": Installing for build: "), colNote.Sprint(declaredText))
	fmt.Fprintf(&b, "%s%s%s%s\r\n\r\n",
		prefix, packageText, colSuccess.Sprint(": Installed build dependencies: "), colNote.Sprint(installedText))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func appendBuildLogStatus(path, pkgName, status string, started time.Time, execCtx *Executor) error {
	elapsed := time.Since(started).Truncate(time.Second)
	line := fmt.Sprintf("\r\n%s%s%s%s%s%s%s%s\r\n",
		colArrow.Sprint(">>> "),
		colNote.Sprint(pkgName),
		colSuccess.Sprint(": Build "),
		colNote.Sprint(status),
		colSuccess.Sprint(" at "),
		colNote.Sprint(time.Now().UTC().Format(time.RFC1123Z)),
		colSuccess.Sprint(" elapsed time "),
		colNote.Sprint(elapsed))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err == nil {
		_, writeErr := io.WriteString(f, line)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}
	if execCtx == nil || !execCtx.ShouldRunAsRoot {
		return err
	}
	cmd := exec.Command("tee", "-a", path)
	cmd.Stdin = strings.NewReader(line)
	cmd.Stdout = io.Discard
	return execCtx.Run(cmd)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func writeBuildHelperScripts(helperDir string) error {
	if err := os.MkdirAll(helperDir, 0o755); err != nil {
		return err
	}
	pickPath := filepath.Join(helperDir, "_pick")
	pickScript := `#!/bin/sh
if [ "$#" -lt 2 ]; then
    echo "usage: _pick [--destdir DIR] <split-package> <path>..." >&2
    echo "       _pick <destdir> <split-package> <path>..." >&2
    exit 2
fi

source_root=""
case "$1" in
    --destdir|-d)
        if [ "$#" -lt 4 ]; then
            echo "_pick: --destdir requires DIR, split package, and path(s)" >&2
            exit 2
        fi
        source_root="$2"
        shift 2
        ;;
    *)
        if [ "$#" -ge 3 ] && [ -d "$1" ]; then
            source_root="$1"
            shift
        fi
        ;;
esac

split_name="$1"
shift

if [ -z "${HOKUTO_SPLIT_DIR:-}" ]; then
    echo "_pick: HOKUTO_SPLIT_DIR is not set" >&2
    exit 2
fi

if [ -n "$source_root" ]; then
    if [ ! -d "$source_root" ]; then
        echo "_pick: destdir does not exist: $source_root" >&2
        exit 2
    fi
    source_root="$(cd "$source_root" && pwd -P)"
fi

for pattern in "$@"; do
    if [ -n "$source_root" ]; then
        case "$pattern" in
            /*) search="$pattern" ;;
            *) search="$source_root/$pattern" ;;
        esac
    else
        case "$pattern" in
            /*) search="$pattern" ;;
            *) search="$PWD/$pattern" ;;
        esac
    fi

    for src in $search; do
        # A globbed SONAME chain may become temporarily dangling as its target
        # is moved earlier in this loop. Preserve symlinks even when -e is
        # false so split packages receive the complete chain.
        [ -e "$src" ] || [ -L "$src" ] || continue

        if [ -n "$source_root" ]; then
            case "$src" in
                "$source_root"/*) rel="${src#"$source_root"/}" ;;
                *) rel="${src#/}" ;;
            esac
        elif [ -n "${HOKUTO_OUTPUT_DIR:-}" ]; then
            case "$src" in
                "$HOKUTO_OUTPUT_DIR"/*) rel="${src#"$HOKUTO_OUTPUT_DIR"/}" ;;
                *) rel="${src#"$PWD"/}"; rel="${rel#/}" ;;
            esac
        else
            rel="${src#"$PWD"/}"
            rel="${rel#/}"
        fi

        d="$HOKUTO_SPLIT_DIR/$split_name/$rel"
        mkdir -p "$(dirname "$d")"
        mv -v "$src" "$d"
        rmdir -p --ignore-fail-on-non-empty "$(dirname "$src")" 2>/dev/null || true
    done

done
`
	if err := os.WriteFile(pickPath, []byte(pickScript), 0o755); err != nil {
		return err
	}

	mesonPath := filepath.Join(helperDir, "hokuto-meson")
	mesonScript := `#!/bin/sh
set -e

for arg in "$@" .; do
    case "$arg" in
        -*) continue ;;
    esac
    if [ -d "$arg" ] && [ -f "$arg/meson.build" ]; then
        if command -v hokuto-meson-check-wraps >/dev/null 2>&1; then
            hokuto-meson-check-wraps "$arg"
        fi
        break
    fi
done

set -x
exec meson setup \
    --prefix /usr \
    --libexecdir lib \
    --sbindir bin \
    --buildtype plain \
    --wrap-mode nodownload \
    -D b_pie=true \
	-D b_ndebug=true \
    -D python.bytecompile=1 \
    "$@"
`
	if err := os.WriteFile(mesonPath, []byte(mesonScript), 0o755); err != nil {
		return err
	}

	meson32Path := filepath.Join(helperDir, "hokuto-meson-32")
	meson32Script := `#!/bin/sh
set -e

for arg in "$@" .; do
    case "$arg" in
        -*) continue ;;
    esac
    if [ -d "$arg" ] && [ -f "$arg/meson.build" ]; then
        if command -v hokuto-meson-check-wraps >/dev/null 2>&1; then
            hokuto-meson-check-wraps "$arg"
        fi
        break
    fi
done

set -x
exec meson setup \
    --prefix /usr \
    --libexecdir lib32 \
    --sbindir bin \
    --buildtype plain \
    --wrap-mode nodownload \
    --cross-file lib32 \
    -D b_pie=true \
	-D b_ndebug=true \
    -D python.bytecompile=1 \
    "$@"
`
	return os.WriteFile(meson32Path, []byte(meson32Script), 0o755)
}

func runSplitScript(pkgDir, outputDir, splitDir, version, pkgName string, buildExec *Executor, env []string, opts BuildOptions) error {
	splitScript := filepath.Join(pkgDir, "split")
	if fi, err := os.Stat(splitScript); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat split script: %w", err)
	} else if fi.IsDir() {
		return nil
	}

	if !opts.Quiet {
		colArrow.Print("-> ")
		colSuccess.Printf("Running split script for %s\n", pkgName)
	}
	cmdStr := fmt.Sprintf("cd %s && %s %s %s %s %s",
		shellQuote(filepath.Dir(splitScript)),
		shellQuote(splitScript),
		shellQuote(outputDir),
		shellQuote(splitDir),
		shellQuote(version),
		shellQuote(pkgName))
	cmd := exec.Command("sh", "-c", cmdStr)
	cmd.Env = append([]string{}, env...)
	cmd.Env = append(cmd.Env,
		"HOKUTO_OUTPUT_DIR="+outputDir,
		"HOKUTO_SPLIT_DIR="+splitDir,
		"HOKUTO_PACKAGE="+pkgName,
		"HOKUTO_VERSION="+version,
	)
	if opts.LogWriter != nil {
		cmd.Stdout = opts.LogWriter
		cmd.Stderr = opts.LogWriter
	} else if Verbose || Debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := buildExec.Run(cmd); err != nil {
		return fmt.Errorf("split script failed for %s: %w", pkgName, err)
	}
	return nil
}

func discoverSplitOutputDirs(splitRoot string) ([]string, error) {
	entries, err := os.ReadDir(splitRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func hasPackagePayload(outputDir string) (bool, error) {
	metadataPrefix := filepath.Join(outputDir, "var", "db", "hokuto", "installed")
	hasPayload := false
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == outputDir {
			return nil
		}
		if strings.HasPrefix(path, metadataPrefix) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		hasPayload = true
		if info.IsDir() {
			return filepath.SkipDir
		}
		return filepath.SkipDir
	})
	return hasPayload, err
}

func copyOptionalMetadataFile(src, dst string, execCtx *Executor) error {
	if fi, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	} else if fi.IsDir() {
		return nil
	}
	cpCmd := exec.Command("cp", "--remove-destination", src, dst)
	return execCtx.Run(cpCmd)
}

func copyPackageRecipeMetadata(pkgDir, installedDir string, execCtx *Executor) error {
	for _, name := range []string{"version", "sources", "build", "options"} {
		if err := copyOptionalMetadataFile(filepath.Join(pkgDir, name), filepath.Join(installedDir, name), execCtx); err != nil {
			return fmt.Errorf("failed to copy %s file: %w", name, err)
		}
	}
	return nil
}

func packageSplitOutputs(parentPkgName, pkgDir, splitRoot, version, revision, targetArch, cflagsVal string, isGeneric bool, shouldStrip bool, buildExec *Executor, cfg *Config, opts BuildOptions, elapsed time.Duration) error {
	splitNames, err := discoverSplitOutputDirs(splitRoot)
	if err != nil {
		return fmt.Errorf("failed to read split output dir: %w", err)
	}
	if len(splitNames) == 0 {
		return nil
	}

	parentOptions := loadBuildOptions(pkgDir)
	for _, splitName := range splitNames {
		splitOutputDir := filepath.Join(splitRoot, splitName)
		hasPayload, err := hasPackagePayload(splitOutputDir)
		if err != nil {
			return fmt.Errorf("failed to inspect split package %s: %w", splitName, err)
		}
		if !hasPayload {
			debugf("Skipping empty split package output %s\n", splitOutputDir)
			continue
		}

		outputSplitName := getOutputPackageName(splitName, cfg)
		if !opts.Quiet {
			colArrow.Print("-> ")
			colSuccess.Print("Packaging split package ")
			colNote.Print(outputSplitName)
			colSuccess.Printf(" from %s\n", parentPkgName)
		}
		splitOptions := loadSplitPackagePostBuildOptions(pkgDir, splitName, outputSplitName, parentOptions)

		installedDir := filepath.Join(splitOutputDir, "var", "db", "hokuto", "installed", outputSplitName)
		mkdirCmd := exec.Command("mkdir", "-p", installedDir)
		if err := buildExec.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create installed dir for split package %s: %w", outputSplitName, err)
		}

		if !splitOptions["binary"] {
			libdepsFile := filepath.Join(installedDir, "libdeps")
			if err := generateLibDeps(splitOutputDir, libdepsFile, buildExec); err != nil {
				fmt.Printf("Warning: failed to generate libdeps for split package %s: %v\n", outputSplitName, err)
			}
		}

		if err := generateDepends(outputSplitName, pkgDir, splitOutputDir, rootDir, buildExec, opts.Bootstrap); err != nil {
			return fmt.Errorf("failed to generate depends for split package %s: %w", outputSplitName, err)
		}

		splitShouldStrip := shouldStrip && !splitOptions["nostrip"]
		if splitShouldStrip {
			if err := stripPackage(splitOutputDir, splitOptions["staticlibs"], buildExec, opts.LogWriter); err != nil {
				return fmt.Errorf("split package %s failed during stripping phase: %w", outputSplitName, err)
			}
		} else {
			debugf("Skipping binary stripping for split package %s.\n", outputSplitName)
		}

		if err := copyPackageRecipeMetadata(pkgDir, installedDir, buildExec); err != nil {
			return fmt.Errorf("failed to copy recipe metadata for split package %s: %w", outputSplitName, err)
		}
		postInstallSrc := findPackageMetadataFile(pkgDir, outputSplitName, "post-install")
		if postInstallSrc != filepath.Join(pkgDir, "post-install") {
			if err := copyOptionalMetadataFile(postInstallSrc, filepath.Join(installedDir, "post-install"), buildExec); err != nil {
				return fmt.Errorf("failed to copy split post-install file for %s: %w", outputSplitName, err)
			}
		}

		buildTimeFile := filepath.Join(installedDir, "buildtime")
		if err := writeRootFile(buildTimeFile, []byte(elapsed.String()+"\n"), 0644, buildExec); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save split build time to %s: %v\n", buildTimeFile, err)
		}

		removeLibtoolArchives(splitOutputDir, buildExec)
		if !splitOptions["staticlibs"] {
			removeStaticLibraries(splitOutputDir, buildExec)
		}
		if err := normalizePackagedManPages(splitOutputDir, buildExec); err != nil {
			return fmt.Errorf("failed to normalize man pages for split package %s: %w", outputSplitName, err)
		}

		isMultilib := detectMultilib(outputSplitName, splitOutputDir)
		pkginfoExec := buildExec
		if buildExec.ShouldRunAsRoot {
			pkginfoExec = RootExec
		}
		if err := WritePackageInfo(splitOutputDir, outputSplitName, version, revision, targetArch, cflagsVal, isGeneric, isMultilib, pkginfoExec); err != nil {
			return fmt.Errorf("failed to write pkginfo for split package %s: %w", outputSplitName, err)
		}
		if err := generateManifest(splitOutputDir, installedDir, buildExec); err != nil {
			return fmt.Errorf("failed to generate manifest for split package %s: %w", outputSplitName, err)
		}
		signExec := buildExec
		if buildExec.ShouldRunAsRoot {
			signExec = RootExec
		}
		if err := SignPackage(splitOutputDir, outputSplitName, signExec, opts.LogWriter); err != nil {
			return fmt.Errorf("failed to sign split package %s: %w", outputSplitName, err)
		}

		variant := IdentifyVariant(outputSplitName, isGeneric, isMultilib)
		if err := createPackageTarball(outputSplitName, version, revision, targetArch, variant, splitOutputDir, buildExec, opts.LogWriter); err != nil {
			return fmt.Errorf("failed to package split tarball %s: %w", outputSplitName, err)
		}
	}
	return nil
}

type builtPackageFinalization struct {
	sourcePkgName string
	outputPkgName string
	pkgDir        string
	outputDir     string
	version       string
	revision      string
	targetArch    string
	cflagsVal     string
	logPath       string
	options       map[string]bool
	buildExec     *Executor
	logger        io.Writer
	started       time.Time
	elapsed       time.Duration
	shouldStrip   bool
	isGeneric     bool
	bootstrap     bool
	updateWebsite bool
}

func removePathFromOutput(outputDir, relPath string, execCtx *Executor) {
	target := filepath.Join(outputDir, relPath)
	if os.Geteuid() == 0 {
		_ = os.RemoveAll(target)
		return
	}
	rmCmd := exec.Command("rm", "-rf", target)
	_ = execCtx.Run(rmCmd)
}

func removeFilesWithSuffix(outputDir, suffix, description string, execCtx *Executor) {
	var matches []string
	err := filepath.WalkDir(outputDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), suffix) {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return nil
		}
		matches = append(matches, "/"+filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to scan for %s in %s: %v\n", description, outputDir, err)
		return
	}
	for _, relPath := range matches {
		removePathFromOutput(outputDir, relPath, execCtx)
	}
	if len(matches) > 0 {
		debugf("Removed %d %s file(s) from %s\n", len(matches), description, outputDir)
	}
}

func removeLibtoolArchives(outputDir string, execCtx *Executor) {
	removeFilesWithSuffix(outputDir, ".la", "libtool archive (.la)", execCtx)
}

func removeStaticLibraries(outputDir string, execCtx *Executor) {
	removeFilesWithSuffix(outputDir, ".a", "static library (.a)", execCtx)
}

func cleanPackagedOutput(outputDir string, execCtx *Executor, options map[string]bool) {
	removeLibtoolArchives(outputDir, execCtx)
	if !options["staticlibs"] {
		removeStaticLibraries(outputDir, execCtx)
	}

	for _, infoPath := range []string{
		"/usr/share/info/dir",
		"/tools/share/info/dir",
		"/usr/aarch64-linux-gnu/share/info/dir",
	} {
		removePathFromOutput(outputDir, infoPath, execCtx)
	}

	for _, pattern := range []string{
		filepath.Join(outputDir, "lib", "perl5", "*", "core_perl", "perllocal.pod"),
		filepath.Join(outputDir, "usr", "lib", "perl5", "*", "core_perl", "perllocal.pod"),
		filepath.Join(outputDir, "usr", "aarch64-linux-gnu", "lib", "perl5", "*", "core_perl", "perllocal.pod"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to glob for perllocal.pod pattern %s: %v\n", pattern, err)
			continue
		}
		if len(matches) == 0 {
			continue
		}
		rmArgs := append([]string{"-f"}, matches...)
		if err := execCtx.Run(exec.Command("rm", rmArgs...)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to delete perllocal.pod files: %v\n", err)
		}
	}

	localePattern := filepath.Join(outputDir, "usr", "share", "locale", "*")
	if localeMatches, err := filepath.Glob(localePattern); err == nil {
		for _, path := range localeMatches {
			base := filepath.Base(path)
			if !strings.HasPrefix(base, "en") {
				removePathFromOutput(outputDir, strings.TrimPrefix(path, outputDir), execCtx)
			}
		}
	}

	for _, docPath := range []string{
		"/usr/share/doc",
		"/usr/aarch64-linux-gnu/share/doc",
	} {
		removePathFromOutput(outputDir, docPath, execCtx)
	}
}

func finalizeBuiltPackage(in builtPackageFinalization) error {
	if in.logger == nil {
		in.logger = os.Stdout
	}

	installedDir := filepath.Join(in.outputDir, "var", "db", "hokuto", "installed", in.outputPkgName)
	debugf("Creating metadata directory: %s\n", installedDir)
	if err := in.buildExec.Run(exec.Command("mkdir", "-p", installedDir)); err != nil {
		return fmt.Errorf("failed to create installed dir: %w", err)
	}

	if !in.options["binary"] {
		libdepsFile := filepath.Join(installedDir, "libdeps")
		if err := generateLibDeps(in.outputDir, libdepsFile, in.buildExec); err != nil {
			fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
		} else {
			debugf("Library dependencies written to %s\n", libdepsFile)
		}
	}

	if err := generateDepends(in.outputPkgName, in.pkgDir, in.outputDir, rootDir, in.buildExec, in.bootstrap); err != nil {
		return fmt.Errorf("failed to generate depends: %w", err)
	}
	debugf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	if in.shouldStrip {
		if err := stripPackage(in.outputDir, in.options["staticlibs"], in.buildExec, in.logger); err != nil {
			return fmt.Errorf("build failed during stripping phase for %s: %w", in.sourcePkgName, err)
		}
	} else {
		debugf("Skipping binary stripping for %s (NoStrip is true).\n", in.sourcePkgName)
	}

	if err := copyPackageRecipeMetadata(in.pkgDir, installedDir, in.buildExec); err != nil {
		return err
	}
	if err := copyOptionalMetadataFile(filepath.Join(in.pkgDir, "post-install"), filepath.Join(installedDir, "post-install"), in.buildExec); err != nil {
		return fmt.Errorf("failed to copy post-install file: %w", err)
	}

	if in.buildExec.ShouldRunAsRoot {
		asRootFile := filepath.Join(installedDir, "asroot")
		if err := in.buildExec.Run(exec.Command("touch", asRootFile)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create asroot marker file %s: %v\n", asRootFile, err)
		}
		debugf("Added asroot marker file to package metadata (package built as root)\n")
	}

	buildTimeFile := filepath.Join(installedDir, "buildtime")
	if err := writeRootFile(buildTimeFile, []byte(in.elapsed.String()+"\n"), 0644, in.buildExec); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save build time to %s: %v\n", buildTimeFile, err)
	}

	cleanPackagedOutput(in.outputDir, in.buildExec, in.options)
	if err := normalizePackagedManPages(in.outputDir, in.buildExec); err != nil {
		return fmt.Errorf("failed to normalize man pages: %w", err)
	}

	logXZPath := filepath.Join(installedDir, "log.xz")
	logExec := in.buildExec
	if in.buildExec.ShouldRunAsRoot {
		logExec = RootExec
	}
	if err := appendBuildLogStatus(in.logPath, in.sourcePkgName, "complete", in.started, in.buildExec); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to append build completion status: %v\n", err)
	}
	if err := compressXZ(in.logPath, logXZPath, logExec); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to compress build log: %v\n", err)
	}

	if in.updateWebsite {
		fullVer := fmt.Sprintf("%s-%s", in.version, in.revision)
		UpdateWebsiteStatus(in.sourcePkgName, fullVer, "success", logXZPath)
	}

	isMultilib := detectMultilib(in.outputPkgName, in.outputDir)
	pkginfoExec := in.buildExec
	if in.buildExec.ShouldRunAsRoot {
		pkginfoExec = RootExec
	}
	if err := WritePackageInfo(in.outputDir, in.outputPkgName, in.version, in.revision, in.targetArch, in.cflagsVal, in.isGeneric, isMultilib, pkginfoExec); err != nil {
		return fmt.Errorf("failed to write pkginfo: %w", err)
	}

	if err := generateManifest(in.outputDir, installedDir, in.buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %w", err)
	}

	signExec := in.buildExec
	if in.buildExec.ShouldRunAsRoot {
		signExec = RootExec
	}
	if err := SignPackage(in.outputDir, in.outputPkgName, signExec, in.logger); err != nil {
		return fmt.Errorf("failed to sign package: %w", err)
	}

	variant := IdentifyVariant(in.sourcePkgName, in.isGeneric, isMultilib)
	if err := createPackageTarball(in.outputPkgName, in.version, in.revision, in.targetArch, variant, in.outputDir, in.buildExec, in.logger); err != nil {
		return fmt.Errorf("failed to package tarball: %w", err)
	}

	return nil
}

func pkgBuild(pkgName string, cfg *Config, execCtx *Executor, opts BuildOptions) (time.Duration, error) {
	if opts.Quiet && opts.LogWriter == nil {
		opts.LogWriter = io.Discard
	}

	// Define the ANSI escape code format for setting the terminal title.
	// \033]0; sets the title, and \a (bell character) terminates the sequence.
	const setTitleFormat = "\033]0;%s\a"
	debugf("INFO RUNNING pkgBuild function")

	// CLONE CONFIG to avoid race conditions in parallel builds.
	// pkgBuild modifies cfg.Values (e.g. for cross-compilation settings), so we need an isolated copy.
	// Without this, parallel updates/builds will leak environment settings (like HOKUTO_CROSS) between packages.
	cfgCopy := &Config{
		Values:       make(map[string]string, len(cfg.Values)),
		DefaultStrip: cfg.DefaultStrip,
		DefaultLTO:   cfg.DefaultLTO,
	}
	maps.Copy(cfgCopy.Values, cfg.Values)
	cfg = cfgCopy // Use the copy for the rest of this function

	// Helper function to set the title in the TTY.
	setTerminalTitle := func(title string) {
		//	// Outputting directly to os.Stdout sets the title in the terminal session.
		if !opts.Quiet {
			fmt.Printf(setTitleFormat, title)
		}
	}

	// Track build time
	startTime := time.Now()

	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return 0, fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
	}

	// NEW: Load build options (consolidated from 'options' file or individual files)
	options := loadBuildOptions(pkgDir)

	// Save current cross settings to restore them later (prevent pollution across packages in the same run)
	origCrossSystem := cfg.Values["HOKUTO_CROSS_SYSTEM"]
	origCrossSimple := cfg.Values["HOKUTO_CROSS_SIMPLE"]
	origCrossArch := cfg.Values["HOKUTO_CROSS_ARCH"]
	defer func() {
		cfg.Values["HOKUTO_CROSS_SYSTEM"] = origCrossSystem
		cfg.Values["HOKUTO_CROSS_SIMPLE"] = origCrossSimple
		cfg.Values["HOKUTO_CROSS_ARCH"] = origCrossArch
	}()

	// NEW: Detect if we are building a cross-system package via fallback
	// (e.g. pkgName is aarch64-pkg but pkgDir belongs to pkg)
	if filepath.Base(pkgDir) != pkgName {
		prefixes := []string{"aarch64-", "x86_64-"}
		for _, pref := range prefixes {
			if strings.HasPrefix(pkgName, pref) && filepath.Base(pkgDir) == strings.TrimPrefix(pkgName, pref) {
				debugf("Detected cross-system fallback build for %s using source %s\n", pkgName, filepath.Base(pkgDir))
				cfg.Values["HOKUTO_CROSS_SYSTEM"] = "1"
				switch pref {
				case "aarch64-":
					cfg.Values["HOKUTO_CROSS_ARCH"] = "arm64"
				case "x86_64-":
					cfg.Values["HOKUTO_CROSS_ARCH"] = "x86_64"
				}
				break
			}
		}
	}

	// NEW: Check for 'cross-simple' option to override toolchain settings
	if options["cross-simple"] {
		debugf("Cross-simple mode enabled for %s. Using host toolchain.\n", pkgName)
		cfg.Values["HOKUTO_CROSS_SIMPLE"] = "1"
	}

	// Read version and revision early for lock check
	versionFile := filepath.Join(pkgDir, "version")
	versionData, err := os.ReadFile(versionFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read version file: %v", err)
	}
	fields := strings.Fields(string(versionData))
	if len(fields) == 0 {
		return 0, fmt.Errorf("version file is empty")
	}
	version := fields[0]
	revision := "1" // Default revision if not specified
	if len(fields) >= 2 {
		revision = fields[1]
	}

	// Check if package version is locked
	if err := checkLock(pkgName, version); err != nil {
		if !opts.Quiet {
			colArrow.Print("-> ")
			colWarn.Println(err)
			colWarn.Println("Permitting build, but installation will be blocked.")
		}
	}

	// 1. Initialize a LOCAL temporary directory variable with the global default.
	currentTmpDir := tmpDir
	// override tmpDir if noram is set
	if options["noram"] {
		currentTmpDir = cfg.Values["TMPDIR2"]
	}

	// Atomically reserve a predictable directory. Failed builds leave their
	// directory behind, so the next attempt advances from -01 to -02, etc.
	pkgTmpDir, err := reserveBuildTempDir(currentTmpDir, pkgName)
	if err != nil {
		return 0, err
	}
	logDir := filepath.Join(pkgTmpDir, "log")
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")
	splitRoot := filepath.Join(pkgTmpDir, "split")

	// Create build/output dirs (non-root, inside TMPDIR).
	for _, dir := range []string{buildDir, outputDir, logDir, splitRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

	// 1. Determine the Execution Context for THIS PACKAGE.
	// This check MUST stay here as it is package-specific.
	needsRootBuild := options["asroot"]

	//Check for an 'interactive' file to control build mode ---
	needsInteractiveBuild := options["interactive"]
	if needsInteractiveBuild {
		debugf("Interactive build mode enabled for %s.\n", pkgName)
	}

	// 2. CLONE AND SELECT EXECUTOR
	// Create a new Executor instance for the build phase.
	buildExec := &Executor{
		Context:         execCtx.Context,       // Inherit the main cancellation context
		ShouldRunAsRoot: needsRootBuild,        // Set the privilege based on 'asroot' file
		Interactive:     needsInteractiveBuild, // SET INTERACTIVE MODE
		Stdout:          opts.LogWriter,
		Stderr:          opts.LogWriter,
	}
	// Fetch all sources for the build, including git repositories.
	if err := fetchSourcesWithOptions(pkgName, pkgDir, true, opts.Quiet); err != nil {
		return 0, fmt.Errorf("failed to fetch sources: %v", err)
	}

	// Perform checksum verification.
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false, opts.LogWriter); err != nil {
		return 0, fmt.Errorf("source verification failed: %w", err)
	}

	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return 0, fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	// Disable stripping for cross-compilation as host 'strip' doesn't support target binaries
	if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		shouldStrip = false
	}

	if options["nostrip"] {
		if shouldStrip { // Only print if it wasn't already disabled
			if !opts.Quiet {
				colArrow.Print("-> ")
				colSuccess.Printf("Disabling stripping.\n")
			}
			if opts.LogWriter != nil {
				fmt.Fprintf(opts.LogWriter, "Disabling stripping.\n")
			}
		}
		shouldStrip = false // Override the global setting for this package only
	}

	// Check if LTO should be enabled
	shouldLTO := cfg.DefaultLTO
	if options["nolto"] {
		if opts.LogWriter == nil {
			colArrow.Print("-> ")
			colSuccess.Printf("Disabling LTO.\n")
		} else {
			fmt.Fprintf(opts.LogWriter, "Disabling LTO.\n")
		}
		shouldLTO = false // Override the global setting for this package only
	}

	// (Version and revision were already read at the beginning of the function for the lock check)

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return 0, fmt.Errorf("build script not found: %v", err)
	}

	// Define the base C/C++/LD flags
	var defaultCFLAGS = "-O2 -march=x86-64-v2 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// Define core count to use
	var numCores int
	if options["idle"] {
		numCores = max(runtime.NumCPU()/2, 1)
		debugf("Idle mode enabled for %s. Using %d cores.\n", pkgName, numCores)
	} else {
		switch buildPriority {
		case "idle":
			numCores = runtime.NumCPU() / 2
			if numCores < 1 {
				numCores = 1
			}
		case "superidle":
			numCores = 1
		default: // "normal"
			numCores = runtime.NumCPU()
		}
	}

	// Jobs for LTO (if enabled)
	ltoJobString := fmt.Sprintf("%d", numCores)
	if options["clang"] {
		// 'clang' option exists, use "auto" for LTO jobs
		ltoJobString = "auto"
		debugf("Using LTOJOBS=auto (clang option).\n")
	} else {
		// No 'clang' option, use core count
		debugf("Using LTOJOBS=%s.\n", ltoJobString)
	}

	// Build environment
	// Start with environment, but filter out CFLAGS/CXXFLAGS/LDFLAGS to avoid conflicts
	// Our defaults should take precedence
	env := []string{}
	for _, e := range os.Environ() {
		// Skip CFLAGS, CXXFLAGS, and LDFLAGS from environment - we'll set them from defaults
		if strings.HasPrefix(e, "CFLAGS=") || strings.HasPrefix(e, "CXXFLAGS=") || strings.HasPrefix(e, "LDFLAGS=") || strings.HasPrefix(e, "HOKUTO_LTO=") {
			continue
		}
		if opts.Bootstrap && strings.HasPrefix(e, "CONFIG_SITE=") {
			continue
		}
		env = append(env, e)
	}
	var defaults = map[string]string{}

	if opts.Bootstrap {
		// --- Bootstrap environment ---
		lfsRoot := cfg.Values["LFS"]
		if lfsRoot == "" {
			return 0, fmt.Errorf("bootstrap mode requires LFS to be set in config")
		}

		// --- Architecture Detection ---
		targetArch := cfg.Values["HOKUTO_ARCH"]
		if targetArch == "" {
			targetArch = "x86_64" // Default
		}

		var lfsTgt, cflags string

		switch targetArch {
		case "aarch64", "arm64":
			// Raspberry Pi 4 / ARM64 Settings
			lfsTgt = "aarch64-lfs-linux-gnu"
			cflags = "-O2 -pipe"
			colArrow.Print("-> ")
			colSuccess.Println("Configuring bootstrap for AArch64")

		case "x86_64":
			lfsTgt = "x86_64-lfs-linux-gnu"
			cflags = "-O2 -march=x86-64-v2 -mtune=generic -pipe -fPIC"

		default:
			lfsTgt = fmt.Sprintf("%s-lfs-linux-gnu", targetArch)
			cflags = "-O2 -pipe -fPIC"
		}

		// --- Multilib Handling in Bootstrap ---
		// Determine Multilib state (Only allow '1' if config requests it AND we are on x86_64)
		multilibVal := "0"
		switch cfg.Values["HOKUTO_MULTILIB"] {
		case "1":
			multilibVal = "1"
		case "0":
			debugf("Disabling MULTILIB for %s architecture (config requested enabled).\n", targetArch)
		}

		defaults = map[string]string{
			"LFS":       lfsRoot,
			"LC_ALL":    "POSIX",
			"LFS_TGT":   lfsTgt,
			"LFS_TGT32": "i686-lfs-linux-gnu",
			"CFLAGS":    cflags,
			"CXXFLAGS":  cflags,
			"LDFLAGS":   "",
			// Crucial: Put LFS tools first in PATH
			"PATH":              filepath.Join(lfsRoot, "tools/bin") + ":/usr/bin:/bin",
			"MAKEFLAGS":         fmt.Sprintf("-j%d", numCores),
			"HOKUTO_ROOT":       lfsRoot,
			"TMPDIR":            currentTmpDir,
			"XDG_CACHE_HOME":    filepath.Join(buildDir, ".cache"), // Prevent g-ir-scanner from using ~/.cache
			"HOKUTO_ARCH":       targetArch,
			"HOKUTO_BUILD_DIR":  buildDir,
			"HOKUTO_OUTPUT_DIR": outputDir,
			"HOKUTO_SPLIT_DIR":  splitRoot,
			"CARGO_HOME":        filepath.Join(buildDir, "cargo"),
			"GNU_MIRROR":        cfg.Values["GNU_MIRROR"],
			"SET_HOKUTO_LTO":    cfg.Values["SET_HOKUTO_LTO"],
			"MULTILIB":          multilibVal,
		}
		// Bootstrap builds do not use the LTO flag sets. SET_HOKUTO_LTO is
		// retained separately for configuring the final system.
		defaults["HOKUTO_LTO"] = "0"

		if cfg.Values["HOKUTO_GENERIC"] == "1" {
			defaults["HOKUTO_GENERIC"] = "1"
		}

	} else {

		// 1. Detect Target Architecture
		// -----------------------------
		targetArch := cfg.Values["HOKUTO_CROSS_ARCH"]
		if targetArch == "" {
			targetArch = cfg.Values["HOKUTO_ARCH"]
		}
		if targetArch == "" {
			cmd := exec.Command("uname", "-m")
			out, err := cmd.Output()
			if err == nil {
				targetArch = strings.TrimSpace(string(out))
			} else {
				// Final fallback to Go runtime info
				targetArch = runtime.GOARCH
			}
		}
		// Normalize architecture names
		if targetArch == "amd64" {
			targetArch = "x86_64"
		}
		if targetArch == "arm64" {
			targetArch = "aarch64"
		}

		isX86 := (targetArch == "x86_64")
		isARM := (targetArch == "aarch64")

		// 2. Apply Architecture Constraints (LTO & Multilib)
		// --------------------------------------------------

		// Disable LTO for non-x86 architectures
		if !isX86 && shouldLTO {
			debugf("Disabling LTO for %s architecture.\n", targetArch)
			shouldLTO = false
		}

		// Determine Multilib state (Only allow '1' if config requests it AND we are on x86_64)
		multilibVal := "0"
		if isX86 && cfg.Values["HOKUTO_MULTILIB"] == "1" {
			multilibVal = "1"
		} else if cfg.Values["HOKUTO_MULTILIB"] == "1" {
			debugf("Disabling MULTILIB for %s architecture (config requested enabled).\n", targetArch)
		}

		// 3. Select Compiler Flags
		var cflagsVal, cxxflagsVal, ldflagsVal string

		// Check if cross-compilation is enabled
		isCross := cfg.Values["HOKUTO_CROSS_ARCH"] != ""

		// Check if generic build is enabled
		isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]

		if isGeneric {
			// Generic build: use CFLAGS_GEN and CFLAGS_GEN_LTO
			if shouldLTO {
				cflagsVal = cfg.Values["CFLAGS_GEN_LTO"]
				cxxflagsVal = cfg.Values["CXXFLAGS_GEN_LTO"]
				ldflagsVal = cfg.Values["LDFLAGS_LTO"]
			} else {
				cflagsVal = cfg.Values["CFLAGS_GEN"]
				cxxflagsVal = cfg.Values["CXXFLAGS_GEN"]
				ldflagsVal = cfg.Values["LDFLAGS"]
			}
		} else if isARM {
			// Case: ARM64 (Native or Cross)
			// Use optimized flags unless explicitly disabled, in simple cross mode, or cross-system build
			if !options["nocrossopt"] && cfg.Values["HOKUTO_CROSS_SIMPLE"] != "1" && cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1" && cfg.Values["CFLAGS_ARM64"] != "" {
				cflagsVal = cfg.Values["CFLAGS_ARM64"]
				cxxflagsVal = cfg.Values["CXXFLAGS_ARM64"]
				debugf("Using optimized ARM64 flags: %s\n", cflagsVal)
			} else {
				cflagsVal = "-O2 -pipe -mtune=generic -fPIC"
				cxxflagsVal = "-O2 -pipe -mtune=generic -fPIC"
				debugf("Using generic flags for ARM64 target.\n")
			}
			ldflagsVal = cfg.Values["LDFLAGS"]
		} else if shouldLTO {
			// Case B: x86_64 with LTO
			cflagsVal = cfg.Values["CFLAGS_LTO"]
			cxxflagsVal = cfg.Values["CXXFLAGS_LTO"]
			ldflagsVal = cfg.Values["LDFLAGS_LTO"]
		} else {
			// Case C: Standard (LTO disabled or x86 without LTO config)
			cflagsVal = cfg.Values["CFLAGS"]
			cxxflagsVal = cfg.Values["CXXFLAGS"]
			ldflagsVal = cfg.Values["LDFLAGS"]
		}

		// Fallbacks
		// When cross-compiling, if CFLAGS_ARM64 is not set, fall back to CFLAGS (which will be sanitized)
		if cflagsVal == "" {
			if isCross {
				cflagsVal = cfg.Values["CFLAGS"]
			}
			if cflagsVal == "" {
				cflagsVal = defaultCFLAGS
			}
		}
		if cxxflagsVal == "" {
			if isCross {
				cxxflagsVal = cfg.Values["CXXFLAGS"]
			}
			if cxxflagsVal == "" {
				cxxflagsVal = cflagsVal
			}
		}
		if ldflagsVal == "" {
			ldflagsVal = defaultLDFLAGS
		}

		// --- FIX: Apply Substitution ALWAYS ---
		// This ensures that if CFLAGS_ARM64 or standard CFLAGS contains "LTOJOBS",
		// it gets resolved correctly instead of breaking the build.
		cflagsVal = strings.ReplaceAll(cflagsVal, "LTOJOBS", ltoJobString)
		cxxflagsVal = strings.ReplaceAll(cxxflagsVal, "LTOJOBS", ltoJobString)
		ldflagsVal = strings.ReplaceAll(ldflagsVal, "LTOJOBS", ltoJobString)

		// --- FIX: Sanitize flags for cross-compilation ---
		// Remove -march=native and -mtune=native when cross-compiling
		if isCross {
			crossArch := cfg.Values["HOKUTO_CROSS_ARCH"]
			normalizedArch := crossArch
			if normalizedArch == "arm64" {
				normalizedArch = "aarch64"
			}
			cflagsVal = sanitizeFlagsForCrossCompilation(cflagsVal, normalizedArch)
			cxxflagsVal = sanitizeFlagsForCrossCompilation(cxxflagsVal, normalizedArch)
		}

		// 4. Apply Linker Logic (Mold)
		// ----------------------------
		// "replace -fuse-ld=bfd with -fuse-ld=mold if mold is installed and LTO is disabled"
		if !shouldLTO {
			useMold := checkPackageExactMatch("mold")

			if useMold {
				// Upgrade BFD/Gold to Mold
				ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=bfd", "-fuse-ld=mold")
				ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=gold", "-fuse-ld=mold")
			} else {
				// Fallback: If config asks for Mold but it's not installed, revert to BFD
				ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=mold", "-fuse-ld=bfd")
			}
		}

		// 5. Apply CPU Flags
		cpuFlags := ""
		if !isGeneric {
			if isX86 {
				cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS_X86"]
				if cpuFlags == "" {
					cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS"] // legacy/fallback
				}
			} else if isARM {
				cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS_ARM"]
			}
		}

		// --- Normal build environment---
		// Build RUSTFLAGS based on CFLAGS and CPU flags
		rustflags := buildRustFlags(cflagsVal, cpuFlags, buildDir, isGeneric)

		hokutoGenericEnv := cfg.Values["HOKUTO_GENERIC"]
		if isGeneric {
			hokutoGenericEnv = "1"
		}

		defaults = map[string]string{
			"AR":                         "gcc-ar",
			"CC":                         "cc",
			"CXX":                        "c++",
			"NM":                         "gcc-nm",
			"RANLIB":                     "gcc-ranlib",
			"CFLAGS":                     cflagsVal,
			"CXXFLAGS":                   cxxflagsVal,
			"LDFLAGS":                    ldflagsVal,
			"CPUFLAGS":                   cpuFlags,
			"MAKEFLAGS":                  fmt.Sprintf("-j%d", numCores),
			"CMAKE_BUILD_PARALLEL_LEVEL": fmt.Sprintf("%d", numCores),
			"RUSTFLAGS":                  rustflags,
			"GOFLAGS":                    "-trimpath -modcacherw",
			"GOPATH":                     filepath.Join(buildDir, "go"),
			"CARGO_HOME":                 filepath.Join(buildDir, "cargo"),
			"HOKUTO_ROOT":                cfg.Values["HOKUTO_ROOT"],
			"TMPDIR":                     currentTmpDir,
			"XDG_CACHE_HOME":             filepath.Join(buildDir, ".cache"), // Prevent g-ir-scanner from using ~/.cache
			"CONFIG_SITE":                ("/usr/share/config.site"),
			"HOKUTO_ARCH":                targetArch,
			"HOKUTO_GENERIC":             hokutoGenericEnv,
			"MULTILIB":                   multilibVal,
			"HOKUTO_BUILD_DIR":           buildDir,
			"HOKUTO_OUTPUT_DIR":          outputDir,
			"HOKUTO_SPLIT_DIR":           splitRoot,
			"GNU_MIRROR":                 cfg.Values["GNU_MIRROR"],
		}
		if shouldLTO {
			defaults["HOKUTO_LTO"] = "1"
		} else {
			defaults["HOKUTO_LTO"] = "0"
		}

		if !isGeneric {
			if isX86 && cpuFlags != "" {
				defaults["CPU_FLAGS_X86"] = cpuFlags
			} else if isARM && cpuFlags != "" {
				defaults["CPU_FLAGS_ARM"] = cpuFlags
			}
		}

		if buildPriority == "idle" || buildPriority == "superidle" {
			defaults["HOKUTO_BUILD_PRIORITY"] = buildPriority
		}

		// Add cross-compilation environment variables if cross flag is set
		// Note: This is only for normal builds, not bootstrap
		if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
			defaults["HOKUTO_CROSS"] = "1"
			crossArch := cfg.Values["HOKUTO_CROSS_ARCH"]
			defaults["HOKUTO_CARCH"] = crossArch

			if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
				defaults["HOKUTO_CROSS_SYSTEM"] = "1"
			}
			if cfg.Values["HOKUTO_CROSS_SIMPLE"] == "1" {
				defaults["HOKUTO_CROSS_SIMPLE"] = "1"
			}

			// Normalize architecture name for toolchain prefix
			normalizedArch := crossArch
			if normalizedArch == "arm64" {
				normalizedArch = "aarch64"
			}

			// Set HOKUTO_ARCH to the normalized architecture for cross-compilation
			defaults["HOKUTO_ARCH"] = normalizedArch

			// Disable MULTILIB for cross-compilation
			defaults["MULTILIB"] = "0"

			// Replace compiler tools with cross-compilation toolchain (unless simple mode or host tool for cross-system)
			isCrossSystem := cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1"
			shouldBuildHostNative := options["host-tool"] && (isCrossSystem || cfg.Values["HOKUTO_CROSS_SIMPLE"] == "1")

			if cfg.Values["HOKUTO_CROSS_SIMPLE"] != "1" && !shouldBuildHostNative {
				toolchainPrefix := normalizedArch + "-linux-gnu-"
				defaults["CC"] = toolchainPrefix + "gcc"
				defaults["CXX"] = toolchainPrefix + "g++"
				defaults["AR"] = toolchainPrefix + "ar"
				defaults["RANLIB"] = toolchainPrefix + "ranlib"
				defaults["OBJCOPY"] = toolchainPrefix + "objcopy"
				defaults["OBJDUMP"] = toolchainPrefix + "objdump"
				defaults["STRIP"] = toolchainPrefix + "strip"
				defaults["PKG_CONFIG"] = toolchainPrefix + "pkg-config"
			}
			// In simple mode, keep normal compiler/linker settings (already set above)

			// Determine the sysroot prefix for cross-compilation
			sysrootPrefix := fmt.Sprintf("/usr/%s-linux-gnu", normalizedArch)

			// Set CROSS_PREFIX based on cross-compilation mode
			if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" || cfg.Values["HOKUTO_CROSS_SIMPLE"] == "1" {
				// Use sysroot for toolchain/system packages in both cross modes
				defaults["CROSS_PREFIX"] = sysrootPrefix
			} else {
				// Regular cross-compilation (user packages): use /usr (target perspective)
				defaults["CROSS_PREFIX"] = "/usr"
			}

			// Ensure the cross-bin directory is in the PATH so tools like pkg-config can be found
			// BUT only if we are NOT building a host-tool (otherwise we break the host compiler)
			if !options["host-tool"] || !isCrossSystem {
				currentPath := os.Getenv("PATH")
				defaults["PATH"] = currentPath + ":" + filepath.Join(sysrootPrefix, "bin")
			}

			// Set PKG_CONFIG environment variables to avoid host pollution
			// BUT skip this if we are building a host tool (native), so we use host libraries/headers
			if !shouldBuildHostNative {
				defaults["PKG_CONFIG_LIBDIR"] = filepath.Join(sysrootPrefix, "lib", "pkgconfig") + ":" + filepath.Join(sysrootPrefix, "share", "pkgconfig")
				defaults["PKG_CONFIG_SYSROOT_DIR"] = sysrootPrefix
				defaults["PKG_CONFIG_PATH"] = "" // Clear to avoid host pollution

				// Set PYTHONPATH to include target site-packages for build-time module detection
				defaults["PYTHONPATH"] = filepath.Join(sysrootPrefix, "lib", "python3.14", "site-packages")
			}

			// Rust cross-compilation setup
			// Set CARGO_BUILD_TARGET and linker for cross-compilation
			var rustTarget string
			switch normalizedArch {
			case "aarch64":
				rustTarget = "aarch64-unknown-linux-gnu"
			case "x86_64":
				rustTarget = "x86_64-unknown-linux-gnu"
			default:
				rustTarget = normalizedArch + "-unknown-linux-gnu"
			}

			// Set the default target for cargo
			defaults["CARGO_BUILD_TARGET"] = rustTarget

			// Set the linker for the target architecture
			// Environment variable format: CARGO_TARGET_<TRIPLE>_LINKER
			// Triple needs to be uppercase with dashes replaced by underscores
			linkerEnvVar := "CARGO_TARGET_" + strings.ToUpper(strings.ReplaceAll(rustTarget, "-", "_")) + "_LINKER"
			defaults[linkerEnvVar] = normalizedArch + "-linux-gnu-gcc"

			debugf("Rust cross-compilation: target=%s, linker_var=%s, linker=%s\n",
				rustTarget, linkerEnvVar, defaults[linkerEnvVar])
		}
	}

	// Ensure CROSS_PREFIX is available and defaults to /usr if not set
	if _, ok := defaults["CROSS_PREFIX"]; !ok {
		if val, envSet := os.LookupEnv("CROSS_PREFIX"); envSet {
			defaults["CROSS_PREFIX"] = val
		} else {
			defaults["CROSS_PREFIX"] = "/usr"
		}
	}

	// Set QEMU_LD_PREFIX for cross-compilation to allow running target binaries via QEMU
	// The cross toolchain and libraries are always in /usr/<arch>-linux-gnu
	if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		normalizedArch := cfg.Values["HOKUTO_CROSS_ARCH"]
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		sysroot := fmt.Sprintf("/usr/%s-linux-gnu", normalizedArch)
		defaults["QEMU_LD_PREFIX"] = sysroot
	}

	// Inject HOKUTO_REAL_USER
	helperDir := filepath.Join(buildDir, ".hokuto-tools")
	if err := writeBuildHelperScripts(helperDir); err != nil {
		return 0, fmt.Errorf("failed to create build helper scripts: %w", err)
	}
	if defaults["PATH"] != "" {
		defaults["PATH"] = helperDir + ":" + defaults["PATH"]
	} else {
		defaults["PATH"] = helperDir + ":" + os.Getenv("PATH")
	}

	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		realUser = os.Getenv("USER")
	}
	defaults["HOKUTO_REAL_USER"] = realUser

	// Sort keys for deterministic order
	keys := make([]string, 0, len(defaults))
	for k := range defaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var envVarsBuilder strings.Builder
	for _, k := range keys {
		v := defaults[k]

		// Handle PATH specially to avoid duplicate entries in env if defaults already has it
		if k == "PATH" {
			// Find and remove existing PATH from env if we are setting a new one from defaults
			newEnv := make([]string, 0, len(env))
			for _, e := range env {
				if !strings.HasPrefix(e, "PATH=") {
					newEnv = append(newEnv, e)
				}
			}
			env = newEnv
		}

		env = append(env, fmt.Sprintf("%s=%s", k, v))
		// Escape single quotes for the command string
		vEscaped := strings.ReplaceAll(v, "'", "'\\''")
		envVarsBuilder.WriteString(fmt.Sprintf("%s='%s' ", k, vEscaped))
	}

	// Run build script
	debugf("Building %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	// 1. Define the log file path
	logPath := filepath.Join(logDir, "build-log.txt")
	optionalBuildState := snapshotOptionalBuildDependencies(pkgDir, cfg)
	declaredBuildDeps, installedBuildDeps := buildLogDependencies(pkgDir, cfg, optionalBuildState)
	if err := writeBuildLogHeader(logPath, pkgName, version, revision, startTime, declaredBuildDeps, installedBuildDeps); err != nil {
		return 0, fmt.Errorf("failed to initialize build log: %w", err)
	}
	// Ensure logDir exists (already created above, but ensure it's there)

	// Check if /bin/script exists
	useScript := false
	if _, err := os.Stat("/bin/script"); err == nil {
		useScript = true
	} else {
		debugf("/bin/script not found, falling back to direct execution\n")
	}

	// Build the command string to execute
	// FIX: We prepend the environment variables to the command string explicitly.
	// This ensures that even if 'script' spawns a shell that sources .bashrc (resetting flags),
	// our flags take precedence for the actual build command.
	cmdStr := fmt.Sprintf("cd %s && %s%s %s %s %s",
		buildDir, envVarsBuilder.String(), buildScript, outputDir, version, pkgName)

	var cmd *exec.Cmd
	var logFile *os.File

	var runErr error // Use a single error variable for both paths, declared outside loop for later use

	// Loop for fallback mechanism: if script fails, retry without it
	for {
		if useScript {
			// Use script to create PTY and preserve colors
			// -q: quiet mode (don't print script start/end messages)
			// -f: flush output immediately (for real-time viewing)
			// -c: command to run
			// script writes the PTY session to the log file automatically
			// script also outputs to stdout/stderr, which we capture for console
			cmd = exec.Command("script", "-q", "-f", "-a", "-c", cmdStr, logPath)
			cmd.Dir = buildDir
		} else {
			// Fallback: Execute directly with sh
			cmd = exec.Command("sh", "-c", cmdStr)
			cmd.Dir = buildDir

			// We need to handle logging manually since we aren't using script
			// Close previous logFile if it exists (though it shouldn't in this flow)
			if logFile != nil {
				logFile.Close()
			}
			var err error
			logFile, err = os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return 0, fmt.Errorf("failed to create log file: %w", err)
			}
			// Defer close is tricky here because we want to close it after run,
			// but we can close it at the end of the function or after wait.
			// For now we'll close it after cmd.Run() returns.
		}

		// Set up environment
		cmd.Env = make([]string, len(env))
		copy(cmd.Env, env)

		// Set TERM environment variable (even for fallback, though less effective without PTY)
		cmd.Env = append(cmd.Env, "TERM=xterm-256color")

		// Force color output for common build tools
		cmd.Env = append(cmd.Env, "CARGO_TERM_COLOR=always") // Rust/Cargo
		cmd.Env = append(cmd.Env, "CLICOLOR_FORCE=1")        // General Unix tools
		cmd.Env = append(cmd.Env, "FORCE_COLOR=1")           // Node.js tools

		// Handle Stdout/Stderr and Logging
		if useScript {
			// script writes to the log file automatically (last argument)
			// script also outputs to stdout/stderr (duplicate of log file content)
			// Important: script needs valid stdout/stderr to create a PTY properly
			// When verbose is disabled, redirect to /dev/null to suppress console output
			// The log file will still contain all the output
			if buildExec.Interactive || Verbose || Debug {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				// Forward stdin in interactive mode so user can respond to prompts
				if buildExec.Interactive {
					cmd.Stdin = os.Stdin
				}
			} else {
				// Suppress console output but give script valid file descriptors
				devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
				if err != nil {
					return 0, fmt.Errorf("failed to open /dev/null: %w", err)
				}
				defer devNull.Close()
				cmd.Stdout = devNull
				cmd.Stderr = devNull
			}
		} else {
			// Fallback path: We must write to logFile AND optionally to stdout/stderr
			var outputWriter io.Writer
			if buildExec.Interactive || Verbose || Debug {
				outputWriter = io.MultiWriter(os.Stdout, logFile)
				// Forward stdin in interactive mode
				if buildExec.Interactive {
					cmd.Stdin = os.Stdin
				}
			} else {
				outputWriter = logFile
			}
			cmd.Stdout = outputWriter
			cmd.Stderr = outputWriter
		}

		// Reset runErr for this attempt
		runErr = nil

		// Run command
		// Note: For 'script', it always returns 0, so we check the log file for exit code.
		// For fallback, cmd.Run() returns the actual error if exit code != 0.

		if !buildExec.Interactive {
			// --- NON-INTERACTIVE PATH: Run with timer and title updates ---
			setTerminalTitle(fmt.Sprintf("Starting %s", pkgName))
			doneCh := make(chan struct{})
			var runWg sync.WaitGroup
			runWg.Add(1)

			go func() {
				defer runWg.Done()
				ticker := time.NewTicker(time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						elapsed := time.Since(startTime).Truncate(time.Second)
						title := fmt.Sprintf("Building: %s (%d/%d) elapsed: %s", pkgName, opts.CurrentIndex, opts.TotalCount, elapsed)
						setTerminalTitle(title)
						// Only print elapsed time to console if not in verbose mode
						// In verbose mode, the build output is already visible, so we only update the title
						if !Verbose && !opts.Quiet {
							colArrow.Print("-> ")
							colSuccess.Printf("Building %s elapsed: %s\r", pkgName, elapsed)
						}

					case <-doneCh:
						if !opts.Quiet {
							fmt.Print("\r")
						}
						return
					case <-buildExec.Context.Done():
						return
					}
				}
			}()

			// Run
			if buildExec.ShouldRunAsRoot {
				if err := buildExec.Run(cmd); err != nil {
					// If using script, err might only be about the script launcher failing, not the build itself
					// If NOT using script, err is the actual build failure
					if !useScript {
						runErr = fmt.Errorf("build failed: %w", err)
					} else {
						runErr = fmt.Errorf("script execution failed: %w", err)
					}
				}
			} else {
				if err := cmd.Run(); err != nil {
					if !useScript {
						runErr = fmt.Errorf("build failed: %w", err)
					} else {
						runErr = fmt.Errorf("script execution failed: %w", err)
					}
				}
			}

			// Stop ticker goroutine and wait.
			close(doneCh)
			runWg.Wait()

		} else {
			// --- INTERACTIVE PATH ---
			if buildExec.ShouldRunAsRoot {
				if err := buildExec.Run(cmd); err != nil {
					if !useScript {
						runErr = fmt.Errorf("build failed: %w", err)
					} else {
						runErr = fmt.Errorf("script execution failed: %w", err)
					}
				}
			} else {
				if err := cmd.Run(); err != nil {
					if !useScript {
						runErr = fmt.Errorf("build failed: %w", err)
					} else {
						runErr = fmt.Errorf("script execution failed: %w", err)
					}
				}
			}
		}

		// CHECK FOR FALLBACK CONDITION
		// If we used script and it failed (runErr != nil), it means script itself failed (e.g. no PTY).
		// We should try again without script.
		if useScript && runErr != nil {
			debugf("Script execution failed (%v), falling back to direct execution...\n", runErr)
			useScript = false
			continue // Retry loop
		}

		// Check exit code for script ONLY if runErr is nil so far
		// If useScript is true, cmd.Run() usually says "success" even if build failed, so we MUST check log.
		if useScript && runErr == nil {
			if exitCode := getScriptExitCode(logPath); exitCode != 0 {
				runErr = fmt.Errorf("build script exited with code %d", exitCode)
			}
		}

		// If we get here, valid attempt completed (success or failure wasn't a script-system-failure)
		break
	}

	// Close log file if we opened it manually
	if logFile != nil {
		logFile.Close()
	}

	if runErr != nil {
		if err := appendBuildLogStatus(logPath, pkgName, "failed", startTime, buildExec); err != nil {
			debugf("Warning: failed to append build failure status: %v\n", err)
		}
		printFailure := func() {
			colArrow.Print("-> ")
			color.Danger.Printf("Build failed for %s: %v\n", pkgName, runErr)
		}
		if opts.Quiet {
			// Parallel builds share the terminal with the live status line. Pause
			// and clear that UI before emitting the failure on its own line.
			WithPrompt(printFailure)
		} else {
			printFailure()
		}
		finalTitle := fmt.Sprintf("❌ FAILED: %s", pkgName)
		setTerminalTitle(finalTitle)

		// Path to the build log (script creates and writes to this file)
		logPath := filepath.Join(logDir, "build-log.txt")

		if opts.UpdateWebsite {
			fullVer := fmt.Sprintf("%s-%s", version, revision)
			UpdateWebsiteStatus(pkgName, fullVer, "failed", logPath)
		}

		// If interactive, let user follow the log; otherwise show last N lines and continue.
		if buildExec.Interactive {
			tailCmd := exec.Command("tail", "-n", "50", "-f", logPath)
			tailCmd.Stdin = os.Stdin
			tailCmd.Stdout = os.Stdout
			tailCmd.Stderr = os.Stderr
			// Run tail via the same Executor so privilege behavior and context cancellation are honored.
			_ = buildExec.Run(tailCmd)
		} else {
			// Non-interactive: just print the last 50 lines and don't block.
			tailOnce := exec.Command("tail", "-n", "50", logPath)
			// Do NOT attach Stdin for non-interactive mode (avoid blocking).
			tailOnce.Stdout = os.Stdout
			tailOnce.Stderr = os.Stderr
			// Run without buildExec.Run so behavior is consistent even if ShouldRunAsRoot=false.
			// But still respect context/privilege: use buildExec.Run if desired; it's okay either way.
			_ = buildExec.Run(tailOnce)
		}

		return 0, runErr
	}

	// success
	elapsed := time.Since(startTime).Truncate(time.Second)
	debugf("\n%s built successfully in %s, output in %s\n", pkgName, elapsed, outputDir)

	if err := runSplitScript(pkgDir, outputDir, splitRoot, version, pkgName, buildExec, env, opts); err != nil {
		return 0, err
	}

	// Determine output package name (rename if cross-system is enabled)
	outputPkgName := getArchivePackageName(pkgName, cfg)

	debugf("%s built successfully, output in %s\n", pkgName, outputDir)

	elapsed = time.Since(startTime)

	// Determine architecture and flags for metadata
	targetArch := defaults["HOKUTO_ARCH"]
	cflagsVal := defaults["CFLAGS"]

	// Determine if this is a generic build
	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]

	// If ARM64, it's ONLY generic if cross-simple/nocrossopt/cross-system was used or CFLAGS_ARM64 was missing
	if !isGeneric && targetArch == "aarch64" {
		if options["nocrossopt"] || cfg.Values["HOKUTO_CROSS_SIMPLE"] == "1" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" || cfg.Values["CFLAGS_ARM64"] == "" {
			isGeneric = true
		}
	} else if !isGeneric && cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		// For other cross builds, default to generic for now
		isGeneric = true
	}

	if err := finalizeBuiltPackage(builtPackageFinalization{
		sourcePkgName: pkgName,
		outputPkgName: outputPkgName,
		pkgDir:        pkgDir,
		outputDir:     outputDir,
		version:       version,
		revision:      revision,
		targetArch:    targetArch,
		cflagsVal:     cflagsVal,
		logPath:       logPath,
		options:       options,
		buildExec:     buildExec,
		logger:        opts.LogWriter,
		started:       startTime,
		elapsed:       elapsed,
		shouldStrip:   shouldStrip,
		isGeneric:     isGeneric,
		bootstrap:     opts.Bootstrap,
		updateWebsite: opts.UpdateWebsite,
	}); err != nil {
		return 0, err
	}

	if err := packageSplitOutputs(pkgName, pkgDir, splitRoot, version, revision, targetArch, cflagsVal, isGeneric, shouldStrip, buildExec, cfg, opts, elapsed); err != nil {
		return 0, err
	}

	// Cleanup tmpdirs
	if Debug {
		debugf("INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", pkgTmpDir)
	} else {
		debugf("INFO: Cleaning up pkgTmpDir: %s\n", pkgTmpDir)
		rmCmd := exec.Command("rm", "-rf", pkgTmpDir)
		if err := RootExec.Run(rmCmd); err != nil {
			fmt.Fprintf(os.Stderr, "failed to cleanup build tmpdirs: %v\n", err)
		}
	}

	// Build SUCCESSFUL: Set title to success status
	finalTitle := fmt.Sprintf("✅ SUCCESS: %s", pkgName)
	setTerminalTitle(finalTitle)
	debugf("HOKUTO ROOT IS %s\n", rootDir)
	if err := updateOptionalRebuildTracker(pkgName, optionalBuildState); err != nil {
		debugf("failed to update optional rebuild tracker for %s: %v\n", pkgName, err)
	}
	return time.Since(startTime), nil

}

// pkgBuildRebuild is used after an uninstall/upgrade to rebuild dependent packages.
// It skips tarball creation, cleanup, and runs with an adjusted environment.
// oldLibsDir is the path to the temporary directory containing backed-up libraries.

// pkgBuildRebuild rebuilds a package that was triggered by another package install.
func pkgBuildRebuild(pkgName string, cfg *Config, execCtx *Executor, oldLibsDir string, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}

	// CLONE CONFIG to avoid race conditions.
	// pkgBuildRebuild modifies cfg.Values (e.g. for cross-compilation settings), so we need an isolated copy.
	cfgCopy := &Config{
		Values:       make(map[string]string, len(cfg.Values)),
		DefaultStrip: cfg.DefaultStrip,
		DefaultLTO:   cfg.DefaultLTO,
	}
	maps.Copy(cfgCopy.Values, cfg.Values)
	cfg = cfgCopy // Use the copy for the rest of this function

	// Define the ANSI escape code format for setting the terminal title.
	// \033]0; sets the title, and \a (bell character) terminates the sequence.
	const setTitleFormat = "\033]0;%s\a"

	// Helper function to set the title in the TTY.
	setTerminalTitle := func(title string) {
		//Outputting directly to os.Stdout sets the title in the terminal session.
		fmt.Printf(setTitleFormat, title)
	}

	// Track build time
	startTime := time.Now()

	// Determine package source directory
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return fmt.Errorf("package %s not found in HOKUTO_PATH: %w", pkgName, err)
	}

	// NEW: Load build options (consolidated from 'options' file or individual files)
	options := loadBuildOptions(pkgDir)

	// 1. Initialize a LOCAL temporary directory variable with the global default.
	currentTmpDir := tmpDir
	// override tmpDir if noram is set
	if options["noram"] {
		currentTmpDir = cfg.Values["TMPDIR2"]
	}

	// --- Setup (Same as pkgBuild) ---
	pkgTmpDir := filepath.Join(currentTmpDir, pkgName)
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")
	logDir := filepath.Join(pkgTmpDir, "log")

	// First try to cleanup pkgTmpDir with Go's os.RemoveAll
	if err := os.RemoveAll(pkgTmpDir); err != nil {
		// If that fails, fall back to system rm -rf with rootExec
		rmCmd := exec.Command("rm", "-rf", pkgTmpDir)
		if err2 := RootExec.Run(rmCmd); err2 != nil {
			return fmt.Errorf("failed to clean pkgTmpDir %s: %v (fallback also failed: %v)", pkgTmpDir, err, err2)
		}
	}

	for _, dir := range []string{buildDir, outputDir, logDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

	// 1. Determine the Execution Context
	needsRootBuild := options["asroot"]

	//Check for an 'interactive' file to control build mode ---
	needsInteractiveBuild := options["interactive"]
	if needsInteractiveBuild {
		debugf("Interactive build mode enabled for %s.\n", pkgName)
	}

	buildExec := &Executor{
		Context:         execCtx.Context,
		ShouldRunAsRoot: needsRootBuild,
		Interactive:     needsInteractiveBuild,
		Stdout:          logger,
		Stderr:          logger,
	}

	// Fetch all sources for the build, including git repositories.
	// Silence output if logger is not stdout (e.g. io.Discard)
	quietFetch := (logger != os.Stdout)
	if err := fetchSourcesWithOptions(pkgName, pkgDir, true, quietFetch); err != nil {
		return fmt.Errorf("failed to fetch sources: %v", err)
	}

	// Perform a strict, non-interactive checksum verification.
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false, logger); err != nil {
		return fmt.Errorf("source verification failed: %w", err)
	}
	// Prepare sources
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	// Disable stripping for cross-compilation
	if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		shouldStrip = false
	}

	if options["nostrip"] {
		if shouldStrip {
			cPrintf(colInfo, "Disabling stripping.\n")
		}
		shouldStrip = false // Override the global setting for this package only
	}

	// Check if LTO should be enabled
	shouldLTO := cfg.DefaultLTO
	if options["nolto"] {
		if logger == nil || logger == os.Stdout {
			cPrintf(colInfo, "Disabling LTO.\n")
		} else {
			fmt.Fprintf(logger, "Disabling LTO.\n")
		}
		shouldLTO = false // Override the global setting for this package only
	}

	// Read version
	versionFile := filepath.Join(pkgDir, "version")
	versionData, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read version file: %v", err)
	}
	fields := strings.Fields(string(versionData))
	if len(fields) == 0 {
		return fmt.Errorf("version file for %s is empty", pkgName)
	}
	version := fields[0]
	revision := "1" // Default revision if not specified
	if len(fields) >= 2 {
		revision = fields[1]
	}

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return fmt.Errorf("build script not found: %v", err)
	}

	// Define the base C/C++/LD flags
	var defaultCFLAGS = "-O2 -march=x86-64-v2 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// Define core count to use
	var numCores int
	if options["idle"] {
		numCores = max(runtime.NumCPU()/2, 1)
		debugf("Idle mode enabled for %s. Using %d cores.\n", pkgName, numCores)
	} else {
		switch buildPriority {
		case "idle":
			numCores = runtime.NumCPU() / 2
			if numCores < 1 {
				numCores = 1
			}
		case "superidle":
			numCores = 1
		default: // "normal"
			numCores = runtime.NumCPU()
		}
	}

	// Jobs for LTO (if enabled)
	ltoJobString := fmt.Sprintf("%d", numCores)
	if options["clang"] {
		ltoJobString = "auto"
		debugf("Using LTOJOBS=auto (clang option).\n")
	} else {
		debugf("Using LTOJOBS=%s.\n", ltoJobString)
	}

	// Initialize Defaults Map
	defaults := map[string]string{
		"AR":                         "gcc-ar",
		"CC":                         "cc",
		"CXX":                        "c++",
		"NM":                         "gcc-nm",
		"RANLIB":                     "gcc-ranlib",
		"MAKEFLAGS":                  fmt.Sprintf("-j%d", numCores),
		"CMAKE_BUILD_PARALLEL_LEVEL": fmt.Sprintf("%d", numCores),
		"GOFLAGS":                    "-trimpath -modcacherw",
		"GOPATH":                     filepath.Join(buildDir, "go"),
		"HOKUTO_ROOT":                rootDir,
		"TMPDIR":                     currentTmpDir,
		"CONFIG_SITE":                ("/usr/share/config.site"),
	}

	if buildPriority == "idle" || buildPriority == "superidle" {
		defaults["HOKUTO_BUILD_PRIORITY"] = buildPriority
	}

	// --- START REFACTORED FLAG LOGIC (Matches pkgBuild) ---

	// 1. Detect Target Architecture
	// -----------------------------
	targetArch := cfg.Values["HOKUTO_CROSS_ARCH"]
	if targetArch == "" {
		targetArch = cfg.Values["HOKUTO_ARCH"]
	}
	if targetArch == "" {
		cmd := exec.Command("uname", "-m")
		out, err := cmd.Output()
		if err == nil {
			targetArch = strings.TrimSpace(string(out))
		} else {
			targetArch = runtime.GOARCH
		}
	}
	if targetArch == "amd64" {
		targetArch = "x86_64"
	}
	if targetArch == "arm64" {
		targetArch = "aarch64"
	}

	isX86 := (targetArch == "x86_64")
	isARM := (targetArch == "aarch64")

	// 2. Apply Architecture Constraints
	// ---------------------------------
	if !isX86 && shouldLTO {
		debugf("Disabling LTO for %s architecture (rebuild).\n", targetArch)
		shouldLTO = false
	}
	if shouldLTO {
		defaults["HOKUTO_LTO"] = "1"
	} else {
		defaults["HOKUTO_LTO"] = "0"
	}

	multilibVal := "0"
	if isX86 && cfg.Values["HOKUTO_MULTILIB"] == "1" {
		multilibVal = "1"
	} else if cfg.Values["HOKUTO_MULTILIB"] == "1" {
		debugf("Disabling MULTILIB for %s architecture (rebuild).\n", targetArch)
	}

	// Add CPU Flags to environment
	cpuFlags := ""
	if !HokutoGeneric { // Only enable if NOT in generic mode
		if isX86 {
			cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS_X86"]
			if cpuFlags == "" {
				cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS"] // legacy/fallback
			}
			defaults["CPU_FLAGS_X86"] = cpuFlags
		} else if isARM {
			cpuFlags = cfg.Values["HOKUTO_CPU_FLAGS_ARM"]
			defaults["CPU_FLAGS_ARM"] = cpuFlags
		}
	}
	defaults["CPUFLAGS"] = cpuFlags

	// 3. Select Compiler Flags
	var cflagsVal, cxxflagsVal, ldflagsVal string

	// Check if cross-compilation is enabled
	isCross := cfg.Values["HOKUTO_CROSS_ARCH"] != ""
	isCrossSystem := cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1"
	shouldBuildHostNative := options["host-tool"] && isCrossSystem

	if isCross && !shouldBuildHostNative {
		// Use cross tools unless it's explicitly a host-tool for cross-system build
		toolchainPrefix := targetArch + "-linux-gnu-"
		defaults["CC"] = toolchainPrefix + "gcc"
		defaults["CXX"] = toolchainPrefix + "g++"
		defaults["AR"] = toolchainPrefix + "ar"
		defaults["RANLIB"] = toolchainPrefix + "ranlib"
	}

	if isARM {
		// Case A: ARM64 (Native or Cross)
		// Use optimized flags unless explicitly disabled, in simple cross mode, or cross-system build
		if !options["nocrossopt"] && cfg.Values["HOKUTO_CROSS_SIMPLE"] != "1" && cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1" && cfg.Values["CFLAGS_ARM64"] != "" {
			cflagsVal = cfg.Values["CFLAGS_ARM64"]
			cxxflagsVal = cfg.Values["CXXFLAGS_ARM64"]
		} else {
			cflagsVal = "-O2 -pipe -mtune=generic"
			cxxflagsVal = "-O2 -pipe -mtune=generic"
		}
		ldflagsVal = cfg.Values["LDFLAGS"]
	} else if shouldLTO {
		// Case B: x86_64 with LTO
		cflagsVal = cfg.Values["CFLAGS_LTO"]
		cxxflagsVal = cfg.Values["CXXFLAGS_LTO"]
		ldflagsVal = cfg.Values["LDFLAGS_LTO"]
	} else {
		// Case C: Standard (LTO disabled or x86 without LTO config)
		cflagsVal = cfg.Values["CFLAGS"]
		cxxflagsVal = cfg.Values["CXXFLAGS"]
		ldflagsVal = cfg.Values["LDFLAGS"]
	}

	// Fallbacks
	// When cross-compiling, if CFLAGS_ARM64 is not set, fall back to CFLAGS (which will be sanitized)
	if cflagsVal == "" {
		if isCross {
			cflagsVal = cfg.Values["CFLAGS"]
		}
		if cflagsVal == "" {
			cflagsVal = defaultCFLAGS
		}
	}
	if cxxflagsVal == "" {
		if isCross {
			cxxflagsVal = cfg.Values["CXXFLAGS"]
		}
		if cxxflagsVal == "" {
			cxxflagsVal = cflagsVal
		}
	}
	if ldflagsVal == "" {
		ldflagsVal = defaultLDFLAGS
	}

	// --- FIX: Apply Substitution ALWAYS ---
	// This ensures that if CFLAGS_ARM64 or standard CFLAGS contains "LTOJOBS",
	// it gets resolved correctly instead of breaking the build.
	cflagsVal = strings.ReplaceAll(cflagsVal, "LTOJOBS", ltoJobString)
	cxxflagsVal = strings.ReplaceAll(cxxflagsVal, "LTOJOBS", ltoJobString)
	ldflagsVal = strings.ReplaceAll(ldflagsVal, "LTOJOBS", ltoJobString)

	// --- FIX: Sanitize flags for cross-compilation ---
	// Remove -march=native and -mtune=native when cross-compiling
	if isCross {
		crossArch := cfg.Values["HOKUTO_CROSS_ARCH"]
		normalizedArch := crossArch
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		cflagsVal = sanitizeFlagsForCrossCompilation(cflagsVal, normalizedArch)
		cxxflagsVal = sanitizeFlagsForCrossCompilation(cxxflagsVal, normalizedArch)
	}

	// 4. Apply Linker Logic (Mold)
	// ----------------------------
	if !shouldLTO {
		useMold := checkPackageExactMatch("mold")
		if useMold {
			ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=bfd", "-fuse-ld=mold")
			ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=gold", "-fuse-ld=mold")
		} else {
			ldflagsVal = strings.ReplaceAll(ldflagsVal, "-fuse-ld=mold", "-fuse-ld=bfd")
		}
	}

	// 5. Update defaults map
	// ----------------------
	defaults["CFLAGS"] = cflagsVal
	defaults["CXXFLAGS"] = cxxflagsVal
	defaults["LDFLAGS"] = ldflagsVal
	defaults["HOKUTO_ARCH"] = targetArch
	defaults["MULTILIB"] = multilibVal

	// Build RUSTFLAGS based on finalized CFLAGS and CPU flags
	defaults["RUSTFLAGS"] = buildRustFlags(cflagsVal, cpuFlags, buildDir, HokutoGeneric)

	// Ensure CROSS_PREFIX/bin is in PATH for cross-compilation
	if isCross {
		normalizedArch := targetArch
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		prefix := fmt.Sprintf("/usr/%s-linux-gnu", normalizedArch)
		defaults["PATH"] = os.Getenv("PATH") + ":" + filepath.Join(prefix, "bin")
	}

	// Rust cross-compilation setup for pkgBuildRebuild
	if isCross {
		normalizedArch := targetArch
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}

		var rustTarget string
		switch normalizedArch {
		case "aarch64":
			rustTarget = "aarch64-unknown-linux-gnu"
		case "x86_64":
			rustTarget = "x86_64-unknown-linux-gnu"
		default:
			rustTarget = normalizedArch + "-unknown-linux-gnu"
		}

		defaults["CARGO_BUILD_TARGET"] = rustTarget
		linkerEnvVar := "CARGO_TARGET_" + strings.ToUpper(strings.ReplaceAll(rustTarget, "-", "_")) + "_LINKER"
		defaults[linkerEnvVar] = normalizedArch + "-linux-gnu-gcc"

		debugf("Rust cross-compilation (rebuild): target=%s, linker_var=%s, linker=%s\n",
			rustTarget, linkerEnvVar, defaults[linkerEnvVar])
	}

	// Set QEMU_LD_PREFIX for cross-compilation to allow running target binaries via QEMU
	// The cross toolchain and libraries are always in /usr/<arch>-linux-gnu
	if isCross {
		normalizedArch := targetArch
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		sysroot := fmt.Sprintf("/usr/%s-linux-gnu", normalizedArch)
		defaults["QEMU_LD_PREFIX"] = sysroot
	}
	// --- END REFACTORED FLAG LOGIC ---

	// Inject HOKUTO_REAL_USER
	helperDir := filepath.Join(buildDir, ".hokuto-tools")
	if err := writeBuildHelperScripts(helperDir); err != nil {
		return fmt.Errorf("failed to create build helper scripts: %w", err)
	}
	if defaults["PATH"] != "" {
		defaults["PATH"] = helperDir + ":" + defaults["PATH"]
	} else {
		defaults["PATH"] = helperDir + ":" + os.Getenv("PATH")
	}

	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		realUser = os.Getenv("USER")
	}
	defaults["HOKUTO_REAL_USER"] = realUser

	// Prepare Environment Array
	// Start with environment, but filter out CFLAGS/CXXFLAGS/LDFLAGS to avoid conflicts
	// Our defaults should take precedence
	env := []string{}
	for _, e := range os.Environ() {
		// Skip CFLAGS, CXXFLAGS, and LDFLAGS from environment - we'll set them from defaults
		if strings.HasPrefix(e, "CFLAGS=") || strings.HasPrefix(e, "CXXFLAGS=") || strings.HasPrefix(e, "LDFLAGS=") || strings.HasPrefix(e, "HOKUTO_LTO=") {
			continue
		}
		env = append(env, e)
	}

	// Prepend oldLibsDir to PATH and LD_LIBRARY_PATH for tools run by the Executor
	// This allows system tools (tar, rsync, cp) used by the Executor to function,
	// even if they depend on the newly removed libraries.
	// The build script itself *should not* rely on the executor's PATH/LD_LIBRARY_PATH
	// for finding its own build dependencies.
	oldLibBin := filepath.Join(oldLibsDir, "bin")
	oldLibUsrBin := filepath.Join(oldLibsDir, "usr", "bin")
	oldLibLib := filepath.Join(oldLibsDir, "lib")
	oldLibUsrLib := filepath.Join(oldLibsDir, "usr", "lib")

	// Update PATH
	currentPath := os.Getenv("PATH")
	if defaults["PATH"] != "" {
		currentPath = defaults["PATH"]
	}
	newPath := fmt.Sprintf("PATH=%s:%s:%s", oldLibBin, oldLibUsrBin, currentPath)
	env = append(env, newPath)

	// Update LD_LIBRARY_PATH
	currentLdLibPath := os.Getenv("LD_LIBRARY_PATH")
	if defaults["LD_LIBRARY_PATH"] != "" {
		currentLdLibPath = defaults["LD_LIBRARY_PATH"]
	}
	newLdLibPath := fmt.Sprintf("LD_LIBRARY_PATH=%s:%s:%s", oldLibLib, oldLibUsrLib, currentLdLibPath)
	env = append(env, newLdLibPath)

	// 5. Final loop to assemble the environment array
	for k, def := range defaults {
		// PATH and LD_LIBRARY_PATH were already handled specially above
		if k == "PATH" || k == "LD_LIBRARY_PATH" {
			continue
		}

		// Append the build variable and its calculated value.
		env = append(env, fmt.Sprintf("%s=%s", k, def))
	}

	// Run build script
	debugf("Rebuilding %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	// 1. Define the log file path
	logPath := filepath.Join(logDir, "build-log.txt")
	optionalBuildState := snapshotOptionalBuildDependencies(pkgDir, cfg)
	declaredBuildDeps, installedBuildDeps := buildLogDependencies(pkgDir, cfg, optionalBuildState)
	if err := writeBuildLogHeader(logPath, pkgName, version, revision, startTime, declaredBuildDeps, installedBuildDeps); err != nil {
		return fmt.Errorf("failed to initialize rebuild log: %w", err)
	}
	// Ensure logDir exists (already created above, but ensure it's there)
	// script appends its PTY output after the structured header.

	// Use script command to create a PTY, preserving colors and progress bars
	// Build the command string to execute
	cmdStr := fmt.Sprintf("cd %s && %s %s %s %s", buildDir, buildScript, outputDir, version, pkgName)

	// Use script to create PTY and preserve colors
	// -q: quiet mode (don't print script start/end messages)
	// -f: flush output immediately (for real-time viewing)
	// -c: command to run
	// script writes the PTY session to the log file automatically
	// script also outputs to stdout/stderr, which we capture for console
	cmd := exec.Command("script", "-q", "-f", "-a", "-c", cmdStr, logPath)
	cmd.Dir = buildDir

	// Set up environment with color support
	cmd.Env = make([]string, len(env))
	copy(cmd.Env, env)

	// Set TERM environment variable to ensure color support
	cmd.Env = append(cmd.Env, "TERM=xterm-256color")

	// Force color output for common build tools
	cmd.Env = append(cmd.Env, "CARGO_TERM_COLOR=always") // Rust/Cargo
	cmd.Env = append(cmd.Env, "CLICOLOR_FORCE=1")        // General Unix tools
	cmd.Env = append(cmd.Env, "FORCE_COLOR=1")           // Node.js tools

	// script writes to the log file automatically (last argument)
	// script also outputs to stdout/stderr (duplicate of log file content)
	// Important: script needs valid stdout/stderr to create a PTY properly
	// When verbose is disabled, redirect to /dev/null to suppress console output
	// The log file will still contain all the output
	if buildExec.Interactive || Verbose || Debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		// Forward stdin in interactive mode so user can respond to prompts
		if buildExec.Interactive {
			cmd.Stdin = os.Stdin
		}
	} else {
		// Suppress console output but give script valid file descriptors
		devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("failed to open /dev/null: %w", err)
		}
		defer devNull.Close()
		cmd.Stdout = devNull
		cmd.Stderr = devNull
	}

	var runErr error // Use a single error variable for both paths

	// Run script - use Executor only when root is needed (for asroot packages)
	// For normal builds, run directly to preserve TTY/PTY access
	if !buildExec.Interactive {
		// --- NON-INTERACTIVE PATH: Run with timer and title updates ---
		setTerminalTitle(fmt.Sprintf("Rebuilding %s", pkgName))
		doneCh := make(chan struct{})
		var runWg sync.WaitGroup
		runWg.Add(1)

		go func() {
			defer runWg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					elapsed := time.Since(startTime).Truncate(time.Second)
					title := fmt.Sprintf("Rebuild %s elapsed: %s", pkgName, elapsed)
					setTerminalTitle(title)
					// Only print elapsed time to console if not in verbose mode AND logger is stdout (not silent)
					// In verbose mode, the build output is already visible, so we only update the title
					// In silent mode (parallel rebuild), we don't want to spam the console
					if !Verbose && logger == os.Stdout {
						colArrow.Print("-> ")
						colSuccess.Printf("Building %s elapsed: %s\r", pkgName, elapsed)
					}
				case <-doneCh:
					if !Verbose && logger == os.Stdout {
						fmt.Print("\r")
					}
					return
				case <-buildExec.Context.Done():
					return
				}
			}
		}()

		// Run script - use Executor only when root is needed (for asroot packages)
		// For normal builds, run directly to preserve TTY/PTY access
		// Note: script always returns 0, but writes the actual exit code to the log file
		// We need to check the log file for COMMAND_EXIT_CODE
		if buildExec.ShouldRunAsRoot {
			if err := buildExec.Run(cmd); err != nil {
				runErr = fmt.Errorf("build failed: %w", err)
			} else {
				// Check the exit code from the log file
				if exitCode := getScriptExitCode(logPath); exitCode != 0 {
					runErr = fmt.Errorf("build script exited with code %d", exitCode)
				}
			}
		} else {
			if err := cmd.Run(); err != nil {
				runErr = fmt.Errorf("build failed: %w", err)
			} else {
				// Check the exit code from the log file
				if exitCode := getScriptExitCode(logPath); exitCode != 0 {
					runErr = fmt.Errorf("build script exited with code %d", exitCode)
				}
			}
		}

		// Stop ticker goroutine and wait.
		close(doneCh)
		runWg.Wait()
	} else {
		// --- INTERACTIVE PATH: Use Executor only when root is needed (for asroot packages)
		// Note: script always returns 0, but writes the actual exit code to the log file
		if buildExec.ShouldRunAsRoot {
			if err := buildExec.Run(cmd); err != nil {
				runErr = fmt.Errorf("build failed: %w", err)
			} else {
				// Check the exit code from the log file
				if exitCode := getScriptExitCode(logPath); exitCode != 0 {
					runErr = fmt.Errorf("build script exited with code %d", exitCode)
				}
			}
		} else {
			if err := cmd.Run(); err != nil {
				runErr = fmt.Errorf("build failed: %w", err)
			} else {
				// Check the exit code from the log file
				if exitCode := getScriptExitCode(logPath); exitCode != 0 {
					runErr = fmt.Errorf("build script exited with code %d", exitCode)
				}
			}
		}
	}

	// Check the single runErr variable (compiler knows it may be non-nil)
	if runErr != nil {
		if err := appendBuildLogStatus(logPath, pkgName, "failed", startTime, buildExec); err != nil {
			debugf("Warning: failed to append rebuild failure status: %v\n", err)
		}
		cPrintf(colError, "\nBuild failed for %s: %v\n", pkgName, runErr)

		// Set title to warning status
		finalTitle := fmt.Sprintf("❌ FAILED: %s", pkgName)
		setTerminalTitle(finalTitle)

		// Path to the build log (script creates and writes to this file)
		logPath := filepath.Join(logDir, "build-log.txt")

		// If interactive, let user follow the log; otherwise show last N lines and continue.
		if buildExec.Interactive {
			tailCmd := exec.Command("tail", "-n", "50", "-f", logPath)
			tailCmd.Stdin = os.Stdin
			tailCmd.Stdout = os.Stdout
			tailCmd.Stderr = os.Stderr
			_ = buildExec.Run(tailCmd)
		} else {
			// Non-interactive: just print the last 50 lines and don't block.
			tailOnce := exec.Command("tail", "-n", "50", logPath)
			// Do NOT attach Stdin for non-interactive mode (avoid blocking).
			tailOnce.Stdout = os.Stdout
			tailOnce.Stderr = os.Stderr
			_ = buildExec.Run(tailOnce)
		}

		return runErr
	}

	// success
	elapsed := time.Since(startTime).Truncate(time.Second)
	debugf("\n%s built successfully in %s, output in %s\n", pkgName, elapsed, outputDir)

	// Determine output package name (rename if cross-system is enabled)
	outputPkgName := getArchivePackageName(pkgName, cfg)

	debugf("%s built successfully, output in %s\n", pkgName, outputDir)

	elapsed = time.Since(startTime)

	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || cfg.Values["HOKUTO_CROSS_ARCH"] != "" || options["generic"]
	if err := finalizeBuiltPackage(builtPackageFinalization{
		sourcePkgName: pkgName,
		outputPkgName: outputPkgName,
		pkgDir:        pkgDir,
		outputDir:     outputDir,
		version:       version,
		revision:      revision,
		targetArch:    targetArch,
		cflagsVal:     cflagsVal,
		logPath:       logPath,
		options:       options,
		buildExec:     buildExec,
		logger:        logger,
		started:       startTime,
		elapsed:       elapsed,
		shouldStrip:   shouldStrip,
		isGeneric:     isGeneric,
		bootstrap:     false,
	}); err != nil {
		return err
	}

	//Set title to success status
	finalTitle := fmt.Sprintf("✅ SUCCESS: %s", pkgName)
	setTerminalTitle(finalTitle)
	if err := updateOptionalRebuildTracker(pkgName, optionalBuildState); err != nil {
		debugf("failed to update optional rebuild tracker for %s: %v\n", pkgName, err)
	}

	// Note: We skip cleanup of outputDir here to allow pkgInstall to sync from it.
	return nil
}

// handleBuildCommand orchestrates the entire build process, intelligently selecting the
// correct dependency resolution strategy based on the build mode (normal, bootstrap, or alldeps).
func handleBuildCommand(args []string, cfg *Config) (err error) {
	// Preprocess arguments to handle custom flag formats (e.g. -j4)
	args = PreprocessBuildArgs(args)

	// --- 1. Flag Parsing & Initial Setup ---
	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	var autoInstall = buildCmd.Bool("a", false, "Automatically install the package(s) after successful build.")
	var idleBuild = buildCmd.Bool("i", false, "Use half CPU cores and lowest niceness for build process.")
	var superidleBuild = buildCmd.Bool("ii", false, "Use one CPU core and lowest niceness for build process.")
	var verbose = buildCmd.Bool("v", false, "Enable verbose output.")
	var verboseLong = buildCmd.Bool("verbose", false, "Enable verbose output.")
	var debug = buildCmd.Bool("debug", false, "Enable debug output (HOKUTO_DEBUG=1).")
	var bootstrap = buildCmd.Bool("bootstrap", false, "Enable bootstrap build mode.")
	var bootstrapDir = buildCmd.String("bootstrap-dir", "", "Specify the bootstrap directory.")
	var allDeps = buildCmd.Bool("alldeps", false, "Force rebuild of all dependencies")
	var withRebuilds = buildCmd.Bool("rebuilds", false, "Enable post-build actions for dependencies marked with 'rebuild'.")
	var withRebuildsShort = buildCmd.Bool("r", false, "Alias for -rebuilds.")
	var ask = buildCmd.Bool("ask", false, "Show the build plan and ask before building or installing build dependencies.")
	var orderedBuild = buildCmd.Bool("ordered", false, "Force build order based on the target package's depends file.")
	var genericBuild = buildCmd.Bool("generic", false, "Use _GEN flags and store packages in generic subfolder")
	var crossArch = buildCmd.String("cross", "", "Enable cross-compilation for target architecture (e.g., arm64)")
	var noDeps = buildCmd.Bool("no-deps", false, "Skip dependency checking and build only the specified package(s)")
	var noDevel = buildCmd.Bool("no-devel", false, "Skip automatic base-devel dependency installation")
	var noCleanup = buildCmd.Bool("no-cleanup", false, "Keep temporary build dependencies installed after the build")
	var noInstall = buildCmd.Bool("no-install", false, "Build packages without installing final user targets")
	var noRemote = buildCmd.Bool("no-remote", false, "Do not use the remote binary mirror for build dependency resolution or installs")
	var promptBinaryDeps = buildCmd.Bool("prompt", false, "Prompt before installing available binary build dependencies.")
	var wgetNoCheckCert = buildCmd.Bool("wget-no-check-certificate", false, "Pass --no-check-certificate to wget fallback for source downloads")
	var parallel = buildCmd.Int("j", 1, "Number of parallel jobs (default: 1)")
	var parallelLong = buildCmd.Int("parallel", 1, "Number of parallel jobs (default: 1)")
	var updateWebsite = buildCmd.Bool("index", false, "Update the github.io status table.")

	// Custom usage function that excludes bootstrap flags from help
	buildCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: hokuto build [options] <package>\n\n")
		buildCmd.VisitAll(func(f *flag.Flag) {
			// Skip bootstrap flags in help output
			if f.Name == "bootstrap" || f.Name == "bootstrap-dir" {
				return
			}
			s := fmt.Sprintf("  -%s", f.Name)
			name, usage := flag.UnquoteUsage(f)
			if len(name) > 0 {
				s += " " + name
			}
			// Boolean flags of one ASCII letter are so common we
			// treat them specially, putting their usage on the same line.
			if len(s) <= 4 { // space, -, flag, space
				s += "\t"
			} else {
				s += "\n    \t"
			}
			s += strings.ReplaceAll(usage, "\n", "\n    \t")
			fmt.Fprint(os.Stderr, s, "\n")
		})
	}

	if err := buildCmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing build flags: %v", err)
	}
	if *debug {
		enableRuntimeDebug(cfg)
	}
	if *noInstall && *autoInstall {
		return fmt.Errorf("--no-install and -a cannot be used together")
	}
	if *noDeps {
		defer suppressRuntimeDependencyAutoInstallScope()()
	}
	defer binaryOnlyRuntimeDependencyInstallScope()()
	endBuildSession := registerHokutoBuildSession()
	defer endBuildSession()
	defer func() {
		if err == nil {
			flushPackageSuggestions(os.Stdout, cfg, *noRemote, true, false)
			return
		}
		discardPackageSuggestions()
	}()
	oldWgetNoCheckCertificate := wgetNoCheckCertificate
	wgetNoCheckCertificate = *wgetNoCheckCert
	defer func() { wgetNoCheckCertificate = oldWgetNoCheckCertificate }()
	maxJobs := *parallel
	if *parallelLong > maxJobs {
		maxJobs = *parallelLong
	}
	// Temporary build dependency installs should use the same quiet/fast path
	// regardless of parallelism; the build output itself provides the progress.
	quietDependencyInstalls := true

	effectiveRebuilds := *withRebuilds || *withRebuildsShort
	// Set the global variables based on the parsed flags
	// Determine the build priority. Super idle takes precedence over idle.
	if *superidleBuild {
		buildPriority = "superidle"
	} else if *idleBuild {
		buildPriority = "idle"
	} else {
		buildPriority = "normal"
	}
	Verbose = *verbose || *verboseLong
	UpdateWebsiteIndex = *updateWebsite

	// Handle generic build flag
	if *genericBuild {
		cfg.Values["HOKUTO_GENERIC"] = "1"
		// Set CXXFLAGS_GEN and CXXFLAGS_GEN_LTO to match CFLAGS_GEN and CFLAGS_GEN_LTO
		// Set CXXFLAGS_GEN and CXXFLAGS_GEN_LTO to match CFLAGS_GEN and CFLAGS_GEN_LTO
		if cfg.Values["CFLAGS_GEN"] != "" {
			cfg.Values["CXXFLAGS_GEN"] = cfg.Values["CFLAGS_GEN"]
		}
		if cfg.Values["CFLAGS_GEN_LTO"] != "" {
			cfg.Values["CXXFLAGS_GEN_LTO"] = cfg.Values["CFLAGS_GEN_LTO"]
		}
	}

	// Handle cross-compilation flag
	if *crossArch != "" {
		// Parse cross flag: format is "arch", "arch,system", or "arch,simple"
		parts := strings.Split(*crossArch, ",")
		crossArchValue := strings.TrimSpace(parts[0])
		crossSystem := ""
		if len(parts) > 1 {
			crossSystem = strings.TrimSpace(parts[1])
		}

		// Validate architecture (currently only arm64 is valid)
		if crossArchValue != "arm64" {
			return fmt.Errorf("error: invalid cross-compilation architecture '%s'. only 'arm64' is currently supported", crossArchValue)
		}
		// Store cross architecture and system/simple flag in config for use in pkgBuild
		if cfg.Values == nil {
			cfg.Values = make(map[string]string)
		}
		cfg.Values["HOKUTO_CROSS_ARCH"] = crossArchValue
		switch crossSystem {
		case "system":
			cfg.Values["HOKUTO_CROSS_SYSTEM"] = "1"
		case "simple":
			cfg.Values["HOKUTO_CROSS_SIMPLE"] = "1"
		}
	}

	// --- Bootstrap Repository & Path Setup ---
	if *bootstrap {
		if *bootstrapDir == "" {
			return fmt.Errorf("error: bootstrap requires bootstrap-dir")
		}
		if cfg.Values == nil {
			cfg.Values = make(map[string]string)
		}
		cfg.Values["LFS"] = *bootstrapDir
		cfg.Values["HOKUTO_ROOT"] = *bootstrapDir
		cfg.Values["HOKUTO_CACHE_DIR"] = filepath.Join(*bootstrapDir, "var", "cache", "hokuto")
		cfg.Values["HOKUTO_BOOTSTRAP"] = "1"
		// Disable signature verification during bootstrap
		cfg.Values["HOKUTO_VERIFY_SIGNATURE"] = "0"
		VerifySignature = false

		if fi, err := os.Stat("/repo/bootstrap"); err == nil && fi.IsDir() {
			cfg.Values["HOKUTO_PATH"] = "/repo/bootstrap"
		} else if fi, err := os.Stat("/tmp/repo/bootstrap"); err == nil && fi.IsDir() {
			cfg.Values["HOKUTO_PATH"] = "/tmp/repo/bootstrap"
		} else {
			cfg.Values["HOKUTO_PATH"] = "/tmp/repo/bootstrap"
			// Need to download and unpack into /tmp/repo
			url := "https://github.com/sauzeros/bootstrap/releases/download/latest/bootstrap-repo.tar.xz"
			tmpFile := filepath.Join(os.TempDir(), "bootstrap-repo.tar.xz")
			colArrow.Print("-> ")
			colSuccess.Printf("Downloading bootstrap repo from %s\n", url)
			resp, err := simpleHTTPClient().Get(url)
			if err != nil {
				return fmt.Errorf("failed to download bootstrap repo: %v", err)
			}
			defer resp.Body.Close()

			out, err := os.Create(tmpFile)
			if err != nil {
				return fmt.Errorf("failed to create temp file: %v", err)
			}
			if _, err := io.Copy(out, resp.Body); err != nil {
				out.Close()
				return fmt.Errorf("failed to save bootstrap archive: %v", err)
			}
			out.Close()

			// Unpack into /tmp/repo
			colArrow.Print("-> ")
			colSuccess.Println("Unpacking bootstrap repo into /tmp/repo")

			extractDir := filepath.Join(os.TempDir(), "repo")
			if err := os.MkdirAll(extractDir, 0o755); err != nil {
				return fmt.Errorf("failed to create extract dir %s: %v", extractDir, err)
			}

			f, err := os.Open(tmpFile)
			if err != nil {
				return fmt.Errorf("failed to open downloaded archive: %v", err)
			}
			defer f.Close()

			xzr, err := xz.NewReader(f)
			if err != nil {
				return fmt.Errorf("failed to create xz reader: %v", err)
			}
			tr := tar.NewReader(xzr)
			for {
				hdr, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return fmt.Errorf("error reading tar: %v", err)
				}
				target := filepath.Join(extractDir, hdr.Name)
				switch hdr.Typeflag {
				case tar.TypeDir:
					if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
						return fmt.Errorf("failed to create dir %s: %v", target, err)
					}
				case tar.TypeReg:
					if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
						return fmt.Errorf("failed to create parent dir: %v", err)
					}
					outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
					if err != nil {
						return fmt.Errorf("failed to create file %s: %v", target, err)
					}
					if _, err := io.Copy(outFile, tr); err != nil {
						outFile.Close()
						return fmt.Errorf("failed to write file %s: %v", target, err)
					}
					outFile.Close()
				case tar.TypeSymlink:
					if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
						return fmt.Errorf("failed to create symlink %s -> %s: %v", target, hdr.Linkname, err)
					}
					log.Printf("Bootstrap repo unpacked successfully into /tmp/repo")
				}
			}
		}

		// Architecture Selection & Auto-Toolchain Setup
		colArrow.Print("-> ")
		colInfo.Println("Select Target Architecture:")
		colInfo.Println("  1. x86_64 (Intel/AMD) - Default")
		colInfo.Println("  2. aarch64 (Raspberry Pi 4 / ARM64)")
		fmt.Print("Enter choice [1/2]: ")

		var archChoice string
		fmt.Scanln(&archChoice)

		if strings.TrimSpace(archChoice) == "2" {
			cfg.Values["HOKUTO_ARCH"] = "aarch64"
			colSuccess.Println("Target set to AArch64.")
			// Multilib is always disabled for aarch64
			cfg.Values["HOKUTO_MULTILIB"] = "0"
			colWarn.Println("Multilib support disabled for bootstrap.")
		} else {
			// x86_64 selected - ask about multilib
			if askForConfirmation(colInfo, "Enable Multilib support?") {
				cfg.Values["HOKUTO_MULTILIB"] = "1"
				colSuccess.Println("Multilib support enabled for bootstrap.")
			} else {
				// Ensure it is unset
				cfg.Values["HOKUTO_MULTILIB"] = "0"
				colWarn.Println("Multilib support disabled for bootstrap.")
			}
			cfg.Values["HOKUTO_ARCH"] = "x86_64"
			colSuccess.Println("Target set to x86_64.")
		}

		// GNU Mirror Selection
		colArrow.Print("-> ")
		colInfo.Println("Select GNU Mirror:")
		colInfo.Println("  1. TH: https://mirror.cyberbits.asia/gnu/ - Default")
		colInfo.Println("  2. EU: https://mirror.cyberbits.eu/gnu/")
		colInfo.Println("  3. US: https://mirrors.ocf.berkeley.edu/gnu/")
		fmt.Print("Enter choice [1-3] (default: 1): ")

		var mirrorChoice string
		fmt.Scanln(&mirrorChoice)
		mirrorChoice = strings.TrimSpace(mirrorChoice)

		switch mirrorChoice {
		case "2":
			cfg.Values["GNU_MIRROR"] = "https://mirror.cyberbits.eu/gnu/"
			colSuccess.Println("GNU Mirror set to EU.")
		case "3":
			cfg.Values["GNU_MIRROR"] = "https://mirrors.ocf.berkeley.edu/gnu/"
			colSuccess.Println("GNU Mirror set to US.")
		default:
			cfg.Values["GNU_MIRROR"] = "https://mirror.cyberbits.asia/gnu/"
			colSuccess.Println("GNU Mirror set to TH.")
		}

		// LTO Consideration (for config)
		if askForConfirmation(colInfo, "Enable LTO (Link Time Optimization) for the final system?") {
			cfg.Values["SET_HOKUTO_LTO"] = "1"
			colSuccess.Println("LTO will be enabled in the final configuration.")
		} else {
			cfg.Values["SET_HOKUTO_LTO"] = "0"
			colWarn.Println("LTO will be disabled in the final configuration.")
		}

		// Optimization Level (Local vs Generic)
		if cfg.Values["HOKUTO_ARCH"] != "aarch64" {
			colArrow.Print("-> ")
			colInfo.Println("Select Optimization Level:")
			colInfo.Println("  1. Local CPU - Default")
			colInfo.Println("  2. Generic")
			fmt.Print("Enter choice [1/2] (default: 1): ")

			var optChoice string
			fmt.Scanln(&optChoice)
			optChoice = strings.TrimSpace(optChoice)

			if optChoice == "2" {
				cfg.Values["HOKUTO_GENERIC"] = "1"
				colSuccess.Println("Optimization level set to Generic.")
			} else {
				cfg.Values["HOKUTO_GENERIC"] = "0"
				colSuccess.Println("Optimization level set to Local CPU.")
			}
		} else {
			// For aarch64, default to Local but don't set HOKUTO_GENERIC=1
			cfg.Values["HOKUTO_GENERIC"] = "0"
		}

		initConfig(cfg)
	}

	requestedPackages := buildCmd.Args()
	if len(requestedPackages) == 0 {
		buildCmd.Usage()
		return fmt.Errorf("no packages specified")
	}
	userRequestedMap := make(map[string]bool)
	forceBuildMap := make(map[string]bool)
	directSplitTargetsBySource := make(map[string][]string)
	var packagesToProcess []string
	addPackageToProcess := func(pkgName string) {
		for _, existing := range packagesToProcess {
			if existing == pkgName {
				return
			}
		}
		packagesToProcess = append(packagesToProcess, pkgName)
	}
	for _, pkg := range requestedPackages {
		if meta, ok := findInstallMetaPackage(pkg, cfg, nil, !*noRemote); ok {
			targets, splitTargets, collectErr := collectMetaPackageMissingBinaryTargets(meta, cfg, *noRemote)
			if collectErr != nil {
				return fmt.Errorf("cannot expand metapackage %s: %w", pkg, collectErr)
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Metapackage %s: %d source package(s) missing current binaries\n", pkg, len(targets))
			for _, sourcePkg := range targets {
				userRequestedMap[sourcePkg] = true
				forceBuildMap[sourcePkg] = true
				addPackageToProcess(sourcePkg)
				for _, splitPkg := range splitTargets[sourcePkg] {
					addMappedSplitDependency(directSplitTargetsBySource, sourcePkg, splitPkg)
				}
			}
			continue
		}
		sourcePkg, isSplit, targetErr := resolveRequestedBuildTarget(pkg)
		if targetErr != nil {
			return fmt.Errorf("cannot build %s: %w", pkg, targetErr)
		}
		if isSplit {
			userRequestedMap[pkg] = true
			forceBuildMap[sourcePkg] = true
			addPackageToProcess(sourcePkg)
			addMappedSplitDependency(directSplitTargetsBySource, sourcePkg, pkg)
			colArrow.Print("-> ")
			debugf("Target %s is a split package; scheduling %s to build it\n", pkg, sourcePkg)
			continue
		}
		userRequestedMap[pkg] = true
		forceBuildMap[pkg] = true
		addPackageToProcess(pkg)
	}
	for _, pkg := range packagesToProcess {
		if _, err := findPackageDir(pkg); err != nil {
			return fmt.Errorf("cannot build %s: %w", pkg, err)
		}
	}

	// --- SELECT DEPENDENCY STRATEGY and EXECUTE BUILD ---
	var failedBuilds = make(map[string]error)
	var totalElapsedTime time.Duration
	var totalBuildCount int
	var builtWithoutInstallingTargets bool
	var temporaryBuildDeps []string
	retainedBuildDeps := make(map[string]bool)
	buildWorkStarted := false
	orphansAtBuildStart := make(map[string]bool)
	if runtimeOrphans, err := findOrphans(); err == nil {
		for _, pkgName := range runtimeOrphans {
			orphansAtBuildStart[pkgName] = true
		}
	} else {
		debugf("Warning: failed to snapshot runtime orphans before build: %v\n", err)
	}
	if makeOrphans, err := findMakeOrphans(); err == nil {
		for _, pkgName := range makeOrphans {
			orphansAtBuildStart[pkgName] = true
		}
	} else {
		debugf("Warning: failed to snapshot make orphans before build: %v\n", err)
	}
	addTemporaryBuildDep := func(pkgName string) {
		for _, existing := range temporaryBuildDeps {
			if existing == pkgName {
				return
			}
		}
		temporaryBuildDeps = append(temporaryBuildDeps, pkgName)
	}
	retainTemporaryBuildDep := func(pkgName string) {
		if pkgName == "" {
			return
		}
		retainedBuildDeps[pkgName] = true
		retainedBuildDeps[getOutputPackageName(pkgName, cfg)] = true
	}
	cleanupTemporaryBuildDeps := func() {
		if *noCleanup || *bootstrap || *noDevel || !buildWorkStarted {
			return
		}
		cleanupAfterFailure := err != nil
		buildSessionRemovable := func(dep string, seen map[string]bool, removable *[]string, allowPreexisting bool) {
			if dep == "" {
				return
			}
			if !allowPreexisting && orphansAtBuildStart[dep] {
				return
			}
			if retainedBuildDeps[dep] {
				return
			}
			if seen[dep] {
				return
			}
			seen[dep] = true
			*removable = append(*removable, dep)
		}
		removeCandidates := func(candidates []string, allowPreexisting bool) int {
			var removable []string
			seenRemovable := make(map[string]bool)
			for _, dep := range candidates {
				buildSessionRemovable(dep, seenRemovable, &removable, allowPreexisting)
			}
			if len(removable) == 0 {
				return 0
			}
			return uninstallBuildDependenciesWithOptions(removable, cfg, quietDependencyInstalls)
		}

		removeCandidates(temporaryBuildDeps, true)
		temporaryBuildDeps = nil

		for {
			runtimeOrphans, err := findOrphans()
			if err != nil {
				debugf("Warning: failed to calculate temporary build orphans: %v\n", err)
				return
			}
			makeOrphans, err := findMakeOrphans()
			if err != nil {
				debugf("Warning: failed to calculate temporary build make-orphans: %v\n", err)
			}
			orphans := append(runtimeOrphans, makeOrphans...)
			if removeCandidates(orphans, cleanupAfterFailure) == 0 {
				return
			}
		}
	}
	defer cleanupTemporaryBuildDeps()
	prepareDevelPackages := func(pkgNames []string) error {
		if *bootstrap {
			return nil
		}
		if *noDevel {
			colArrow.Print("-> ")
			colWarn.Println("Skipping devel package check (--no-devel enabled)")
			return nil
		}
		if !packageSetNeedsDevelPackages(pkgNames) {
			debugf("Skipping devel package check: all packages in the build set use binary or nodevel\n")
			return nil
		}
		includeMultilib := packageSetHasBuildOption(pkgNames, "multilib")
		installedDevelDeps, err := ensureDevelPackagesInstalledWithOptions(cfg, includeMultilib, *noRemote, quietDependencyInstalls)
		if err != nil {
			return fmt.Errorf("failed to prepare devel packages: %w", err)
		}
		for _, dep := range installedDevelDeps {
			addTemporaryBuildDep(dep)
		}
		return nil
	}

	// ** STRATEGY 1: Bootstrap or --alldeps mode **
	if *bootstrap || *allDeps {
		colArrow.Print("-> ")
		colSuccess.Println("Using forward-dependency build strategy for bootstrap/--alldeps mode.")
		var fullBuildList []string
		for _, pkgName := range packagesToProcess {
			deps, err := getPackageDependenciesForward(pkgName, cfg)
			if err != nil {
				return fmt.Errorf("error resolving forward dependencies for %s: %v", pkgName, err)
			}
			fullBuildList = append(fullBuildList, deps...)
			fullBuildList = append(fullBuildList, pkgName) // Add the target itself
		}

		fullBuildList = MovePackageToFront(fullBuildList, "sauzeros-base")

		if *ask {
			depsToInstall := missingDevelPackagesForBuildSet(cfg, fullBuildList)
			if !confirmBuildPlanWithAsk(fullBuildList, depsToInstall, nil) {
				colArrow.Print("-> ")
				colWarn.Println("Build canceled.")
				return nil
			}
		}

		buildWorkStarted = true
		if err := prepareDevelPackages(fullBuildList); err != nil {
			return err
		}

		colArrow.Print("-> ")
		colSuccess.Printf("Build order: %s\n", strings.Join(fullBuildList, " -> "))

		if len(fullBuildList) > 1 {
			go prefetchSources(fullBuildList[1:])
		}

		// Execute the simple, sequential build

		totalBuildCount := len(fullBuildList)
		for i, pkgName := range fullBuildList {
			// ** THE CRITICAL FIX IS HERE **
			// If in bootstrap mode (not --alldeps alone), check if the package is already installed.
			if *bootstrap && isPackageInstalled(pkgName) {
				colArrow.Print("-> ")
				colSuccess.Printf("Package '%s' is already installed in the target directory. Skipping.\n", pkgName)
				continue
			}
			// *****************************

			colArrow.Print("-> ")
			colSuccess.Printf("Building: %s (%d/%d)\n", pkgName, i+1, totalBuildCount)
			duration, err := pkgBuild(pkgName, cfg, UserExec, BuildOptions{
				Bootstrap:     *bootstrap,
				CurrentIndex:  i + 1,
				TotalCount:    totalBuildCount,
				UpdateWebsite: UpdateWebsiteIndex,
			})
			if err != nil {
				failedBuilds[pkgName] = err
				colArrow.Print("-> ")
				color.Danger.Printf("Fatal build failure for %s: %v\n", pkgName, err)
				goto BuildSummary
			}
			totalElapsedTime += duration
			// In bootstrap/alldeps mode, every built package is installed immediately.
			version, revision, err := getRepoVersion2(pkgName)
			if err != nil {
				failedBuilds[pkgName] = fmt.Errorf("failed to get version/revision: %w", err)
				break
			}
			// Use output package name for tarball and installation (may be renamed for cross-system)
			outputPkgName := getOutputPackageName(pkgName, cfg)
			archivePkgName := getArchivePackageName(pkgName, cfg)
			arch := GetSystemArchForPackage(cfg, pkgName)
			variant := GetSystemVariantForPackage(cfg, pkgName)
			tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))
			isCriticalAtomic.Store(1)
			handlePreInstallUninstall(outputPkgName, cfg, RootExec, false, nil)
			if _, installErr := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true, false, false, nil); installErr != nil {
				isCriticalAtomic.Store(0)
				colArrow.Print("-> ")
				color.Danger.Printf("Installation failed for %s: %v\n", outputPkgName, installErr)
				failedBuilds[pkgName] = fmt.Errorf("post-build installation failed: %w", installErr)
				goto BuildSummary // Fatal error, abort
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Installing:")
			colNote.Printf(" %s (%d/%d)\n", outputPkgName, i+1, totalBuildCount)
			// Add to world file
			// Only add if user specifically asked for this package
			if userRequestedMap[pkgName] {
				addToWorld(pkgName)
			}
			for _, splitPkg := range directSplitTargetsBySource[pkgName] {
				if err := installBuiltSplitTargetWithLogger(pkgName, splitPkg, cfg, nil, false); err != nil {
					isCriticalAtomic.Store(0)
					colArrow.Print("-> ")
					color.Danger.Printf("Installation failed for split target %s: %v\n", splitPkg, err)
					failedBuilds[pkgName] = fmt.Errorf("split target installation failed for %s: %w", splitPkg, err)
					goto BuildSummary
				}
				if userRequestedMap[splitPkg] {
					addToWorld(splitPkg)
				}
				colArrow.Print("-> ")
				colSuccess.Printf("Installing split target:")
				colNote.Printf(" %s\n", splitPkg)
			}
			isCriticalAtomic.Store(0)
		}

	} else {
		// ** STRATEGY 2: Normal Build Mode **
		var packagesThatMustBeBuilt map[string]bool
		splitDepsBySource := make(map[string][]string)
		for sourcePkg, splitPkgs := range directSplitTargetsBySource {
			for _, splitPkg := range splitPkgs {
				addMappedSplitDependency(splitDepsBySource, sourcePkg, splitPkg)
			}
		}
		binaryDeclined := make(map[string]bool)
		deferredAskConfirmation := false

		if *noDeps {
			// Skip dependency resolution when --no-deps is set
			colArrow.Print("-> ")
			colWarn.Println("Skipping dependency checking (--no-deps enabled)")
			packagesThatMustBeBuilt = make(map[string]bool)
			for pkg := range forceBuildMap {
				packagesThatMustBeBuilt[pkg] = true
			}
		} else {
			// Normal dependency resolution
			colArrow.Print("-> ")
			colSuccess.Println("Discovering all required dependencies")
			masterProcessed := make(map[string]bool)
			var missingDeps []string
			for _, pkgName := range packagesToProcess {
				if err := resolveMissingDeps(pkgName, masterProcessed, &missingDeps, forceBuildMap, cfg, *noRemote); err != nil {
					return fmt.Errorf("error resolving dependencies for %s: %v", pkgName, err)
				}
			}
			missingDeps = MovePackageToFront(missingDeps, "sauzeros-base")

			if *ask && Debug {
				previewBuildSet := previewBuildSetForMissingDeps(missingDeps, forceBuildMap, cfg, *noRemote)
				previewBuildList := buildPackageNames(previewBuildSet)
				var previewPlan *BuildPlan
				if len(previewBuildList) > 0 {
					previewPlan, err = resolveBuildPlan(previewBuildList, userRequestedMap, effectiveRebuilds, cfg, nil)
					if err != nil {
						return fmt.Errorf("error generating build preview: %v", err)
					}
					addPostRebuildSplitDependencies(previewPlan, splitDepsBySource)
				}

				buildOrder := previewBuildList
				postRebuilds := map[string][]string(nil)
				if previewPlan != nil {
					buildOrder = plannedBuildDisplayOrder(previewPlan, cfg, *noRemote)
					postRebuilds = previewPlan.PostRebuilds
				}
				previewPackages := buildPackageNames(previewBuildSet)
				depsToInstall := append(plannedBinaryInstallsForMissingDeps(missingDeps, forceBuildMap, cfg, *noRemote), missingDevelPackagesForBuildSet(cfg, previewPackages)...)
				if !confirmBuildPlanWithAsk(buildOrder, depsToInstall, postRebuilds) {
					colArrow.Print("-> ")
					colWarn.Println("Build canceled.")
					return nil
				}
			} else if *ask {
				deferredAskConfirmation = true
			}

			buildWorkStarted = true
			packagesThatMustBeBuilt = make(map[string]bool)
			for pkg := range forceBuildMap {
				packagesThatMustBeBuilt[pkg] = true
			}

			missingDepBar := newDependencyInstallProgress(len(missingDeps), "Installing Build Dependencies", quietDependencyInstalls && !*promptBinaryDeps)
			deactivateMissingDepProgress := activateDependencyInstallProgress(missingDepBar)
			for _, depPkg := range missingDeps {
				describeDependencyCheckProgress(missingDepBar, depPkg)
				if err := func() error {
					defer advanceDependencyInstallProgress(missingDepBar)
					if packagesThatMustBeBuilt[depPkg] {
						return nil
					}
					if _, err := findPackageMetadataDir(depPkg); err != nil {
						if isPackageInstalled(depPkg) {
							return nil
						}
						if sourcePkg, ok := findSplitDependencySource(depPkg); ok {
							if !binaryDeclined[depPkg] && dependencyBinaryAvailable(depPkg, cfg, *noRemote) {
								if useAvailableBuildDependencyBinary(*promptBinaryDeps, "Dependency '%s' is missing. Use available binary package?", depPkg) {
									installed, installErr := installAvailableSplitDependencyBinary(sourcePkg, depPkg, cfg, *noRemote, nil, quietDependencyInstalls)
									if installErr == nil {
										if installed {
											addTemporaryBuildDep(depPkg)
										}
										return nil
									}
									colWarn.Printf("Warning: failed to install available binary dependency %s: %v\n", depPkg, installErr)
								} else {
									binaryDeclined[depPkg] = true
								}
							}
							clearDependencyInstallProgress(missingDepBar)
							colArrow.Print("-> ")
							debugf("Dependency %s is a split package; scheduling %s to build it\n", depPkg, sourcePkg)
							packagesThatMustBeBuilt[sourcePkg] = true
							addMappedSplitDependency(splitDepsBySource, sourcePkg, depPkg)
							return nil
						}
						installed, installErr := ensurePackageInstalledWithOptions(depPkg, cfg, *noRemote, nil, quietDependencyInstalls)
						if installErr == nil {
							if installed {
								addTemporaryBuildDep(depPkg)
							}
							return nil
						}
						return fmt.Errorf("error: dependency %s has no source package and could not be installed as a binary package: %w", depPkg, installErr)
					}

					outputDepPkg, tarballPath, binaryAvailable, binaryErr := availableBuildDependencyBinaryTarball(depPkg, cfg, *noRemote)
					if binaryErr != nil {
						debugf("Binary dependency lookup failed for %s; falling back to source build: %v\n", depPkg, binaryErr)
						packagesThatMustBeBuilt[depPkg] = true
						return nil
					}
					if !binaryAvailable {
						packagesThatMustBeBuilt[depPkg] = true
						return nil
					}

					if !useAvailableBuildDependencyBinary(*promptBinaryDeps, "Dependency '%s' is missing. Use available binary package?", depPkg) {
						binaryDeclined[depPkg] = true
						packagesThatMustBeBuilt[depPkg] = true
						return nil
					}

					logger, fast := dependencyInstallLogger(quietDependencyInstalls)
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputDepPkg, cfg, RootExec, false, logger)
					if _, err := pkgInstall(tarballPath, outputDepPkg, cfg, RootExec, false, fast, false, logger); err != nil {
						isCriticalAtomic.Store(0)
						return fmt.Errorf("fatal error installing binary %s: %v", depPkg, err)
					}
					isCriticalAtomic.Store(0)
					addTemporaryBuildDep(outputDepPkg)
					return nil
				}(); err != nil {
					clearDependencyInstallProgress(missingDepBar)
					deactivateMissingDepProgress()
					return err
				}
			}
			clearDependencyInstallProgress(missingDepBar)
			deactivateMissingDepProgress()
		}

		if len(packagesThatMustBeBuilt) == 0 {
			fmt.Println("All packages and dependencies are already installed.")
			return nil
		}

		if *ask && *noDeps {
			buildList := buildPackageNames(packagesThatMustBeBuilt)
			buildList = MovePackageToFront(buildList, "sauzeros-base")
			depsToInstall := missingDevelPackagesForBuildSet(cfg, buildList)
			if !confirmBuildPlanWithAsk(buildList, depsToInstall, nil) {
				colArrow.Print("-> ")
				colWarn.Println("Build canceled.")
				return nil
			}
		}

		buildWorkStarted = true
		if err := prepareDevelPackages(buildPackageNames(packagesThatMustBeBuilt)); err != nil {
			return err
		}

		// Set the total count for the summary.
		totalBuildCount = len(packagesThatMustBeBuilt)

		// --- CHOOSE BUILD STRATEGY: ORDERED or GRAPH-BASED ---
		if *orderedBuild && len(packagesToProcess) == 1 {
			// --- NEW: ORDERED "DRIVER" BUILD MODE ---
			targetMetaPackage := packagesToProcess[0]
			colArrow.Print("-> ")
			colSuccess.Printf("Using ordered build mode driven by '%s'.\n\n", targetMetaPackage)

			pkgDir, err := findPackageDir(targetMetaPackage)
			if err != nil {
				return fmt.Errorf("cannot find source for target package '%s': %v", targetMetaPackage, err)
			}
			orderedTopLevelDeps, err := parseDependsFile(pkgDir)
			if err != nil {
				return fmt.Errorf("cannot parse depends file for '%s': %v", targetMetaPackage, err)
			}

			// Add the meta-package itself to the list to be processed last
			orderedTopLevelDeps = append(orderedTopLevelDeps, DepSpec{Name: targetMetaPackage})

			for i, dep := range orderedTopLevelDeps {
				pkgName := dep.Name
				// Only process this top-level dependency if it's in our list of things to build
				if !packagesThatMustBeBuilt[pkgName] {
					continue
				}

				colArrow.Print("-> ")
				colSuccess.Printf("Processing Top-Level Dependency %d/%d: %s \n", i+1, len(orderedTopLevelDeps), pkgName)

				var plan *BuildPlan
				for {
					// ordered build mode typically builds from source
					plan, err = resolveBuildPlan([]string{pkgName}, userRequestedMap, effectiveRebuilds, cfg, nil)
					if err != nil {
						return fmt.Errorf("error generating build plan for '%s': %v", pkgName, err)
					}
					addPostRebuildSplitDependencies(plan, splitDepsBySource)
					installedBinaryDeps, err := installAvailableBinaryBuildDeps(plan, userRequestedMap, binaryDeclined, cfg, addTemporaryBuildDep, *noRemote, *promptBinaryDeps, quietDependencyInstalls)
					if err != nil {
						return err
					}
					if !installedBinaryDeps {
						break
					}
				}
				if len(plan.Order) == 0 {
					colSuccess.Printf("Package '%s' is already built and up to date. Skipping.\n\n", pkgName)
					continue
				}

				colInfo.Printf("Build order for this group: %s\n\n", strings.Join(plannedBuildDisplayOrder(plan, cfg, *noRemote), " -> "))

				progressCount := 0
				failedThisGroup, _, elapsedThisGroup, installedDepsThisGroup := executeBuildPass(plan, pkgName, true, cfg, bootstrap, userRequestedMap, splitDepsBySource, *noRemote, retainTemporaryBuildDep, &progressCount)
				totalElapsedTime += elapsedThisGroup
				for _, dep := range installedDepsThisGroup {
					addTemporaryBuildDep(dep)
				}
				for k, v := range failedThisGroup {
					failedBuilds[k] = v
				}

				// If any build in this group failed, stop the entire process.
				if len(failedThisGroup) > 0 {
					color.Danger.Println("\nBuild failed in this group. Aborting ordered build.")
					goto BuildSummary
				}
			}

		} else {
			if *orderedBuild {
				colWarn.Println("Warning: -ordered flag is only supported for a single target package. Using default build mode.")
			}

			var buildListInput []string
			for pkg := range packagesThatMustBeBuilt {
				buildListInput = append(buildListInput, pkg)
			}

			var initialPlan *BuildPlan
			var err error
			if *noDeps {
				initialPlan = &BuildPlan{
					Order:             buildListInput,
					SkippedPackages:   make(map[string]string),
					RebuildPackages:   make(map[string]bool),
					PostRebuilds:      make(map[string][]string),
					PostBuildRebuilds: make(map[string][]string),
					NoDeps:            true,
				}
				initialPlan.Order = MovePackageToFront(initialPlan.Order, "sauzeros-base")
				err = nil
			} else {
				colArrow.Print("-> ")
				colSuccess.Println("Generating Build Plan")
				for {
					initialPlan, err = resolveBuildPlan(buildListInput, userRequestedMap, effectiveRebuilds, cfg, nil)
					if err != nil {
						break
					}
					addPostRebuildSplitDependencies(initialPlan, splitDepsBySource)
					installedBinaryDeps, installErr := installAvailableBinaryBuildDeps(initialPlan, userRequestedMap, binaryDeclined, cfg, addTemporaryBuildDep, *noRemote, *promptBinaryDeps, quietDependencyInstalls)
					if installErr != nil {
						return installErr
					}
					if !installedBinaryDeps {
						break
					}
				}
			}
			if err != nil {
				return fmt.Errorf("error generating build plan: %v", err)
			}
			addPostRebuildSplitDependencies(initialPlan, splitDepsBySource)
			initialPlan.NoInstall = *noInstall
			if len(initialPlan.Order) == 0 {
				fmt.Println("All packages are up to date. Nothing to build.")
				return nil
			}
			if err := prepareVersionedPlanSources(initialPlan.Order); err != nil {
				return err
			}

			printResolvedBuildSummary(initialPlan)
			if deferredAskConfirmation && !askForConfirmationDefaultNo(colWarn, "Proceed with build?") {
				colArrow.Print("-> ")
				colWarn.Println("Build canceled.")
				return nil
			}
			if len(initialPlan.Order) > 1 {
				// Prefetch the plan list, skipping the first one which starts immediately
				go prefetchSources(initialPlan.Order[1:])
			}
			if Debug && len(initialPlan.PostRebuilds) > 0 {
				var rebuilds []string
				for parent, deps := range initialPlan.PostRebuilds {
					rebuilds = append(rebuilds, fmt.Sprintf("%s (for %s)", parent, strings.Join(deps, ",")))
				}
				sort.Strings(rebuilds)
				colArrow.Print("-> ")
				colWarn.Printf("Packages scheduled for inline rebuild with optional features: %s\n", strings.Join(rebuilds, ", "))
			}

			progressCount := 0

			if maxJobs > 1 {
				colArrow.Print("-> ")
				colSuccess.Printf("Executing parallel build (jobs: %d)\n", maxJobs)

				// Define smart builder to check for binaries first
				smartBuildBuilder := func(pkgName string, cfg *Config, exec *Executor, opts BuildOptions) (time.Duration, error) {
					// 1. If user specifically requested this package, we usually force build
					// unless -a logic implies otherwise. But generally build command means build.
					if userRequestedMap[pkgName] || initialPlan.RebuildPackages[pkgName] {
						return pkgBuild(pkgName, cfg, exec, opts)
					}

					// 2. Ideally we should respect rebuild flags/logic, but for now:
					// If it's a dependency, check for binary availability.
					// Similar to sequential logic above.

					version, revision, err := getRepoVersion2(pkgName)
					if err != nil {
						// Fallback to build if version lookup fails (shouldn't happen if plan resolved)
						return pkgBuild(pkgName, cfg, exec, opts)
					}
					archivePkgName := getArchivePackageName(pkgName, cfg)

					// Try to fetch binary if configured
					if !*noRemote && BinaryMirror != "" {
						// Optimization: Check remote index first
						index, err := GetCachedRemoteIndex(cfg)
						shouldTryDownload := true
						if err == nil {
							if !IsPackageInIndex(index, archivePkgName, version, revision, cfg) {
								shouldTryDownload = false
							}
						}

						if shouldTryDownload {
							var expectedSum string
							targetArch := GetSystemArchForPackage(cfg, pkgName)
							targetVariant := GetSystemVariantForPackage(cfg, pkgName)
							for _, entry := range index {
								if entry.Name == archivePkgName && entry.Version == version &&
									entry.Revision == revision && entry.Arch == targetArch &&
									entry.Variant == targetVariant {
									expectedSum = entry.B3Sum
									break
								}
							}
							_ = fetchBinaryPackage(archivePkgName, version, revision, cfg, true, expectedSum, false)
						}
					}

					arch := GetSystemArch(cfg)
					variant := GetSystemVariantForPackage(cfg, pkgName)
					tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))

					if _, err := os.Stat(tarballPath); err == nil {
						// Found binary! Return success with 0 duration to signal "skipped build" (ready for install)
						return 0, nil
					}

					// Not found? Build it.
					return pkgBuild(pkgName, cfg, exec, opts)
				}

				// Start parallel build
				installedBinaryDeps, err := installAvailableBinaryDependenciesForPlanWithOptions(initialPlan, cfg, *noRemote, true)
				if err != nil {
					return err
				}
				for _, dep := range installedBinaryDeps {
					addTemporaryBuildDep(dep)
				}
				installedParallelDeps, err := RunParallelBuilds(initialPlan, cfg, maxJobs, userRequestedMap, true, *autoInstall, splitDepsBySource, smartBuildBuilder)
				if err != nil {
					return err
				}
				for _, dep := range installedParallelDeps {
					addTemporaryBuildDep(dep)
				}

				if err := PostInstallTasks(RootExec, os.Stdout); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Global post-install tasks failed: %v\n", err)
				}
				// Skip the rest of sequential logic
				return nil
			}

			failedPass1, targetsPass1, elapsedPass1, installedDepsPass1 := executeBuildPass(initialPlan, "Initial Pass", false, cfg, bootstrap, userRequestedMap, splitDepsBySource, *noRemote, retainTemporaryBuildDep, &progressCount)
			totalElapsedTime = elapsedPass1
			failedBuilds = failedPass1
			for _, dep := range installedDepsPass1 {
				addTemporaryBuildDep(dep)
			}

			if len(targetsPass1) > 0 {
				// Skip installation prompt and installation for cross-compilation without system flag
				// (cross-compiled packages without system are not meant to be installed on build host)
				isCrossWithoutSystem := cfg.Values["HOKUTO_CROSS_ARCH"] != "" && cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1"

				shouldInstall := *autoInstall
				if !*noInstall && !shouldInstall && !isCrossWithoutSystem {
					sort.Strings(targetsPass1)
					// Convert to output package names for display (may be renamed for cross-system)
					outputPkgNames := make([]string, len(targetsPass1))
					for i, pkg := range targetsPass1 {
						outputPkgNames[i] = getOutputPackageName(pkg, cfg)
					}
					pkgNoun := "package"
					if len(outputPkgNames) > 1 {
						pkgNoun = "packages"
					}
					shouldInstall = askForConfirmation(colWarn, "-> Install built %s: %s", pkgNoun, colNote.Sprint(strings.Join(outputPkgNames, ", ")))
				}
				if shouldInstall && !isCrossWithoutSystem {
					installedRequestedTarget := false
					for i, finalPkg := range targetsPass1 {
						if _, failed := failedBuilds[finalPkg]; failed {
							continue
						}
						version, revision, _ := getRepoVersion2(finalPkg)
						outputFinalPkg := getOutputPackageName(finalPkg, cfg)
						archiveFinalPkg := getArchivePackageName(finalPkg, cfg)
						arch := GetSystemArchForPackage(cfg, finalPkg)
						variant := GetSystemVariantForPackage(cfg, finalPkg)
						tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveFinalPkg, version, revision, arch, variant))
						isCriticalAtomic.Store(1)
						handlePreInstallUninstall(outputFinalPkg, cfg, RootExec, false, nil)
						if _, err := pkgInstall(tarballPath, outputFinalPkg, cfg, RootExec, false, false, false, nil); err != nil {
							isCriticalAtomic.Store(0)
							colArrow.Print("-> ")
							color.Danger.Printf("Installation failed for %s: %v\n", outputFinalPkg, err)
							failedBuilds[finalPkg] = fmt.Errorf("final installation failed: %w", err)
							cleanupTemporaryBuildDeps()
							goto BuildSummary // Abort the whole process
						} else {
							// Add package to world file
							if userRequestedMap[finalPkg] {
								addToWorld(finalPkg)
								installedRequestedTarget = true
							}
							colArrow.Print("-> ")
							colSuccess.Printf("Installing:")
							colNote.Printf(" %s (%d/%d)\n", outputFinalPkg, i+1, len(targetsPass1))
						}
						isCriticalAtomic.Store(0)
					}
					if !installedRequestedTarget {
						builtWithoutInstallingTargets = true
						cleanupTemporaryBuildDeps()
					}
				} else {
					builtWithoutInstallingTargets = true
					cleanupTemporaryBuildDeps()
				}
			}
		}
	}

BuildSummary:

	// --- Final Report ---
	if len(failedBuilds) == 0 {
		colArrow.Print("-> ")
		if builtWithoutInstallingTargets {
			colSuccess.Printf("All packages built successfully (%d/%d) Time: %s\n", totalBuildCount, totalBuildCount, totalElapsedTime.Truncate(time.Second))
		} else {
			colSuccess.Printf("All packages built and installed successfully (%d/%d) Time: %s\n", totalBuildCount, totalBuildCount, totalElapsedTime.Truncate(time.Second))
		}
		return nil
	}
	color.Danger.Print("-> ")
	color.Danger.Println("Failed or Blocked Packages:")
	var failedKeys []string
	for k := range failedBuilds {
		failedKeys = append(failedKeys, k)
	}
	sort.Strings(failedKeys)
	for _, pkg := range failedKeys {
		color.Debug.Printf("  - %-20s: %v\n", pkg, failedBuilds[pkg])
	}
	fmt.Println()
	return fmt.Errorf("some packages failed to build")
}

// Helper for HandleBuildCommand to execute a single build pass based on the provided BuildPlan.

func executeBuildPass(plan *BuildPlan, _ string, installAllTargets bool, cfg *Config, bootstrap *bool, userRequestedMap map[string]bool, splitDepsBySource map[string][]string, noRemote bool, retainBuildDep func(string), progressCount *int) (map[string]error, []string, time.Duration, []string) {

	toBuild := plan.Order
	failed := make(map[string]error)
	var successfullyBuiltTargets []string
	var installedBuildDeps []string
	builtThisPass := make(map[string]bool)
	inPlan := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inPlan[pkgName] = true
	}
	binaryInstallAttempts := make(map[string]bool)
	var totalElapsedTime time.Duration
	postRebuildDepsAvailable := func(deps []string) bool {
		for _, dep := range deps {
			if builtThisPass[dep] || isPackageInstalled(dep) {
				continue
			}
			if sourcePkg, ok := findSplitDependencySource(dep); ok && builtThisPass[sourcePkg] {
				if isPackageInstalled(dep) {
					continue
				}
			}
			return false
		}
		return true
	}
	depMatchesPackage := func(dep DepSpec, pkgName string) bool {
		if len(dep.Alternatives) > 0 {
			if cached, ok := cachedAlternativeDep(dep); ok {
				return cached == pkgName
			}
			for _, alt := range dep.Alternatives {
				if alt == pkgName {
					return true
				}
			}
			return false
		}
		return dep.Name == pkgName
	}
	passInProgress := true
	for passInProgress && len(toBuild) > 0 {
		progressThisPass := false
		var remainingAfterPass []string
		for _, pkgName := range toBuild {
			if _, isFailed := failed[pkgName]; isFailed {
				continue
			}
			canBuild := true
			if !plan.NoDeps { // Dependency checks are skipped if plan.NoDeps is true
				pkgDir, _ := findPackageDir(pkgName)
				deps, _ := parseDependsFile(pkgDir)
				for _, dep := range deps {
					if !activeBuildDependency(dep, cfg, false) {
						continue
					}

					isSatisfied := false

					// Helper to check if a package is available, or can be made available
					// from a binary package without changing the active build plan.
					isDepAvailable := func(name string, op string, ver string, dep DepSpec) bool {
						// 1. Check if it was built this pass (using exact name)
						if builtThisPass[name] {
							return true
						}

						// 2. Check if any satisfying package is installed (including renamed ones)
						if sat := findInstalledSatisfying(name, op, ver); sat != "" {
							return true
						}

						if *bootstrap {
							return false
						}

						// 3. Fallback: if it was built this pass under a renamed name,
						// we need to check if that renamed name satisfies the constraint.
						// This is complex, but for now we can check if any key in builtThisPass
						// matches name-MAJOR if we can derive MAJOR from the constraint.
						// However, if it was built this pass, it was also INSTALLED,
						// so findInstalledSatisfying should have caught it.
						// The only edge case is if it's built but not yet installed (not possible in current sequential flow).
						if inPlan[name] || binaryInstallAttempts[name] || !dependencyBinaryAvailable(name, cfg, noRemote) {
							return false
						}

						binaryInstallAttempts[name] = true
						colArrow.Print("-> ")
						colSuccess.Printf("Installing available binary dependency:")
						colNote.Printf(" %s\n", name)
						installed, err := ensurePackageInstalledWithOptions(name, cfg, noRemote, nil, true)
						if err != nil {
							colArrow.Print("-> ")
							colWarn.Printf("Warning: failed to install available binary dependency %s: %v\n", name, err)
							return false
						}
						if installed {
							installedBuildDeps = append(installedBuildDeps, name)
							if dep.Make {
								addToWorldMake(name)
							}
						}
						return findInstalledSatisfying(name, op, ver) != ""
					}

					candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
					if err != nil {
						isSatisfied = false
					} else {
						for _, cand := range candidates {
							if isDepAvailable(cand, dep.Op, dep.Version, dep) {
								isSatisfied = true
								break
							}
						}
					}

					if len(candidates) == 0 && len(dep.Alternatives) == 0 {
						if isDepAvailable(dep.Name, dep.Op, dep.Version, dep) {
							isSatisfied = true
						}
					}

					if !isSatisfied {
						// Check if we are blocked by a SPECIFIC failure in the alternatives
						if len(dep.Alternatives) > 0 {
							candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
							if err == nil {
								for _, cand := range candidates {
									if _, hasFailed := failed[cand]; hasFailed {
										failed[pkgName] = fmt.Errorf("blocked by failed dependency '%s'", cand)
										break
									}
								}
							} else {
								for _, alt := range dep.Alternatives {
									if _, hasFailed := failed[alt]; hasFailed {
										failed[pkgName] = fmt.Errorf("blocked by failed dependency '%s'", alt)
										break
									}
								}
							}
						} else {
							if _, hasFailed := failed[dep.Name]; hasFailed {
								failed[pkgName] = fmt.Errorf("blocked by failed dependency '%s'", dep.Name)
							}
						}

						canBuild = false
						break
					}
				}
			}
			if !canBuild {
				remainingAfterPass = append(remainingAfterPass, pkgName)
				continue
			}
			if missingDeps, ok := plan.PostRebuilds[pkgName]; ok && postRebuildDepsAvailable(missingDeps) {
				delete(plan.PostRebuilds, pkgName)
			}
			totalInPlan := len(plan.Order) // Get the original total count
			*progressCount++
			currentIndex := *progressCount
			colArrow.Print("-> ")
			colSuccess.Print("Building: ")
			colNote.Printf("%s (%d/%d)\n", pkgName, currentIndex, totalInPlan)

			duration, err := pkgBuild(pkgName, cfg, UserExec, BuildOptions{
				Bootstrap:     *bootstrap,
				CurrentIndex:  currentIndex,
				TotalCount:    totalInPlan,
				UpdateWebsite: UpdateWebsiteIndex,
			})
			if err != nil {
				failed[pkgName] = err
				color.Danger.Printf("Build failed for %s: %v\n\n", pkgName, err)
				continue
			} else {
				progressThisPass = true
				totalElapsedTime += duration // Accumulate the time from the successful build

				// Check if this package is required by any not-yet-built package in the current build pass.
				// This ensures we install user-requested packages immediately when another package
				// still needs them, even if execution had to skip around the planned order.
				isDependencyForThisPass := false

				// Only check look-ahead if it's a user requested package.
				// Implicit dependencies (!userRequestedMap) are auto-installed by default logic below.
				if userRequestedMap[pkgName] {
					for _, futurePkg := range plan.Order {
						if futurePkg == pkgName || builtThisPass[futurePkg] {
							continue
						}
						if _, futureFailed := failed[futurePkg]; futureFailed {
							continue
						}

						// Check dependencies of futurePkg
						fDir, err := findPackageDir(futurePkg)
						if err == nil {
							fDeps, err := parseDependsFile(fDir)
							if err == nil {
								for _, d := range fDeps {
									if !activeBuildDependency(d, cfg, false) {
										continue
									}
									if depMatchesPackage(d, pkgName) {
										isDependencyForThisPass = true
										break
									}
								}
							}
						}
						if isDependencyForThisPass {
							break
						}
					}
				}

				// Check if this package triggers any post-build rebuilds ---
				triggersRebuilds := len(plan.PostBuildRebuilds[pkgName]) > 0
				requiredSplitDeps := splitDepsBySource[pkgName]
				triggersSplitDeps := len(requiredSplitDeps) > 0

				// We install immediately IF:
				//  - It's a dependency, OR
				//  - It's a user target that is a dependency for something else in this batch, OR
				//  - It's a user target that triggers a post-build rebuild.
				shouldInstallNow := !userRequestedMap[pkgName] || isDependencyForThisPass || triggersRebuilds || triggersSplitDeps

				if installAllTargets || shouldInstallNow {
					// Install the package immediately.
					version, revision, _ := getRepoVersion2(pkgName)
					outputPkgName := getOutputPackageName(pkgName, cfg)
					archivePkgName := getArchivePackageName(pkgName, cfg)
					wasInstalledBefore := isPackageInstalled(outputPkgName)
					arch := GetSystemArchForPackage(cfg, pkgName)
					variant := GetSystemVariantForPackage(cfg, pkgName)
					tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))
					installLogger := io.Writer(nil)
					installFast := false
					if !userRequestedMap[pkgName] {
						installLogger = io.Discard
						installFast = true
					}
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputPkgName, cfg, RootExec, false, installLogger)
					if _, installErr := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true, installFast, false, installLogger); installErr != nil {
						isCriticalAtomic.Store(0)
						colArrow.Print("-> ")
						color.Danger.Printf("Installation failed for %s: %v\n", outputPkgName, installErr)
						failed[pkgName] = fmt.Errorf("post-build installation failed: %w", installErr)
						return failed, successfullyBuiltTargets, totalElapsedTime, installedBuildDeps // Abort this pass
					}
					colArrow.Print("-> ")
					colSuccess.Printf("Installing:")
					colNote.Printf(" %s (%d/%d) Time: %s\n", outputPkgName, currentIndex, totalInPlan, duration.Truncate(time.Second))
					// Add to World file
					// Only add if this was an explicit user target,
					// NOT if it was just installed because it's a dependency (shouldInstallNow check logic)
					if userRequestedMap[pkgName] {
						addToWorld(pkgName)
					}

					// Check if it's a Make Dependency
					// If the user did NOT request it explicitly, check if it was pulled in
					// as a 'make' dependency by any other package in the toBuild list.
					if !*bootstrap && !userRequestedMap[pkgName] && !wasInstalledBefore {
						installedBuildDeps = append(installedBuildDeps, outputPkgName)
						isMakeDep := false
						// Scan all packages in the plan (including those already built or waiting)
						// to see if any of them list 'pkgName' as a 'make' dependency.
						for _, otherPkg := range plan.Order {
							pDir, err := findPackageDir(otherPkg)
							if err == nil {
								deps, err := parseDependsFile(pDir)
								if err == nil {
									for _, d := range deps {
										// FILTER: skip cross dependencies if not cross-compiling
										if d.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
											continue
										}

										// FILTER: skip crossnative dependencies unless we are in a cross-native build
										if d.CrossNative {
											if cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
												continue
											}
										}

										if d.Name == pkgName && d.Make {
											isMakeDep = true
											break
										}
									}
								}
							}
							if isMakeDep {
								break
							}
						}

						if isMakeDep {
							addToWorldMake(pkgName)
						}
					}

					isCriticalAtomic.Store(0)

					for _, splitPkg := range requiredSplitDeps {
						wasSplitInstalledBefore := isPackageInstalled(splitPkg)
						var err error
						if userRequestedMap[splitPkg] {
							err = installBuiltSplitTargetWithLogger(pkgName, splitPkg, cfg, nil, false)
						} else {
							err = installBuiltSplitDependencyWithOptions(pkgName, splitPkg, cfg, true)
						}
						if err != nil {
							colArrow.Print("-> ")
							color.Danger.Printf("Installation failed for split dependency %s: %v\n", splitPkg, err)
							failed[pkgName] = fmt.Errorf("split dependency install failed for %s: %w", splitPkg, err)
							return failed, successfullyBuiltTargets, totalElapsedTime, installedBuildDeps
						}
						colArrow.Print("-> ")
						if userRequestedMap[splitPkg] {
							addToWorld(splitPkg)
							colSuccess.Printf("Installing split target:")
						} else {
							colSuccess.Printf("Installing split dependency:")
							if !*bootstrap && !wasSplitInstalledBefore {
								installedBuildDeps = append(installedBuildDeps, splitPkg)
							}
						}
						colNote.Printf(" %s\n", splitPkg)
						builtThisPass[splitPkg] = true
					}
				} else {
					// This is a standalone user target. Defer installation until the end.
					successfullyBuiltTargets = append(successfullyBuiltTargets, pkgName)
				}

				builtThisPass[pkgName] = true // Mark the current package as successfully built and installed

				// Now, check if this installation satisfies an optional dependency for a package we've already built.
				for parent, missingDeps := range plan.PostRebuilds {
					// Condition 1: The parent package must have already been built in this pass.
					if !builtThisPass[parent] {
						continue
					}

					// Condition 2: Check if ALL of its missing optional deps are now available.
					allDepsNowAvailable := true
					for _, dep := range missingDeps {
						if !builtThisPass[dep] {
							allDepsNowAvailable = false
							break
						}
					}

					if allDepsNowAvailable {
						fmt.Println()
						colArrow.Print("-> ")
						colWarn.Printf("Optional dependency '%s' now available for '%s'. Triggering immediate rebuild.\n", strings.Join(missingDeps, ", "), parent)
						if retainBuildDep != nil {
							for _, dep := range missingDeps {
								retainBuildDep(dep)
							}
						}

						// Rebuild the parent package
						*progressCount++
						rebuildIdx := *progressCount
						duration, err := pkgBuild(parent, cfg, UserExec, BuildOptions{
							Bootstrap:    *bootstrap,
							CurrentIndex: rebuildIdx,
							TotalCount:   totalInPlan,
						})
						if err != nil {
							color.Danger.Printf("Inline rebuild of '%s' failed: %v\n", parent, err)
							failed[parent] = fmt.Errorf("inline rebuild failed: %w", err)
							continue // Move to check the next parent
						}
						totalElapsedTime += duration

						// SKIP INSTALLATION FOR CROSS-COMPILED PACKAGES
						// BUT allow it if we are building the cross-system (toolchain/sysroot packages)
						if cfg.Values["HOKUTO_CROSS"] == "1" && cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1" {
							colArrow.Print("-> ")
							colSuccess.Printf("Inline rebuild of '%s' completed.\n", parent)
							// CRITICAL: Remove the parent from the map to prevent multiple rebuilds.
							delete(plan.PostRebuilds, parent)
							continue
						}

						// Install the newly rebuilt parent
						version, revision, _ := getRepoVersion2(parent)
						outputParent := getOutputPackageName(parent, cfg)
						archiveParent := getArchivePackageName(parent, cfg)
						arch := GetSystemArchForPackage(cfg, parent)
						variant := GetSystemVariantForPackage(cfg, parent)
						tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveParent, version, revision, arch, variant))
						isCriticalAtomic.Store(1)
						handlePreInstallUninstall(outputParent, cfg, RootExec, false, nil)
						if _, installErr := pkgInstall(tarballPath, outputParent, cfg, RootExec, true, false, false, nil); installErr != nil {
							isCriticalAtomic.Store(0)
							colArrow.Print("-> ")
							color.Danger.Printf("Installation failed for rebuilt %s: %v\n", outputParent, installErr)
							failed[parent] = fmt.Errorf("install of rebuilt '%s' failed: %w", parent, installErr)
							return failed, successfullyBuiltTargets, totalElapsedTime, installedBuildDeps // Abort
						} else {
							isCriticalAtomic.Store(0)
							colArrow.Print("-> ")
							colSuccess.Printf("Inline rebuild of '%s' installed successfully.\n", parent)
						}

						// CRITICAL: Remove the parent from the map to prevent multiple rebuilds.
						delete(plan.PostRebuilds, parent)
					}
				}
			}
			// --- 2. NEW: Check for and execute post-build rebuilds ---
			if rebuilds, ok := plan.PostBuildRebuilds[pkgName]; ok {
				fmt.Println() // Add a blank line for readability
				colArrow.Print("-> ")
				colWarn.Printf("Executing post-build rebuilds triggered by %s: %v\n", pkgName, rebuilds)

				for _, rebuildPkg := range rebuilds {
					// A. Build the package again
					*progressCount++
					rebuildIdx := *progressCount
					duration, err := pkgBuild(rebuildPkg, cfg, UserExec, BuildOptions{
						Bootstrap:    *bootstrap,
						CurrentIndex: rebuildIdx,
						TotalCount:   totalInPlan,
					})
					if err != nil {
						color.Danger.Printf("Post-build of '%s' failed: %v\n", rebuildPkg, err)
						// Mark the PARENT package as failed, because its post-build action failed.
						failed[pkgName] = fmt.Errorf("post-build of '%s' failed: %w", rebuildPkg, err)
						break // Stop processing other rebuilds for this parent
					}
					totalElapsedTime += duration

					// B. Install the newly rebuilt package automatically
					version, revision, _ := getRepoVersion2(rebuildPkg)
					outputRebuildPkg := getOutputPackageName(rebuildPkg, cfg)
					archiveRebuildPkg := getArchivePackageName(rebuildPkg, cfg)
					arch := GetSystemArchForPackage(cfg, rebuildPkg)
					variant := GetSystemVariantForPackage(cfg, rebuildPkg)
					tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveRebuildPkg, version, revision, arch, variant))
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputRebuildPkg, cfg, RootExec, false, nil)
					// Always run this non-interactively
					if _, installErr := pkgInstall(tarballPath, outputRebuildPkg, cfg, RootExec, true, false, false, nil); installErr != nil {
						isCriticalAtomic.Store(0)
						colArrow.Print("-> ")
						color.Danger.Printf("Installation failed for post-build %s: %v\n", outputRebuildPkg, installErr)
						failed[pkgName] = fmt.Errorf("install of post-built '%s' failed: %w", rebuildPkg, installErr)
						return failed, successfullyBuiltTargets, totalElapsedTime, installedBuildDeps // Abort
					}
					isCriticalAtomic.Store(0)
				}
			}

		}
		toBuild = remainingAfterPass
		passInProgress = progressThisPass
	}
	if !plan.NoDeps {
		for _, pkg := range toBuild {
			if _, exists := failed[pkg]; !exists {
				// Find which dependency is missing to provide a better error message
				pkgDir, _ := findPackageDir(pkg)
				deps, _ := parseDependsFile(pkgDir)
				missingDep := "unknown"
				for _, dep := range deps {
					if !activeBuildDependency(dep, cfg, false) {
						continue
					}

					isSatisfied := false
					candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
					if err == nil {
						for _, cand := range candidates {
							if builtThisPass[cand] || findInstalledSatisfying(cand, dep.Op, dep.Version) != "" {
								isSatisfied = true
								break
							}
						}
					}
					if len(candidates) == 0 && len(dep.Alternatives) == 0 {
						if builtThisPass[dep.Name] || findInstalledSatisfying(dep.Name, dep.Op, dep.Version) != "" {
							isSatisfied = true
						}
					}

					if !isSatisfied {
						missingDep = dep.Name
						if dep.Op != "" {
							missingDep = fmt.Sprintf("%s%s%s", dep.Name, dep.Op, dep.Version)
						}
						break
					}
				}
				failed[pkg] = fmt.Errorf("dependency not satisfied: %s", missingDep)
			}
		}
	}
	return failed, successfullyBuiltTargets, totalElapsedTime, installedBuildDeps
}
