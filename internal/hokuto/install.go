package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/gookit/color"
	"golang.org/x/term"
)

type packageSuggestion struct {
	Package    string
	Name       string
	Op         string
	Version    string
	Alternates []string
	Dependency string
	Text       string
	// Order is the position in the declaring suggests list, so prompts
	// follow the order the packager chose (systemd before linux, whose
	// post-install needs udev).
	Order int
}

var packageSuggestions = struct {
	sync.Mutex
	items map[string]map[string]packageSuggestion
}{
	items: make(map[string]map[string]packageSuggestion),
}

// getRebuildTriggers parses /etc/hokuto/hokuto.rebuild and returns packages that should
// be rebuilt when the given trigger package is installed.
// Format: triggerpkg pkg1 pkg2 pkg3...
// Returns empty slice if no triggers found or file doesn't exist.
func getRebuildTriggers(triggerPkg string, rootDir string) []string {
	rebuildFilePath := filepath.Join(rootDir, "etc", "hokuto", "hokuto.rebuild")
	if rootDir == "/" {
		rebuildFilePath = "/etc/hokuto/hokuto.rebuild"
	}

	data, err := os.ReadFile(rebuildFilePath)
	if err != nil {
		data, err = readFileAsRoot(rebuildFilePath)
		if err != nil {
			// File doesn't exist or can't be read - that's fine, just return empty
			return nil
		}
	}

	var packagesToRebuild []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue // Need at least trigger package and one package to rebuild
		}

		// First field is the trigger package
		if fields[0] == triggerPkg {
			// Check if each package is installed before adding to rebuild list
			for _, pkg := range fields[1:] {
				// A kernel module package is rebuilt as the instance for
				// the kernel that triggered it (nvidia-open~linux-cachyos).
				if isKmodRecipe(pkg) {
					if instance := kmodInstanceName(pkg, triggerPkg); isPackageInstalled(instance) {
						packagesToRebuild = append(packagesToRebuild, instance)
					} else {
						debugf("Skipping rebuild trigger for %s (not installed)\n", instance)
					}
					continue
				}
				if isPackageInstalled(pkg) {
					packagesToRebuild = append(packagesToRebuild, pkg)
				} else {
					debugf("Skipping rebuild trigger for %s (not installed)\n", pkg)
				}
			}
			break // Found matching trigger, no need to continue
		}
	}

	return packagesToRebuild
}

func readPackageSuggestions(pkgName, rootDir string) []packageSuggestion {
	return readPackageSuggestionsForCollection(pkgName, rootDir, false)
}

func readPackageSuggestionsForCollection(pkgName, rootDir string, includeSatisfied bool) []packageSuggestion {
	suggestsPath := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName, "suggests")
	data, err := os.ReadFile(suggestsPath)
	if err != nil {
		data, err = readFileAsRoot(suggestsPath)
		if err != nil {
			return nil
		}
	}

	var missing []packageSuggestion
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		deps, err := parseDependsData([]byte(line))
		if err != nil || len(deps) == 0 {
			continue
		}
		depSpec := deps[0]
		if !depSpec.Suggest {
			continue
		}

		alternates := append([]string(nil), depSpec.Alternatives...)
		if len(alternates) == 0 && depSpec.Name != "" {
			alternates = []string{depSpec.Name}
		}
		if len(alternates) == 0 || (!includeSatisfied && suggestionSatisfied(depSpec)) {
			continue
		}

		dep := depSpec.Name
		if len(alternates) > 1 {
			dep = strings.Join(alternates, " | ")
		} else if depSpec.Op != "" {
			dep += depSpec.Op + depSpec.Version
		}
		missing = append(missing, packageSuggestion{
			Package:    pkgName,
			Name:       depSpec.Name,
			Op:         depSpec.Op,
			Version:    depSpec.Version,
			Alternates: alternates,
			Dependency: dep,
			Text:       depSpec.SuggestText,
		})
	}
	return missing
}

func suggestionSatisfied(dep DepSpec) bool {
	if len(dep.Alternatives) > 1 {
		for _, name := range dep.Alternatives {
			if name != "" && isPackageInstalled(name) {
				return true
			}
		}
		return false
	}
	return dep.Name != "" && findInstalledDependencySatisfying(dep.Name, dep.Op, dep.Version) != ""
}

func suggestionAlternativesInstalled(item packageSuggestion) bool {
	if len(item.Alternates) == 1 {
		return findInstalledDependencySatisfying(item.Alternates[0], item.Op, item.Version) != ""
	}
	for _, name := range item.Alternates {
		if name != "" && isPackageInstalled(name) {
			return true
		}
	}
	return false
}

func collectPackageSuggestions(pkgName, rootDir string) {
	// Cross-system packages (aarch64-*, x86_64-*) are sysroot copies used for
	// cross compiling; nothing on the host runs them, so their optional
	// runtime dependencies are never worth suggesting.
	if strings.HasPrefix(pkgName, "aarch64-") || strings.HasPrefix(pkgName, "x86_64-") {
		return
	}
	declared := readPackageSuggestionsForCollection(pkgName, rootDir, true)
	if len(declared) == 0 {
		return
	}

	packageSuggestions.Lock()
	defer packageSuggestions.Unlock()

	for i, item := range declared {
		item.Order = i
		if packageSuggestions.items[item.Package] == nil {
			packageSuggestions.items[item.Package] = make(map[string]packageSuggestion)
		}
		key := item.Dependency + "\x00" + item.Text
		packageSuggestions.items[item.Package][key] = item
	}
}

func collectMetaPackageSuggestions(meta MetaPackage) {
	if len(meta.Suggests) == 0 {
		return
	}

	packageSuggestions.Lock()
	defer packageSuggestions.Unlock()
	if packageSuggestions.items[meta.Name] == nil {
		packageSuggestions.items[meta.Name] = make(map[string]packageSuggestion)
	}
	for order, depSpec := range meta.Suggests {
		alternates := append([]string(nil), depSpec.Alternatives...)
		if len(alternates) == 0 && depSpec.Name != "" {
			alternates = []string{depSpec.Name}
		}
		if len(alternates) == 0 {
			continue
		}
		dependency := depSpec.Name
		if len(alternates) > 1 {
			dependency = strings.Join(alternates, " | ")
		} else if depSpec.Op != "" {
			dependency += depSpec.Op + depSpec.Version
		}
		item := packageSuggestion{
			Package: meta.Name, Name: depSpec.Name, Op: depSpec.Op, Version: depSpec.Version,
			Alternates: alternates, Dependency: dependency, Text: depSpec.SuggestText,
			Order: order,
		}
		key := item.Dependency + "\x00" + item.Text
		packageSuggestions.items[meta.Name][key] = item
	}
}

func hasPackageSuggestions() bool {
	packageSuggestions.Lock()
	defer packageSuggestions.Unlock()
	return len(packageSuggestions.items) > 0
}

func discardPackageSuggestions() {
	packageSuggestions.Lock()
	packageSuggestions.items = make(map[string]map[string]packageSuggestion)
	packageSuggestions.Unlock()
}

func flushPackageSuggestions(logger io.Writer, cfg *Config, noRemote bool, promptInstall bool, autoYes bool) {
	if logger == nil {
		logger = os.Stdout
	}

	packageSuggestions.Lock()
	items := packageSuggestions.items
	packageSuggestions.items = make(map[string]map[string]packageSuggestion)
	packageSuggestions.Unlock()

	// hokuto-builder only builds packages; what its container has installed
	// is build dependencies, which need no optional extras.
	if len(items) == 0 || runningInHokutoBuilder() {
		return
	}

	var packages []string
	pending := make(map[string][]packageSuggestion)
	// On an architecture served by cross builds, a suggestion whose recipe
	// was never prepared for them has no package to install.
	installableOnArch := make(map[string]bool)
	for pkg := range items {
		if !packageOrMetaInstalled(pkg) {
			continue
		}
		// dracut, pulled in only to run a kernel's post-install hook, is
		// not something the user chose; its optional extras are not worth
		// asking about.
		if installedOnlyForPostInstall(pkg) {
			continue
		}
		for _, item := range items[pkg] {
			if suggestionAlternativesInstalled(item) {
				continue
			}
			if cfg != nil {
				var ok bool
				if item, ok = filterSuggestionForArch(item, cfg, noRemote, installableOnArch); !ok {
					continue
				}
			}
			pending[pkg] = append(pending[pkg], item)
		}
		if len(pending[pkg]) > 0 {
			packages = append(packages, pkg)
		}
	}
	if len(packages) == 0 {
		return
	}
	sort.Strings(packages)

	// Each suggestion is asked about below, with its text; the list is
	// only for runs that do not ask. Suggestions are optional and default to
	// No, so -y (and the auto-bump's global yes) takes that default: they
	// are listed but never installed without an explicit answer.
	asking := promptInstall && cfg != nil && !autoYes && !GlobalAssumeYes
	if !asking {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprintln(logger, colSuccess.Sprint("Suggested optional runtime dependencies:"))
	}
	var installPrompts []packageSuggestion
	// Suggestions are installed like dependencies, which leave the global
	// post-install tasks (ldconfig, the GSettings schemas, icon and desktop
	// caches) to the command; it ran them before asking. Run them again once
	// anything was installed here: pwvucontrol, accepted as a suggestion of
	// xfce4-pulseaudio-plugin, aborted on its uncompiled schema.
	installedSuggestion := false
	defer func() {
		if installedSuggestion {
			if err := PostInstallTasks(RootExec, logger); err != nil {
				fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: post-install tasks failed: %v", err))
			}
		}
	}()
	for _, pkg := range packages {
		if !asking {
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprintln(logger, colNote.Sprintf("%s:", pkg))
		}

		suggestions := pending[pkg]
		sort.Slice(suggestions, func(i, j int) bool {
			if suggestions[i].Order != suggestions[j].Order {
				return suggestions[i].Order < suggestions[j].Order
			}
			if suggestions[i].Dependency == suggestions[j].Dependency {
				return suggestions[i].Text < suggestions[j].Text
			}
			return suggestions[i].Dependency < suggestions[j].Dependency
		})

		for _, item := range suggestions {
			if !asking {
				fmt.Fprint(logger, colArrow.Sprint("-> "))
				fmt.Fprint(logger, "  ")
				fmt.Fprint(logger, colNote.Sprint(item.Dependency))
				if item.Text != "" {
					fmt.Fprintf(logger, " - %s", item.Text)
				}
				fmt.Fprintln(logger)
			}
			if asking {
				installPrompts = append(installPrompts, item)
			}
		}
	}

	for _, item := range installPrompts {
		if suggestionAlternativesInstalled(item) {
			continue
		}

		for _, altName := range item.Alternates {
			if altName == "" || isPackageInstalled(altName) {
				continue
			}
			// Every piece is colored: a name's color ends with a reset, which
			// would leave the text after it uncolored.
			prompt := colSuccess.Sprint("Install suggested dependency ") + colNote.Sprint(altName) +
				colSuccess.Sprint(" for ") + colNote.Sprint(item.Package) + colSuccess.Sprint("?")
			if item.Text != "" {
				prompt += fmt.Sprintf(" (%s)", item.Text)
			}
			if !askForConfirmationDefaultNo(colSuccess, "%s%s", colArrow.Sprint("-> "), prompt) {
				continue
			}

			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprint(logger, colSuccess.Sprint("Installing suggested dependency: "))
			fmt.Fprintln(logger, colNote.Sprint(altName))
			if _, err := ensurePackageInstalled(altName, cfg, noRemote); err != nil {
				fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: failed to install suggested dependency %s: %v", altName, err))
				continue
			}
			installedSuggestion = true
			if err := recordAcceptedSuggestion(item.Package, altName); err != nil {
				fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colWarn.Sprintf("Warning: failed to record %s as a suggested dependency of %s: %v", altName, item.Package, err))
			}
			break
		}
	}

	if promptInstall && cfg != nil && hasPackageSuggestions() {
		flushPackageSuggestions(logger, cfg, noRemote, promptInstall, autoYes)
	}
}

func installMissingPackageRuntimeDependencies(pkgName string, cfg *Config, logger io.Writer, quiet, noRemote bool) error {
	if cfg != nil && cfg.Values["HOKUTO_BOOTSTRAP"] == "1" {
		return nil
	}
	if suppressRuntimeDependencyAutoInstall.Load() > 0 {
		return nil
	}

	dependsPath := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName, "depends")
	data, err := os.ReadFile(dependsPath)
	if err != nil {
		data, err = readFileAsRoot(dependsPath)
		if err != nil {
			return nil
		}
	}

	deps, err := parseDependsData(data)
	if err != nil {
		return fmt.Errorf("failed to parse installed dependencies for %s: %w", pkgName, err)
	}

	for _, dep := range deps {
		if dep.Make || dep.Optional || dep.Rebuild || dep.PostInstall || dep.Suggest {
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
		if hostLineOfCrossSystemPackage(pkgName, depName) {
			continue
		}
		if _, inProgress := runtimeDependencyInstallInProgress.Load(depName); inProgress {
			continue
		}
		if _, planned := installPlanPending.Load(depName); planned {
			continue
		}
		if findInstalledDependencySatisfying(depName, dep.Op, dep.Version) != "" {
			continue
		}
		// An older release a constraint needs (glew<2.3): from the mirror,
		// unless the plan being installed brings it.
		if !noRemote {
			if pinned, ok := pinnedReleaseFor(depName, dep.Op, dep.Version, cfg, nil); ok {
				if _, planned := installPlanPending.Load(pinned); planned {
					continue
				}
				if _, err := installRuntimeDependencyBinaryOnly(pinned, cfg, noRemote, nil, quiet); err != nil {
					return fmt.Errorf("failed to install runtime dependency %s for %s: %w", pinned, pkgName, err)
				}
				continue
			}
		}
		depName = wildcardMajorDependencyName(depName, dep.Op, dep.Version)

		if binaryOnlyRuntimeDependencyInstall.Load() > 0 {
			installed, err := installRuntimeDependencyBinaryOnly(depName, cfg, noRemote, nil, quiet)
			if err != nil {
				return fmt.Errorf("failed to install binary runtime dependency %s for %s: %w", depName, pkgName, err)
			}
			if !installed {
				// Often only "not built yet" (this run builds it) or a cycle
				// still being resolved; repairInstalledRuntimeDeps reports
				// what is really missing before anything is compiled.
				debugf("Skipping runtime dependency %s for %s during build: no binary available\n", depName, pkgName)
			} else if !quiet {
				if logger == nil {
					logger = os.Stdout
				}
				fmt.Fprint(logger, colArrow.Sprint("-> "))
				fmt.Fprintf(logger, "%s", colSuccess.Sprint("Installed binary runtime dependency: "))
				fmt.Fprintln(logger, colNote.Sprint(depName))
			}
			continue
		}
		if !quiet {
			if logger == nil {
				logger = os.Stdout
			}
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprintf(logger, "%s", colSuccess.Sprint("Installing runtime dependency: "))
			fmt.Fprintln(logger, colNote.Sprint(depName))
		}
		if _, err := ensurePackageInstalledWithOptions(depName, cfg, noRemote, nil, quiet); err != nil {
			return fmt.Errorf("failed to install runtime dependency %s for %s: %w", depName, pkgName, err)
		}
	}

	return nil
}

func installPostInstallDependencies(pkgName string, cfg *Config, execCtx *Executor, logger io.Writer, quiet, noRemote, yes bool) ([]string, error) {
	dependsPath := filepath.Join(Installed, pkgName, "depends")
	data, err := os.ReadFile(dependsPath)
	if err != nil {
		data, err = readFileAsRoot(dependsPath)
		if err != nil {
			return nil, nil
		}
	}

	deps, err := parseDependsData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse installed dependencies for %s: %w", pkgName, err)
	}

	before := snapshotInstalledPackageNames()
	cleanupOnError := func(installErr error) ([]string, error) {
		newlyInstalled := newlyInstalledPackageNames(before)
		if cleanupErr := cleanupPostInstallDependencies(newlyInstalled, cfg, execCtx, logger, quiet); cleanupErr != nil {
			return nil, fmt.Errorf("%w (cleanup also failed: %v)", installErr, cleanupErr)
		}
		return nil, installErr
	}

	for _, dep := range deps {
		if !dep.PostInstall {
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
			resolved, err := resolveAlternativeDep(dep, yes, cfg, pkgName)
			if err != nil {
				return cleanupOnError(fmt.Errorf("failed to resolve post-install dependency for %s: %w", pkgName, err))
			}
			depName = resolved
		}
		if depName == "" || depName == pkgName || shouldSkipMultilibMakeDep(dep, depName, cfg) {
			continue
		}
		if findInstalledDependencySatisfying(depName, dep.Op, dep.Version) != "" {
			continue
		}
		depName = wildcardMajorDependencyName(depName, dep.Op, dep.Version)

		if !quiet {
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprint(logger, colSuccess.Sprint("Installing post-install dependency: "))
			fmt.Fprintln(logger, colNote.Sprint(depName))
		}
		if _, err := ensurePackageInstalledWithOptions(depName, cfg, noRemote, nil, quiet); err != nil {
			return cleanupOnError(fmt.Errorf("failed to install post-install dependency %s for %s: %w", depName, pkgName, err))
		}
	}

	return newlyInstalledPackageNames(before), nil
}

func newlyInstalledPackageNames(before map[string]bool) []string {
	var packages []string
	for pkgName := range snapshotInstalledPackageNames() {
		if !before[pkgName] {
			packages = append(packages, pkgName)
		}
	}
	sort.Strings(packages)
	return packages
}

func cleanupPostInstallDependencies(packages []string, cfg *Config, execCtx *Executor, logger io.Writer, quiet bool) error {
	remaining := append([]string(nil), packages...)
	var failures []string
	for len(remaining) > 0 {
		removedThisPass := false
		var stillNeeded []string
		for i := len(remaining) - 1; i >= 0; i-- {
			pkgName := remaining[i]
			if len(installedDependents(pkgName, cfg, nil)) > 0 {
				stillNeeded = append(stillNeeded, pkgName)
				continue
			}
			if !quiet {
				fmt.Fprint(logger, colArrow.Sprint("-> "))
				fmt.Fprint(logger, colSuccess.Sprint("Removing post-install dependency: "))
				fmt.Fprintln(logger, colNote.Sprint(pkgName))
			}
			if err := pkgUninstallWithRemovalSet(pkgName, cfg, execCtx, false, true, logger, nil); err != nil {
				fmt.Fprintf(logger, "warning: failed to remove post-install dependency %s: %v\n", pkgName, err)
				stillNeeded = append(stillNeeded, pkgName)
				continue
			}
			removeFromWorld(pkgName)
			removeFromWorldMake(pkgName)
			removedThisPass = true
		}
		if !removedThisPass {
			for _, pkgName := range stillNeeded {
				dependents := installedDependents(pkgName, cfg, nil)
				if len(dependents) > 0 {
					failures = append(failures, fmt.Sprintf("%s is still required by %s", pkgName, strings.Join(dependents, ", ")))
				} else {
					failures = append(failures, pkgName)
				}
			}
			break
		}
		remaining = stillNeeded
	}
	if len(failures) > 0 {
		return fmt.Errorf("failed to remove temporary post-install dependencies: %s", strings.Join(failures, "; "))
	}
	return nil
}

func confirmInstallPlanWithAsk(installPlan []string, metas map[string]MetaPackage) bool {
	colArrow.Print("-> ")
	colSuccess.Println("Install preview (--ask)")

	if len(installPlan) == 0 {
		colArrow.Print("-> ")
		colNote.Println("Packages to install: none")
	} else {
		colArrow.Print("-> ")
		colNote.Printf("Packages to install (%d): %s\n", len(installPlan), strings.Join(installPlan, " -> "))
	}

	metaNames := make([]string, 0, len(metas))
	for name := range metas {
		metaNames = append(metaNames, name)
	}
	sort.Strings(metaNames)
	if len(metaNames) > 0 {
		colArrow.Print("-> ")
		colNote.Printf("Metapackages to mark installed (%d): %s\n", len(metaNames), strings.Join(metaNames, ", "))
	}

	return askForConfirmationDefaultNo(colWarn, "Proceed with install?")
}

// pkgInstall installs a compiled hokuto package from a tarball.
// If yes is true, it assumes 'yes' to all prompts.
// If fast is true, it optimizes for speed (e.g., skip some UI/status updates).
// If managed is true, it skips internal rebuild triggers (e.g. DKMS) assuming the caller handles them.
// pkgInstall installs a package from a tarball.
// It returns a list of packages that need to be rebuilt if managed is true, or nil otherwise.
func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes, fast, managed bool, logger io.Writer) ([]string, error) {
	return pkgInstallWithRemotePolicy(tarballPath, pkgName, cfg, execCtx, yes, fast, managed, true, logger)
}

func stagedArchivePackageName(stagingDir, requestedName string) (string, error) {
	metadataRoot := filepath.Join(stagingDir, "var", "db", "hokuto", "installed")
	if info, err := os.Stat(filepath.Join(metadataRoot, requestedName)); err == nil && info.IsDir() {
		return requestedName, nil
	}
	entries, err := os.ReadDir(metadataRoot)
	if err != nil {
		return "", fmt.Errorf("package archive has no installed metadata: %w", err)
	}
	var candidates []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(metadataRoot, entry.Name(), "pkginfo")); err == nil {
			candidates = append(candidates, entry.Name())
		}
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("cannot determine package identity from archive: found %d metadata directories", len(candidates))
	}
	return candidates[0], nil
}

// pkgInstallWithRemotePolicy installs a package and controls whether runtime
// dependencies discovered after extraction may be fetched from the binary
// mirror. Callers that do not explicitly opt in retain pkgInstall's historical
// local-only behavior.
func pkgInstallWithRemotePolicy(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes, fast, managed, noRemote bool, logger io.Writer) ([]string, error) {
	defer lockInstalledState()()
	oldRelease, wasInstalled := installedRelease(pkgName)
	rebuilds, err := installPackageArchive(tarballPath, pkgName, cfg, execCtx, yes, fast, managed, noRemote, logger)
	if err == nil {
		logPackageInstall(pkgName, oldRelease, wasInstalled)
	}
	return rebuilds, err
}

// installPackageArchive is pkgInstallWithRemotePolicy under the
// installed-state lock.
func installPackageArchive(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes, fast, managed, noRemote bool, logger io.Writer) ([]string, error) {
	transferEquivalentWorld := false
	transferEquivalentWorldMake := false
	if logger == nil {
		logger = os.Stdout
	}
	// "Installing" message is now handled by the caller (cli.go, update.go, build.go)
	// to avoid duplicate output.

	// glibc is not placed like other packages: replacing the C library file
	// by file under running tools is what the staging copy cannot survive.
	// It is still unpacked into staging first, so its signature and version
	// hold are checked like any other package's, and then copied into the
	// root by tar in one pass from the verified tree.
	if pkgName == "glibc" {
		stagingBase := installStagingBase(rootDir, tmpDir, cfg)
		stagingDir := filepath.Join(stagingBase, pkgName, "staging")
		os.RemoveAll(stagingDir)
		if err := os.MkdirAll(stagingDir, 0o755); err != nil {
			return nil, fmt.Errorf("failed to create staging dir: %v", err)
		}
		defer func() { _ = removeAllPrivilegedFallback(filepath.Join(stagingBase, pkgName), execCtx) }()
		if err := unpackPackageToStaging(tarballPath, stagingDir, execCtx); err != nil {
			return nil, err
		}
		sigLogger := logger
		if fast {
			sigLogger = io.Discard
		}
		if err := VerifyPackageSignature(stagingDir, pkgName, cfg, execCtx, sigLogger); err != nil {
			return nil, err
		}
		if version, err := stagedPackageVersion(stagingDir, pkgName); err == nil {
			if err := checkLock(pkgName, version); err != nil {
				colArrow.Print("-> ")
				colError.Println(err)
				return nil, err
			}
		}

		if !fast {
			fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprint("Installing glibc using direct extraction method"))
		}

		var extractErr error
		tarSuccess := false
		if _, err := exec.LookPath("tar"); err == nil {
			tarCmd := exec.Command("sh", "-c", `tar -C "$1" -cf - . | tar -C "$2" -xpf -`, "sh", stagingDir, rootDir)
			if Debug {
				tarCmd.Stdout = os.Stdout
				tarCmd.Stderr = os.Stderr
			} else {
				tarCmd.Stdout = io.Discard
				tarCmd.Stderr = io.Discard
			}

			if err := execCtx.Run(tarCmd); err == nil {
				tarSuccess = true
				if !fast {
					fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprint("glibc installed successfully via direct extraction"))
				}
			} else {
				debugf("System tar failed for %s, falling back to internal tar+zstd: %v\n", tarballPath, err)
			}
		}

		if !tarSuccess {
			// Verified above; this reads the same archive again.
			if os.Geteuid() == 0 {
				if err := unpackTarballFallback(tarballPath, rootDir); err != nil {
					extractErr = fmt.Errorf("native fallback failed: %v", err)
				} else if !fast {
					fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprint("glibc installed successfully via direct extraction"))
				}
			} else {
				extractErr = fmt.Errorf("installing as a normal user needs a working tar with zstd; install tar and zstd, or run hokuto as root")
			}
		}

		if extractErr != nil {
			return nil, fmt.Errorf("failed to extract glibc tarball: %v", extractErr)
		}

		postInstallDeps, err := installPostInstallDependencies(pkgName, cfg, execCtx, logger, fast, noRemote, yes)
		if err != nil {
			return nil, err
		}

		// Always run post-install hook for glibc
		if err := executePostInstall(pkgName, rootDir, execCtx, cfg, logger, fast); err != nil {
			colArrow.Print("-> ")
			color.Danger.Printf("post-install for %s returned error: %v\n", pkgName, err)
		}
		if err := cleanupPostInstallDependencies(postInstallDeps, cfg, execCtx, logger, fast); err != nil {
			return nil, err
		}

		if !fast {
			// Run global post-install tasks immediately if not in fast mode
			if err := PostInstallTasks(execCtx, logger); err != nil {
				fmt.Fprintf(logger, "Warning: %v\n", err)
			}
		}

		registerInstalledPackageInfo(rootDir, pkgName, cfg)
		collectPackageSuggestions(pkgName, rootDir)
		return nil, nil
	}

	// Stage on the destination's own filesystem so the package can be hard
	// linked into place instead of copied. TMPDIR is unsuitable here: it is
	// routinely a tmpfs or zram disk for fast builds, which is a different
	// filesystem from the root and would force a full second copy.
	stagingBase := installStagingBase(rootDir, tmpDir, cfg)
	stagingDir := filepath.Join(stagingBase, pkgName, "staging")
	pkgTmpDir := filepath.Join(stagingBase, pkgName)

	// Declare and initialize the 'failed' slice for tracking non-fatal errors
	var failed []string

	// Clean staging dir
	os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create staging dir: %v", err)
	}

	// 1. Unpack tarball into staging
	debugf("Unpacking %s into %s\n", tarballPath, stagingDir)

	if err := unpackPackageToStaging(tarballPath, stagingDir, execCtx); err != nil {
		return nil, err
	}

	archivePkgName, err := stagedArchivePackageName(stagingDir, pkgName)
	if err != nil {
		return nil, err
	}

	// 1.5. Verify package signature
	sigLogger := logger
	if fast {
		sigLogger = io.Discard
	}
	if err := VerifyPackageSignature(stagingDir, archivePkgName, cfg, execCtx, sigLogger); err != nil {
		return nil, err
	}
	// Kernel modules must match the release their kernel has installed now.
	if _, _, isKmod := splitKmodInstance(archivePkgName); isKmod {
		info, err := readFileAsRoot(filepath.Join(stagingDir, "var", "db", "hokuto", "installed", archivePkgName, "pkginfo"))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to read pkginfo: %w", archivePkgName, err)
		}
		if err := checkKmodStagedRelease(archivePkgName, ParsePkgInfo(info)); err != nil {
			return nil, err
		}
	}
	if archivePkgName != pkgName {
		from := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", archivePkgName)
		to := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
		if _, err := os.Stat(to); err == nil {
			return nil, fmt.Errorf("cannot install %s as %s: target metadata already exists", archivePkgName, pkgName)
		}
		if err := os.Rename(from, to); err != nil {
			if moveErr := execCtx.Run(exec.Command("mv", "--", from, to)); moveErr != nil {
				return nil, fmt.Errorf("failed to assign parallel install identity %s to %s: %w", pkgName, archivePkgName, moveErr)
			}
		}
		if err := renameManifestMetadataPaths(filepath.Join(to, "manifest"), archivePkgName, pkgName, execCtx); err != nil {
			return nil, fmt.Errorf("failed to assign parallel install identity %s to %s: %w", pkgName, archivePkgName, err)
		}
	}

	// Helper function to run diff with root executor fallback if permission denied
	runDiffWithFallback := func(file1, file2 string, outputToStdout bool) error {
		// Helper to filter binary diff messages
		printFiltered := func(out string) {
			if strings.HasPrefix(out, "Binary files") && strings.Contains(out, "differ") {
				if Debug {
					fmt.Print(out)
				}
			} else {
				fmt.Print(out)
			}
		}
		// Try to check if we can read the file first
		if f, err := os.Open(file1); err != nil {
			// If we can't read file1 due to permissions, try with root executor
			if os.IsPermission(err) {
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var outBuf bytes.Buffer
				if outputToStdout {
					diffCmd.Stdout = &outBuf
					diffCmd.Stderr = os.Stderr
				}
				// diff returns non-zero when files differ, which is normal - ignore that
				_ = RootExec.Run(diffCmd)

				if outputToStdout {
					printFiltered(outBuf.String())
				}
				return nil
			}
		} else {
			f.Close()
		}

		// Try normal diff first
		diffCmd := exec.Command("diff", "-u", file1, file2)
		var outBuf bytes.Buffer
		if outputToStdout {
			diffCmd.Stdout = &outBuf
			diffCmd.Stderr = os.Stderr
		}

		err := diffCmd.Run()

		// If diff returns error (exit code 1 means diffs found, >1 means error)
		if err != nil {
			// Check if it's a permission issue by trying to read the file again
			if _, readErr := os.Open(file1); readErr != nil && os.IsPermission(readErr) {
				// Retry with root executor
				diffCmd := exec.Command("diff", "-u", file1, file2)
				outBuf.Reset()
				if outputToStdout {
					diffCmd.Stdout = &outBuf
					diffCmd.Stderr = os.Stderr
				}
				_ = RootExec.Run(diffCmd)

				if outputToStdout {
					printFiltered(outBuf.String())
				}
				return nil
			}
		}

		// Print the captured output (if any) from the normal run
		if outputToStdout {
			printFiltered(outBuf.String())
		}
		return nil
	}

	// Helper function to get diff output with root executor fallback if permission denied
	getDiffOutput := func(file1, file2 string) ([]byte, error) {
		// Try to check if we can read the file first
		if f, err := os.Open(file1); err != nil {
			// If we can't read file1 due to permissions, try with root executor
			if os.IsPermission(err) {
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var out bytes.Buffer
				diffCmd.Stdout = &out
				diffCmd.Stderr = &out
				// diff returns non-zero when files differ, which is normal - ignore that
				_ = RootExec.Run(diffCmd)
				return out.Bytes(), nil
			}
		} else {
			f.Close()
		}
		// Try normal diff first
		diffOut, err := exec.Command("diff", "-u", file1, file2).Output()
		// If diff fails, check if it's a permission issue by trying to read the file again
		if err != nil {
			if _, readErr := os.Open(file1); readErr != nil && os.IsPermission(readErr) {
				// Retry with root executor
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var out bytes.Buffer
				diffCmd.Stdout = &out
				diffCmd.Stderr = &out
				_ = RootExec.Run(diffCmd)
				return out.Bytes(), nil
			}
		}
		// diff returns non-zero when files differ, which is normal - return output anyway
		return diffOut, nil
	}

	// 2. Detect user-modified files
	debugf("detect user modified files")

	// Determine if this package was built as a user (for optimization)
	// Check for asroot file in the staging directory metadata (embedded during build)
	stagingMetadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	asRootFile := filepath.Join(stagingMetadataDir, "asroot")
	versionFile := filepath.Join(stagingMetadataDir, "version")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}

	// Check if package version is locked
	if data, err := os.ReadFile(versionFile); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			version := fields[0]
			if err := checkLock(pkgName, version); err != nil {
				colArrow.Print("-> ")
				colError.Println(err)
				return nil, err
			}
		}
	}

	// Use appropriate executor for modified files detection
	var modifiedExec *Executor
	if needsRootBuild {
		// Package was built as root, use root executor
		modifiedExec = execCtx
	} else {
		// Package was built as user, use user executor for faster checksum computation
		modifiedExec = &Executor{
			Context:         execCtx.Context,
			ShouldRunAsRoot: false,
		}
		debugf("Using optimized user executor for modified files detection (package built as user)\n")
	}

	modifiedFiles, err := getModifiedFiles(pkgName, rootDir, modifiedExec)
	if err != nil {
		if !modifiedExec.ShouldRunAsRoot {
			debugf("optimized user modified files detection failed, falling back to root executor: %v\n", err)
			modifiedFiles, err = getModifiedFiles(pkgName, rootDir, execCtx) // execCtx is original (likely root)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// 3. Interactive handling of modified files
	stdinReader := bufio.NewReader(os.Stdin)
	skipAllPrompts := false // Flag to skip prompts for all remaining files
	// Track files removed from staging due to conflicts (to remove from manifest later)
	filesRemovedFromStaging := make(map[string]bool)
	// Track files that were already handled in conflict checks (to skip duplicate prompts)
	filesHandledInConflict := make(map[string]bool)
	for _, file := range modifiedFiles {
		stagingFile := filepath.Join(stagingDir, file)
		currentFile := filepath.Join(rootDir, file) // file under the install root

		// "Use new for [A]ll" was chosen: the file stays in staging and
		// replaces the modified one.
		if skipAllPrompts {
			continue
		}
		// Without prompts (yes mode: remote updates, dependency installs,
		// rebuilds, -y) no change made on this system is lost: /etc/passwd
		// edited by useradd must survive a sauzeros-base update. A modified
		// file the package still has is kept; one it dropped is moved to the
		// backup directory. No diff is shown -- it would print files like
		// /etc/shadow.
		if yes && !fast {
			if _, err := os.Lstat(stagingFile); err == nil {
				if err := keepCurrentFileInStaging(currentFile, stagingFile, execCtx); err != nil {
					return nil, err
				}
				fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colNote.Sprintf("Kept modified %s; the version from %s was not installed", file, pkgName))
			} else {
				backupPath, err := moveRemovedFileToBackup(currentFile, file, execCtx)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colNote.Sprintf("%s no longer contains %s, which was modified here: moved it to %s", pkgName, file, backupPath))
			}
			filesHandledInConflict[file] = true
			continue
		}

		// --- NEW: Find the owner package ---
		ownerPkg, err := findOwnerPackage(file)
		if err != nil {
			// Non-fatal, but print error
			cPrintf(color.FgRed, "Warning: Failed to find owner for %s: %v\n", file, err)
			ownerPkg = "UNKNOWN" // Use UNKNOWN if the lookup failed
		}
		if ownerPkg == "" {
			ownerPkg = "UNMANAGED" // Use UNMANAGED if no manifest lists the file
		}

		if _, err := os.Stat(stagingFile); err == nil {
			// file exists in staging

			// --- NEW: Check for file conflict with another package ---
			conflictPkg, conflictChecksumMatches, isSymlink, symlinkTarget := checkFileConflict(file, currentFile, pkgName, rootDir, execCtx)
			if conflictPkg != "" && conflictChecksumMatches {
				// File is already installed from another package and checksum matches
				// Check if staging file (from new package) is a symlink or regular file
				stagingIsSymlink := false
				var stagingSymlinkTarget string
				if stagingInfo, err := os.Lstat(stagingFile); err == nil && stagingInfo.Mode()&os.ModeSymlink != 0 {
					stagingIsSymlink = true
					if target, err := os.Readlink(stagingFile); err == nil {
						stagingSymlinkTarget = target
					}
				}

				// Show conflict-specific prompt
				runDiffWithFallback(currentFile, stagingFile, true)
				os.Stdout.Sync()

				var input string
				if !yes && !skipAllPrompts && !fast {
					if isSymlink && symlinkTarget != "" {
						// Existing file is a symlink
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							printKeyChoicePrompt(styledPrompt("Symlink ", file+" -> "+symlinkTarget, " is already installed from ", conflictPkg, ":"), fmt.Sprintf("[K]eep %s symlink, [u]se %s symlink", conflictPkg, pkgName))
						} else {
							printKeyChoicePrompt(styledPrompt("Symlink ", file+" -> "+symlinkTarget, " is already installed from ", conflictPkg, ":"), fmt.Sprintf("[K]eep %s symlink, [u]se %s file", conflictPkg, pkgName))
						}
					} else {
						// Existing file is a regular file
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							printKeyChoicePrompt(styledPrompt("File ", file, " is already installed from ", conflictPkg, ":"), fmt.Sprintf("[K]eep %s file, [u]se %s symlink", conflictPkg, pkgName))
						} else {
							printKeyChoicePrompt(styledPrompt("File ", file, " is already installed from ", conflictPkg, ":"), fmt.Sprintf("[K]eep %s file, [u]se %s file", conflictPkg, pkgName))
						}
					}
					os.Stdout.Sync()
					response, err := stdinReader.ReadString('\n')
					if err != nil {
						response = "k" // Default to keep on read error
					}
					input = strings.TrimSpace(response)
				}
				if input == "" {
					input = "k" // Default to keep if user presses enter, even in fast mode
				}
				switch strings.ToLower(input) {
				case "k":
					// Keep the file from the other package - delete from staging
					if os.Geteuid() == 0 {
						if err := os.Remove(stagingFile); err != nil {
							return nil, fmt.Errorf("failed to remove file from staging %s natively: %v", stagingFile, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-f", stagingFile)
						if err := execCtx.Run(rmCmd); err != nil {
							return nil, fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
						}
					}
					// Track this file for manifest removal
					filesRemovedFromStaging[file] = true
					if isSymlink {
						debugf("Kept symlink from %s package, removed from staging: %s -> %s\n", conflictPkg, file, symlinkTarget)
					} else {
						debugf("Kept file from %s package, removed from staging: %s\n", conflictPkg, file)
					}
					continue // Skip to next file
				case "u":
					// Use the new file from current package - mark as handled and skip modified file prompt
					filesHandledInConflict[file] = true
					// File stays in staging, continue to next file (skip modified file handling)
					continue
				default:
					// Invalid input, default to keep
					if os.Geteuid() == 0 {
						if err := os.Remove(stagingFile); err != nil {
							return nil, fmt.Errorf("failed to remove file from staging %s natively: %v", stagingFile, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-f", stagingFile)
						if err := execCtx.Run(rmCmd); err != nil {
							return nil, fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
						}
					}
					// Track this file for manifest removal
					filesRemovedFromStaging[file] = true
					if isSymlink {
						debugf("Kept symlink from %s package (invalid input), removed from staging: %s -> %s\n", conflictPkg, file, symlinkTarget)
					} else {
						debugf("Kept file from %s package (invalid input), removed from staging: %s\n", conflictPkg, file)
					}
					continue
				}
			}

			// Skip if this file was already handled in conflict check
			if filesHandledInConflict[file] {
				continue
			}

			// The fast installer keeps its progress bar on the current
			// terminal line. Move below it before the diff and the prompt, so
			// they do not get appended to the progress bar.
			if fast {
				prepareDependencyProgressLogOutput()
			}
			// Try to display diff, retry with root executor if permission
			// denied. A file only root may read (/etc/shadow, /etc/gshadow,
			// sudoers) is not shown: its contents would end up on the
			// terminal and in its scrollback.
			if rootOnlyReadable(currentFile) {
				colArrow.Print("-> ")
				fmt.Println(styledPrompt("The changes to ", file, " are not shown: only root may read it."))
			} else {
				runDiffWithFallback(currentFile, stagingFile, true)
			}
			// Flush stdout to ensure diff output is visible before prompt
			os.Stdout.Sync()

			var input string
			// Asked even with -y in a fast (update) install, as the user's own
			// edits are at stake; without a terminal to answer (hokuto-builder's
			// service), the default keeps them.
			if ((!yes && !skipAllPrompts) || fast) && !term.IsTerminal(int(os.Stdin.Fd())) {
				colArrow.Print("-> ")
				fmt.Println(styledPrompt("Kept the modified ", file, ": no terminal to ask about it."))
			} else if (!yes && !skipAllPrompts) || fast {
				printKeyChoicePrompt(styledPrompt("File ", file, " was modified here (owner: ", ownerPkg, "). Choose:"), "[K]eep current, [u]se new, [b]ackup, [e]dit, use new for [A]ll")
				// Flush stdout to ensure prompt is visible
				os.Stdout.Sync()
				// Use the shared, robust bufio.Reader
				response, err := stdinReader.ReadString('\n')
				if err != nil {
					// Default to 'k' on read error (e.g., Ctrl+D)
					response = "k"
				}
				input = strings.TrimSpace(response)
			}
			if input == "" {
				input = "k" // Default to 'keep' if user presses enter, even in fast mode
			}
			switch strings.ToLower(input) {
			case "k":
				if err := keepCurrentFileInStaging(currentFile, stagingFile, execCtx); err != nil {
					return nil, err
				}
			case "u":
				// keep staging file as-is
			case "b":
				// Backup current file and use new file from package (keep staging file as-is)
				if err := backupModifiedFile(currentFile, file, execCtx, logger); err != nil {
					return nil, fmt.Errorf("failed to backup modified file %s: %w", currentFile, err)
				}
			case "a":
				// Use new for all remaining files - set flag and use new for this file
				skipAllPrompts = true
				// keep staging file as-is (same as "u")
			case "e":
				// --- NEW: Get original staging file permissions ---
				stagingInfo, err := os.Stat(stagingFile)
				if err != nil {
					return nil, fmt.Errorf("failed to stat staging file %s: %v", stagingFile, err)
				}
				originalMode := stagingInfo.Mode()
				// read staging content
				stContent, err := os.ReadFile(stagingFile)
				if err != nil {
					return nil, fmt.Errorf("failed to read staging file %s: %v", stagingFile, err)
				}

				// produce unified diff (currentFile vs stagingFile); ignore diff errors (non-zero exit means differences)
				// Try to get diff output, retry with root executor if permission denied
				diffOut, _ := getDiffOutput(currentFile, stagingFile) // we don't fail if diff returns non-zero

				// create temp file prefilled with staging content + marked diff
				tmp, err := os.CreateTemp("", "hokuto-edit-")
				if err != nil {
					return nil, fmt.Errorf("failed to create temp file for editing: %v", err)
				}
				tmpPath := tmp.Name()
				defer func() {
					tmp.Close()
					_ = os.Remove(tmpPath)
				}()

				if _, err := tmp.Write(stContent); err != nil {
					return nil, fmt.Errorf("failed to write staging content to temp file: %v", err)
				}

				// append a separator and diff output for reference
				if len(diffOut) > 0 {
					if _, err := tmp.WriteString("\n\n--- diff (installed -> staging) ---\n"); err != nil {
						return nil, fmt.Errorf("failed to write diff header to temp file: %v", err)
					}
					if _, err := tmp.Write(diffOut); err != nil {
						return nil, fmt.Errorf("failed to write diff to temp file: %v", err)
					}
				}

				// close before launching editor
				if err := tmp.Close(); err != nil {
					return nil, fmt.Errorf("failed to close temp file before editing: %v", err)
				}

				editor := os.Getenv("EDITOR")
				if editor == "" {
					editor = "nano"
				}

				// Launch editor against the temp file as the invoking user so they can edit comfortably.
				editCmd := exec.Command(editor, tmpPath)
				editCmd.Stdin, editCmd.Stdout, editCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := editCmd.Run(); err != nil {
					return nil, fmt.Errorf("editor failed: %v", err)
				}

				// After editing, copy temp back to staging
				if os.Geteuid() == 0 {
					if err := copyFile(tmpPath, stagingFile); err != nil {
						return nil, fmt.Errorf("failed to copy edited file back to staging %s natively: %v", stagingFile, err)
					}
					// restore mode
					if err := os.Chmod(stagingFile, originalMode.Perm()); err != nil {
						return nil, fmt.Errorf("failed to restore permissions on %s natively: %v", stagingFile, err)
					}
				} else {
					cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", tmpPath, stagingFile)
					if err := execCtx.Run(cpCmd); err != nil {
						return nil, fmt.Errorf("failed to copy edited file back to staging %s: %v", stagingFile, err)
					}
					// --- NEW: Explicitly restore permissions ---
					// The `cp --preserve=mode` relies on the temp file's mode, which is wrong.
					// Use chmod to ensure the correct original mode is set.
					// We format the mode to an octal string (e.g., "0644").
					modeStr := fmt.Sprintf("%#o", originalMode.Perm())

					chmodCmd := exec.Command("chmod", modeStr, stagingFile)
					if err := execCtx.Run(chmodCmd); err != nil {
						return nil, fmt.Errorf("failed to restore permissions on %s to %s: %v", stagingFile, modeStr, err)
					}
				}
			}
		} else {
			// file does NOT exist in staging
			ans := "n" // Default to not keeping the file
			if !yes {
				printChoicePrompt(styledPrompt("File ", file, " was modified here, but the new package no longer has it. Keep it?"), "[y/N]")
				// Use the shared, robust bufio.Reader
				response, err := stdinReader.ReadString('\n')
				if err == nil {
					ans = strings.ToLower(strings.TrimSpace(response))
				}
			}
			if ans == "y" {
				if err := copyRemovedFileIntoStaging(currentFile, stagingFile, execCtx); err != nil {
					return nil, err
				}
				debugf("Kept modified file by copying %s into staging\n", file)
			} else {
				if os.Geteuid() == 0 {
					if err := os.Remove(currentFile); err != nil {
						cPrintf(colWarn, "Warning: failed to remove %s natively: %v\n", currentFile, err)
					}
				} else {
					// user chose not to keep it -> remove the installed file (run as root)
					rmCmd := exec.Command("rm", "-f", currentFile)
					if err := execCtx.Run(rmCmd); err != nil {
						// warn but continue install; do not abort the whole install for a removal failure
						fmt.Fprintf(logger, "Warning: failed to remove %s: %v\n", currentFile, err)
					} else {
						debugf("Removed user-modified file: %s\n", file)
					}
				}
			}
		}
	}

	// Note: Manifest entries for removed files will be cleaned up in checkStagingConflicts
	// after the manifest is generated, to avoid modifying the tarball's manifest

	// Generate updated manifest of staging
	debugf("Generating staging manifest\n")
	stagingManifest := stagingDir + "/var/db/hokuto/installed/" + pkgName + "/manifest"
	stagingManifest2dir := "/tmp/staging-manifest-" + pkgName
	stagingManifest2file := filepath.Join(stagingManifest2dir, "/manifest")

	// Use appropriate executor for manifest generation (reuse the same logic as modified files detection)
	var manifestExec *Executor
	if needsRootBuild {
		// Package was built as root, use root executor
		manifestExec = execCtx
	} else {
		// Package was built as user, use user executor for faster manifest generation
		manifestExec = &Executor{
			Context:         execCtx.Context,
			ShouldRunAsRoot: false,
		}
		debugf("Using optimized user executor for manifest generation (package built as user)\n")
	}

	if err := generateManifest(stagingDir, stagingManifest2dir, manifestExec); err != nil {
		if !manifestExec.ShouldRunAsRoot {
			debugf("optimized user manifest generation failed, falling back to root executor: %v\n", err)
			if err := generateManifest(stagingDir, stagingManifest2dir, RootExec); err != nil {
				return nil, fmt.Errorf("failed to generate manifest: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to generate manifest: %v", err)
		}
	}
	debugf("Generate update manifest\n")
	if err := updateManifestWithNewFiles(stagingManifest, stagingManifest2file); err != nil {
		fmt.Fprintf(os.Stderr, "Manifest update failed: %v\n", err)
	}

	// Delete stagingManifest2dir
	if err := removeAllPrivilegedFallback(stagingManifest2dir, execCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove StagingManifest: %v", err)
	}

	// 3.5. Check for conflicts with existing files (for both fresh installs and upgrades)
	// This handles cases where files exist on disk but are not tracked by any package
	// (e.g., user chose to "keep existing" during a previous install)
	debugf("Checking for conflicts with existing files\n")
	transferEquivalentWorld, transferEquivalentWorldMake, err = removeInstalledEquivalentConflicts(stagingMetadataDir, pkgName, cfg, execCtx, yes, logger)
	if err != nil {
		return nil, err
	}
	if err := checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest, execCtx, yes, fast, filesRemovedFromStaging, nil); err != nil {
		return nil, err
	}

	// 4. Determine obsolete files (compare manifests)
	debugf("Find obsolete files\n")
	filesToDelete, err := removeObsoleteFiles(pkgName, stagingDir, rootDir)
	if err != nil {
		return nil, err
	}

	// --- NEW: Dependency Check and Backup (Before deletion) ---
	debugf("Dependency check")
	affectedPackages := make(map[string][]string)
	libFilesToDelete := make(map[string]struct{})

	// Ensure the temporary directory exists.
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temporary directory %s: %v", tmpDir, err)
	}

	tempLibBackupDir, err := os.MkdirTemp(tmpDir, "hokuto-lib-backup-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary backup directory: %v", err)
	}

	// CLEANUP: Ensure the backup directory is removed on exit
	defer func() {
		if !Debug {
			if err := removeAllPrivilegedFallback(tempLibBackupDir, execCtx); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to cleanup temporary library backup: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", tempLibBackupDir)
		}
	}()

	// 4a. Check filesToDelete against all libdeps
	// Skip this check entirely if the package being installed is a -bin package.
	// These packages often bundle libraries that are removed/upgraded during an update,
	// but since they are self-contained (or should be treated as such for this purpose),
	// this shouldn't trigger rebuilds of other packages.
	// Check package options for 'binary' flag
	pkgMetaDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	pkgOpts := loadBuildOptions(pkgMetaDir)

	if pkgOpts["binary"] {
		debugf("Skipping reverse dependency check for binary package: %s\n", pkgName)
	} else {
		// Optimization: Pre-compute lookups
		filesToDeleteMap := make(map[string]struct{}, len(filesToDelete))
		for _, f := range filesToDelete {
			filesToDeleteMap[f] = struct{}{}
		}

		allInstalledEntries, err := os.ReadDir(Installed)
		if err == nil {
			for _, entry := range allInstalledEntries {
				if !entry.IsDir() || entry.Name() == pkgName {
					continue // Skip: files or package being installed
				}

				otherPkgName := entry.Name()
				libdepsPath := filepath.Join(Installed, otherPkgName, "libdeps")

				// Optimization: Try fast read first
				var libdepsContent []byte
				var err error
				if data, lerr := os.ReadFile(libdepsPath); lerr == nil {
					libdepsContent = data
				} else {
					libdepsContent, err = readFileAsRoot(libdepsPath)
					if err != nil {
						continue // Skip if libdeps file is unreadable
					}
				}

				// Check if any file in filesToDelete is a libdep of otherPkgName
				lines := strings.SplitSeq(string(libdepsContent), "\n")
				for line := range lines {
					libDep, ok := parseLibDepRef(line)
					if !ok {
						continue
					}

					var matchFile string
					if strings.HasPrefix(libDep.Name, "/") {
						// Old format: absolute path
						absLibPath := libDep.Name
						if rootDir != "/" {
							absLibPath = filepath.Join(rootDir, libDep.Name[1:])
						}
						if _, ok := filesToDeleteMap[absLibPath]; ok {
							matchFile = absLibPath
						}
					} else {
						for _, fullPath := range filesToDelete {
							if libraryPathMatchesDep(fullPath, libDep) {
								matchFile = fullPath
								break
							}
						}
					}

					if matchFile != "" {
						// Store just the basename for display
						libName := filepath.Base(matchFile)
						// Avoid duplicates
						exists := false
						for _, l := range affectedPackages[otherPkgName] {
							if l == libName {
								exists = true
								break
							}
						}
						if !exists {
							affectedPackages[otherPkgName] = append(affectedPackages[otherPkgName], libName)
						}
						libFilesToDelete[matchFile] = struct{}{}
					}
				}
			}
		}
	}
	// 4b. Backup all affected library files
	for libPath := range libFilesToDelete {
		// libPath is the HOKUTO_ROOT-prefixed path (e.g., /tmp/hokuto/usr/lib/libfoo.so)

		// Determine the relative path inside the HOKUTO_ROOT (e.g., usr/lib/libfoo.so)
		relPath, err := filepath.Rel(rootDir, libPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to determine relative path for backup %s: %v\n", libPath, err)
			continue
		}

		// Construct the full backup path (e.g., /tmp/hokuto-lib-backup-XXXX/usr/lib/libfoo.so)
		backupPath := filepath.Join(tempLibBackupDir, relPath)
		backupDir := filepath.Dir(backupPath)

		// Create the directory structure in the backup location
		if os.Geteuid() == 0 {
			if err := os.MkdirAll(backupDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create backup dir %s natively: %v", backupDir, err)
			}
			if err := copyFile(libPath, backupPath); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to backup library %s natively: %v\n", libPath, err)
			} else {
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("Backed up affected library %s to %s\n", libPath, backupPath))
			}
		} else {
			mkdirCmd := exec.Command("mkdir", "-p", backupDir)
			if err := execCtx.Run(mkdirCmd); err != nil {
				return nil, fmt.Errorf("failed to create backup dir %s: %v", backupDir, err)
			}

			// Copy the library file to the backup location
			cpCmd := exec.Command("cp", "--remove-destination", "--preserve=mode,ownership,timestamps", libPath, backupPath)
			if err := execCtx.Run(cpCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to backup library %s: %v\n", libPath, err)
			} else {
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("Backed up affected library %s to %s\n", libPath, backupPath))
			}
		}
	}

	// 5. Place staging into root, with the installed size for "hokuto list".
	recordStagedInstalledSize(stagingDir, pkgName, execCtx)
	debugf("Placing staging into root")
	if err := placeStaging(stagingDir, rootDir, execCtx); err != nil {
		return nil, fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}
	invalidatePackageEquivalentCache()
	invalidateFileOwnershipPackage(pkgName)
	if transferEquivalentWorld {
		if err := addToWorld(pkgName); err != nil {
			return nil, fmt.Errorf("failed to transfer world entry to %s: %w", pkgName, err)
		}
	}
	if transferEquivalentWorldMake {
		if err := addToWorldMake(pkgName); err != nil {
			return nil, fmt.Errorf("failed to transfer world_make entry to %s: %w", pkgName, err)
		}
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd := exec.Command("rm", "-f", p)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Fprintf(logger, "warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			debugf("Removed obsolete file: %s\n", p)
		}
	}

	// 7. Run package post-install script
	if logger == nil {
		logger = os.Stdout
	}

	postInstallDeps, err := installPostInstallDependencies(pkgName, cfg, execCtx, logger, fast, noRemote, yes)
	if err != nil {
		return nil, err
	}
	if !fast {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprintln(logger, colSuccess.Sprint("Executing package post-install script"))
	}
	if err := executePostInstall(pkgName, rootDir, execCtx, cfg, logger, fast); err != nil {
		fmt.Fprintf(logger, "warning: post-install for %s returned error: %v\n", pkgName, err)
	}
	if err := cleanupPostInstallDependencies(postInstallDeps, cfg, execCtx, logger, fast); err != nil {
		return nil, err
	}
	if err := installMissingPackageRuntimeDependencies(pkgName, cfg, logger, fast, noRemote); err != nil {
		return nil, err
	}

	// Collected rebuilds to return in managed mode
	var parallelRebuilds []string

	// 7.5. Check for rebuild triggers from /etc/hokuto/hokuto.rebuild
	rebuildTriggerPkgs := getRebuildTriggers(pkgName, rootDir)
	if len(rebuildTriggerPkgs) > 0 {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprint(logger, colSuccess.Sprint("Rebuild trigger: "))
		fmt.Fprintf(logger, "%s", colNote.Sprintf("%s\n", strings.Join(rebuildTriggerPkgs, " ")))
		if managed {
			parallelRebuilds = append(parallelRebuilds, rebuildTriggerPkgs...)
		} else {
			shouldRebuild := yes // Default to true if --yes flag is set
			if !yes {
				shouldRebuild = askForConfirmation(colWarn, "%sRebuild the packages?", colArrow.Sprint("-> "))
			}
			if shouldRebuild {
				temporaryBuildDeps, err := installRebuildDependenciesWithOptions(rebuildTriggerPkgs, cfg, noRemote, fast)
				if len(temporaryBuildDeps) > 0 {
					defer uninstallBuildDependenciesWithOptions(temporaryBuildDeps, cfg, fast)
				}
				if err != nil {
					failed = append(failed, fmt.Sprintf("failed to prepare rebuild dependencies triggered by %s: %v", pkgName, err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to prepare rebuild dependencies: %v\n", err))
					shouldRebuild = false
				}
			}

			if shouldRebuild {
				// The module rebuilds share their kernel's headers: keep them
				// installed from the first rebuild to the last.
				releaseHeaders := reserveKmodHeaders(rebuildTriggerPkgs, cfg)
				defer releaseHeaders()
				for _, rebuildPkg := range rebuildTriggerPkgs {
					debugf("\n--- Rebuilding %s (triggered by %s) ---\n", rebuildPkg, pkgName)

					// Pass empty string for oldLibsDir since this is a trigger-based rebuild, not a library dependency rebuild
					if err := pkgBuildRebuild(rebuildPkg, cfg, execCtx, "", nil); err != nil {
						failed = append(failed, fmt.Sprintf("rebuild of %s (triggered by %s) failed: %v", rebuildPkg, pkgName, err))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Rebuild of %s failed: %v\n", rebuildPkg, err))
						continue
					}

					version, revision, err := getRepoVersion2(rebuildPkg)
					if err != nil {
						failed = append(failed, fmt.Sprintf("failed to get repo version for rebuilt package %s: %v", rebuildPkg, err))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to get version for rebuilt package %s: %v\n", rebuildPkg, err))
						continue
					}
					outputRebuildPkg := getOutputPackageName(rebuildPkg, cfg)
					archiveRebuildPkg := getArchivePackageName(rebuildPkg, cfg)
					arch := GetSystemArchForPackage(cfg, rebuildPkg)
					variant := GetSystemVariantForPackage(cfg, rebuildPkg)
					tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveRebuildPkg, version, revision, arch, variant))

					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputRebuildPkg, cfg, RootExec, true, logger)
					if _, installErr := pkgInstallWithRemotePolicy(tarballPath, outputRebuildPkg, cfg, RootExec, true, fast, false, noRemote, logger); installErr != nil {
						isCriticalAtomic.Store(0)
						failed = append(failed, fmt.Sprintf("failed to install rebuilt package %s: %v", outputRebuildPkg, installErr))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to install rebuilt package %s: %v\n", outputRebuildPkg, installErr))
						continue
					}
					isCriticalAtomic.Store(0)
				}
			} else {
				colArrow.Print("-> ")
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("Skipping rebuild of %s\n", strings.Join(rebuildTriggerPkgs, ", ")))
			}
		}
	}

	// --- Rebuild Affected Packages (Step 8) ---
	// A sequential update that is about to replace an affected package
	// rechecks it once the update is done instead (see library_rebuild.go);
	// in managed mode the parallel manager makes that decision.
	if !managed {
		deferUpdateBatchRebuilds(affectedPackages)
	}
	if len(affectedPackages) > 0 {
		affectedList := make([]string, 0, len(affectedPackages))
		for pkg := range affectedPackages {
			affectedList = append(affectedList, pkg)
		}
		sort.Strings(affectedList)

		// If managed (parallel mode), we return the list of affected packages so the caller
		// can handle them (queue them for parallel execution). We do NOT prompt or rebuild here.
		if managed {
			parallelRebuilds = append(parallelRebuilds, affectedList...)
		} else if isRemoteUpdate() {
			// Print warning and skip rebuilds for remote binary update
			colArrow.Print("\n-> ")
			cPrintf(colWarn, "The following packages depend on libraries that were removed/upgraded:\n")
			for _, pkg := range affectedList {
				fmt.Println(affectedLibraryLine(pkg, affectedPackages[pkg]))
			}
			colArrow.Print("-> ")
			colSuccess.Println("Skipping library rebuild prompts for remote binary updates.")
		} else {
			// --- Sequential Handling (managed=false) ---
			// 8a. Prompt for rebuild (Hokuto is guaranteed to be run in a terminal)
			var sb strings.Builder
			sb.WriteString("\n" + colArrow.Sprint("-> ") + colWarn.Sprint("The following packages depend on libraries that were removed/upgraded:") + "\n")
			for _, pkg := range affectedList {
				sb.WriteString(affectedLibraryLine(pkg, affectedPackages[pkg]) + "\n")
			}
			// Interactive rebuild selection
			var packagesToRebuild []string
			rebuildAll := false // Flag to track if 'a' (all) was selected

			// Check if 'yes' was passed explicitly by the user (CLI flag)
			// If not (e.g. implied by parallel mode), we should still prompt for rebuilds.
			userExplicitYes := isExplicitYes()

			if !yes || (yes && !userExplicitYes) {
				// Use the same robust reader we defined earlier
				shouldQuit := false
				WithPrompt(func() {
					// Print warning inside the prompt block to ensure it's not overwritten
					fmt.Print(sb.String())

					for _, pkg := range affectedList {
						if shouldQuit {
							break
						}

						if rebuildAll {
							// 'all' was selected, just add and continue
							packagesToRebuild = append(packagesToRebuild, pkg)
							colArrow.Print("-> ")
							fmt.Println(styledPrompt("Rebuilding ", pkg, " (all selected)"))
							// continue // continue doesn't render well here since we are inside closure inside loop?
							// actually we are inside closure.
							// Wait, if we wrap the WHOLE loop in WithPrompt, then we can use continue naturally?
							// No, WithPrompt accepts a func().
							continue
						}

						// Prompt for this specific package
						printChoicePrompt(styledPrompt("Rebuild ", pkg, "?"), "[Y/n/a(ll)/q(uit)]")
						os.Stdout.Sync()
						response, err := stdinReader.ReadString('\n')
						if err != nil {
							response = "q" // Treat error (like Ctrl+D) as 'quit'
						}
						response = strings.ToLower(strings.TrimSpace(response))

						switch response {
						case "y", "": // Default is Yes
							packagesToRebuild = append(packagesToRebuild, pkg)
						case "n": // No
							colArrow.Print("-> ")
							fmt.Println(styledPrompt("Skipping rebuild for ", pkg))
						case "a": // All
							colArrow.Print("-> ")
							fmt.Println(styledPrompt("Rebuilding ", pkg, " and all subsequent packages"))
							rebuildAll = true
							packagesToRebuild = append(packagesToRebuild, pkg)
						case "q": // Quit
							colArrow.Print("-> ")
							colSuccess.Println("Quitting rebuild selection. No more packages will be rebuilt.")
							shouldQuit = true // Signal to break loop
						default: // Invalid, treat as 'No' for safety
							colArrow.Print("-> ")
							fmt.Println(styledPrompt("Invalid input. Skipping rebuild for ", pkg))
						}
					}
				})
			} else {
				// If --yes is passed explicitly, just rebuild all affected packages
				fmt.Fprintf(logger, "%s", colInfo.Sprint("Rebuilding all affected packages due to --yes flag.\n"))
				packagesToRebuild = affectedList
			}

			if len(packagesToRebuild) > 0 {
				temporaryBuildDeps, err := installRebuildDependenciesWithOptions(packagesToRebuild, cfg, noRemote, fast)
				if len(temporaryBuildDeps) > 0 {
					defer uninstallBuildDependenciesWithOptions(temporaryBuildDeps, cfg, fast)
				}
				if err != nil {
					failed = append(failed, fmt.Sprintf("failed to prepare library rebuild dependencies: %v", err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to prepare rebuild dependencies: %v\n", err))
					packagesToRebuild = nil
				}
			}

			// 8b. Perform rebuild
			if len(packagesToRebuild) > 0 {
				colArrow.Print("-> ")
				colSuccess.Println("Starting rebuild of affected packages")

				// Check if we should silence output (parallel mode without explicit user interaction for this step)
				// In parallel mode, 'yes' is true, but we might want to hide the verbose rebuild logs
				// because they interfere with the parallel status line.
				var rebuildLogger io.Writer
				rebuildLogger = logger
				if yes && !isExplicitYes() {
					// Implicit yes (parallel mode) -> silence output
					rebuildLogger = io.Discard
				}

				for _, pkg := range packagesToRebuild {
					if rebuildLogger != io.Discard {
						fmt.Fprintf(logger, "%s", colInfo.Sprintf("\n--- Rebuilding %s ---\n", pkg))
					} else {
						// In silent mode, just print a one-line status to the main log/stdout if needed,
						// or rely on the final success message.
						// Actually, with io.Discard, we print NOTHING from the build process.
					}

					if err := pkgBuildRebuild(pkg, cfg, execCtx, tempLibBackupDir, rebuildLogger); err != nil {
						failed = append(failed, fmt.Sprintf("rebuild of %s failed: %v", pkg, err))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Rebuild of %s failed: %v\n", pkg, err))
						continue // Skip to next package on failure, same as hokuto update
					}

					version, revision, err := getRepoVersion2(pkg)
					if err != nil {
						failed = append(failed, fmt.Sprintf("failed to get repo version for rebuilt package %s: %v", pkg, err))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to get version for rebuilt package %s: %v\n", pkg, err))
						continue
					}
					outputRebuildPkg := getOutputPackageName(pkg, cfg)
					archiveRebuildPkg := getArchivePackageName(pkg, cfg)
					arch := GetSystemArchForPackage(cfg, pkg)
					variant := GetSystemVariantForPackage(cfg, pkg)
					tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archiveRebuildPkg, version, revision, arch, variant))

					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputRebuildPkg, cfg, RootExec, true, rebuildLogger)
					if _, installErr := pkgInstallWithRemotePolicy(tarballPath, outputRebuildPkg, cfg, RootExec, true, fast, false, noRemote, rebuildLogger); installErr != nil {
						isCriticalAtomic.Store(0)
						failed = append(failed, fmt.Sprintf("failed to install rebuilt package %s: %v", outputRebuildPkg, installErr))
						fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to install rebuilt package %s: %v\n", outputRebuildPkg, installErr))
						continue
					}
					isCriticalAtomic.Store(0)
				}
			}
		}
	}

	// 9. Cleanup
	if err := removeAllPrivilegedFallback(pkgTmpDir, execCtx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to cleanup: %v\n", err)
	}

	// 10. Report failures if any
	if len(failed) > 0 { // 'failed' slice is correctly declared at the start of pkgInstall
		return nil, fmt.Errorf("some file actions failed:\n%s", strings.Join(failed, "\n"))
	}

	// 11. Run global post-install tasks
	if !fast {
		if err := PostInstallTasks(RootExec, logger); err != nil {
			fmt.Fprintf(os.Stderr, "post-install tasks completed with warnings: %v\n", err)
		}
	}
	registerInstalledPackageInfo(rootDir, pkgName, cfg)
	collectPackageSuggestions(pkgName, rootDir)
	return parallelRebuilds, nil
}

// checkStagingConflicts checks for conflicts between files in staging and existing files in the target.
// This handles fresh installs where the package is not installed but files may already exist.
// filesHandledInConflict is optional and only used for tracking (can be nil for fresh installs).
func checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest string, execCtx *Executor, yes, fast bool, filesRemovedFromStaging map[string]bool, filesHandledInConflict map[string]bool) error {
	// Read the staging manifest
	stagingData, err := os.ReadFile(stagingManifest)
	if err != nil {
		// No staging manifest (shouldn't happen, but handle gracefully)
		return nil
	}

	// Use the shared ownership snapshot instead of rebuilding an owner map for
	// every package install. The snapshot refreshes only manifests that changed.
	ownershipSnapshot := getFileOwnershipSnapshot(rootDir)
	// Also build a set of files owned by the current package (for upgrade scenarios)
	currentPkgFiles := make(map[string]bool)
	// Parent-directory symlinks don't change during this pass, so resolve
	// each directory once instead of once per manifest line.
	dirCache := make(map[string]string)

	// First, check if current package is installed and build its file set
	installedManifestPath := filepath.Join(Installed, pkgName, "manifest")
	if data, err := os.ReadFile(installedManifestPath); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			entry, ok, parseErr := parseManifestLine(scanner.Text())
			if parseErr != nil || !ok || strings.HasSuffix(entry.Path, "/") {
				continue
			}
			manifestFilePath := entry.Path
			cleanPath := canonicalizePathCached(rootDir, manifestFilePath, dirCache)
			cleanPathNoSlash := strings.TrimPrefix(cleanPath, "/")
			currentPkgFiles[cleanPath] = true
			currentPkgFiles[cleanPathNoSlash] = true
		}
	}

	stdinReader := bufio.NewReader(os.Stdin)
	skipAllPrompts := yes
	useOriginalForAll := false // Flag to use original for all remaining alternatives (unmanaged)
	useNewForAll := false      // Flag to use new for all remaining alternatives (unmanaged)
	// If auto-confirming or fast mode, set flags to default to "new"
	if yes || fast {
		useNewForAll = true
	}
	keepAllConflicts := false   // Flag to keep all conflicting files items (package conflicts)
	useNewAllConflicts := false // Flag to use new file for all conflicting items (package conflicts)
	if fast {
		useNewAllConflicts = true
	}

	// Data structure to collect conflicts grouped by conflicting package
	type conflictInfo struct {
		filePath    string
		stagingFile string
		conflictPkg string
	}
	conflictsByPkg := make(map[string][]conflictInfo)
	unmanagedConflicts := []conflictInfo{}
	var siblingConflicts []conflictInfo

	// First pass: collect all conflicts
	scanner := bufio.NewScanner(strings.NewReader(string(stagingData)))
	for scanner.Scan() {
		entry, ok, parseErr := parseManifestLine(scanner.Text())
		if parseErr != nil {
			return fmt.Errorf("invalid staging manifest: %w", parseErr)
		}
		if !ok || strings.HasSuffix(entry.Path, "/") {
			continue // Skip directories
		}

		filePath := entry.Path // Path from manifest (may have leading slash)
		// Normalize path: remove leading slash for comparison
		filePathClean := canonicalizePathCached(rootDir, filePath, dirCache)
		filePathCleanNoSlash := strings.TrimPrefix(filePathClean, "/")

		// Ignore internal metadata files
		if strings.Contains(filePathClean, "var/db/hokuto") {
			continue
		}

		stagingFile := filepath.Join(stagingDir, strings.TrimPrefix(filePath, "/"))
		targetFile := filepath.Join(rootDir, strings.TrimPrefix(filePath, "/"))

		// Check if file exists in target location
		if _, err := os.Lstat(targetFile); os.IsNotExist(err) {
			continue // File doesn't exist, no conflict
		}

		// File exists in target - check for conflicts using cached owner map
		// First check if file is owned by current package (normal upgrade scenario)
		if currentPkgFiles[filePathClean] || currentPkgFiles[filePathCleanNoSlash] || currentPkgFiles[filePath] {
			// File is in current package's manifest - this is a normal upgrade, skip conflict check
			continue
		}

		ownerPkg := ownershipSnapshot.ownerOtherThan(filePathClean, pkgName)
		if ownerPkg == "" {
			ownerPkg = ownershipSnapshot.ownerOtherThan(filePathCleanNoSlash, pkgName)
		}

		if ownerPkg != "" && kmodSiblings(ownerPkg, pkgName) {
			// The same kernel module package for another kernel ships the
			// same config file (/etc/modprobe.d/...). Share it silently.
			siblingConflicts = append(siblingConflicts, conflictInfo{
				filePath:    filePath,
				stagingFile: stagingFile,
				conflictPkg: ownerPkg,
			})
		} else if ownerPkg != "" && ownerPkg != pkgName {
			// File is owned by another package - this is a conflict
			conflictsByPkg[ownerPkg] = append(conflictsByPkg[ownerPkg], conflictInfo{
				filePath:    filePath,
				stagingFile: stagingFile,
				conflictPkg: ownerPkg,
			})
		} else if ownerPkg == "" {
			// File exists but is not owned by any package
			unmanagedConflicts = append(unmanagedConflicts, conflictInfo{
				filePath:    filePath,
				stagingFile: stagingFile,
				conflictPkg: "",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading staging manifest: %v", err)
	}

	// All registrations go into one batch so the alternatives DB is loaded,
	// updated and saved once per install rather than once per conflicting
	// package.
	var batchRequests []AlternativeRequest
	var stagingFilesToRemove []string

	// Files shared with a sibling kernel module instance: the new file is
	// used and both instances own it, so uninstalling one keeps it.
	for _, c := range siblingConflicts {
		batchRequests = append(batchRequests, AlternativeRequest{
			FilePath:     c.filePath,
			IncomingPkg:  pkgName,
			CurrentPkg:   c.conflictPkg,
			IncomingFile: c.stagingFile,
		})
		if filesHandledInConflict != nil {
			filesHandledInConflict[c.filePath] = true
		}
	}

	// Second pass: prompt once per conflicting package, in a stable order
	conflictPkgs := make([]string, 0, len(conflictsByPkg))
	for conflictPkg := range conflictsByPkg {
		conflictPkgs = append(conflictPkgs, conflictPkg)
	}
	sort.Strings(conflictPkgs)
	for _, conflictPkg := range conflictPkgs {
		conflicts := conflictsByPkg[conflictPkg]
		var input string
		// Check batch flags first - if already set, skip prompt
		if keepAllConflicts {
			input = "k"
		} else if useNewAllConflicts {
			input = "n"
		} else if !skipAllPrompts && !fast {
			// Display all conflicting files
			colArrow.Print("-> ")
			fmt.Println(styledPrompt("Files ", pkgName, " installs that ", conflictPkg, " already has:"))
			for _, c := range conflicts {
				fmt.Println("   " + colNote.Sprint(c.filePath))
			}
			printKeyChoicePrompt(styledPrompt("Use the files of ", pkgName, " or keep those of ", conflictPkg, "?"), "[N]ew, keep [o]riginal")
			os.Stdout.Sync()
			response, err := stdinReader.ReadString('\n')
			if err != nil {
				response = "n" // Default to new on read error
			}
			input = strings.ToLower(strings.TrimSpace(response))
			if input == "" {
				input = "n" // Default to new
			}
			// Set batch flag for remaining conflicts
			switch input {
			case "k", "o":
				keepAllConflicts = true
			case "n":
				useNewAllConflicts = true
			default:
				// Invalid input, default to new
				useNewAllConflicts = true
				input = "n"
			}
		} else {
			input = "n" // Default to new in --yes mode
			useNewAllConflicts = true
		}

		// Apply choice to all files in this conflict group
		for _, c := range conflicts {
			switch input {
			case "k", "o":
				// Keep Original (existing file). Stash the new (incoming) file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   c.conflictPkg,
					IncomingFile: c.stagingFile,
					KeepOriginal: true,
				}
				batchRequests = append(batchRequests, req)
				stagingFilesToRemove = append(stagingFilesToRemove, c.stagingFile)
				// Do NOT add to manifestEntriesToRemove. We want the package to "own" the file
				// even if we are using the existing one on disk. This ensures uninstall works.

				debugf("Kept file from %s package, queueing new file (from %s) as alternative: %s\n", c.conflictPkg, pkgName, c.filePath)

			case "n":
				// Use New (incoming file). Stash the original (existing) file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   c.conflictPkg,
					IncomingFile: c.stagingFile,
					KeepOriginal: false,
				}
				batchRequests = append(batchRequests, req)

				if filesHandledInConflict != nil {
					filesHandledInConflict[c.filePath] = true
				}
				debugf("Using new file from %s, queueing existing file (from %s) as alternative: %s\n", pkgName, c.conflictPkg, c.filePath)
			}
		}

	}

	// Handle unmanaged file conflicts
	if len(unmanagedConflicts) > 0 {
		var input string
		if useOriginalForAll {
			input = "k"
		} else if useNewForAll {
			input = "n"
		} else if !skipAllPrompts && !fast {
			colArrow.Print("-> ")
			fmt.Println(styledPrompt("Files ", pkgName, " installs that exist already but belong to no package:"))
			for _, c := range unmanagedConflicts {
				fmt.Println("   " + colNote.Sprint(c.filePath))
			}
			printKeyChoicePrompt(styledPrompt("Use the files of ", pkgName, " or keep the existing ones?"), "[N]ew, [k]eep original")
			os.Stdout.Sync()
			response, err := stdinReader.ReadString('\n')
			if err != nil {
				response = "n"
			}
			input = strings.ToLower(strings.TrimSpace(response))
			if input == "" {
				input = "n"
			}
			switch input {
			case "k", "o":
				useOriginalForAll = true
			case "n":
				useNewForAll = true
			default:
				useNewForAll = true
				input = "n"
			}
		} else {
			input = "n"
			useNewForAll = true
		}

		for _, c := range unmanagedConflicts {
			switch input {
			case "k", "o":
				// Keep Original (unmanaged). Stash new file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   "",
					IncomingFile: c.stagingFile,
					KeepOriginal: true,
				}
				batchRequests = append(batchRequests, req)
				stagingFilesToRemove = append(stagingFilesToRemove, c.stagingFile)
				debugf("Kept existing unmanaged file, queueing new file as alternative: %s\n", c.filePath)

			case "n":
				// Use New. Stash original (unmanaged).
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   "",
					IncomingFile: c.stagingFile,
					KeepOriginal: false,
				}
				batchRequests = append(batchRequests, req)
				debugf("Using new file, queueing existing file as alternative: %s\n", c.filePath)
			}
		}
	}

	if len(batchRequests) > 0 {
		debugf("Processing %d alternative registrations concurrently...\n", len(batchRequests))
		if err := BatchRegisterAlternatives(rootDir, batchRequests, execCtx); err != nil {
			return fmt.Errorf("failed to register package alternatives: %w", err)
		}
	}

	// "Keep original": the incoming file is now stashed, so drop it from the
	// staging tree. Its manifest entry stays so the package still owns the
	// path for uninstall.
	for start := 0; start < len(stagingFilesToRemove); start += 500 {
		end := min(start+500, len(stagingFilesToRemove))
		args := append([]string{"-f", "--"}, stagingFilesToRemove[start:end]...)
		if err := execCtx.Run(exec.Command("rm", args...)); err != nil {
			return fmt.Errorf("failed to remove kept-original files from staging: %v", err)
		}
	}

	if len(filesRemovedFromStaging) > 0 {
		if err := removeManifestEntries(stagingManifest, filesRemovedFromStaging, execCtx); err != nil {
			// Non-fatal, but log the error
			debugf("Warning: failed to remove entries from staging manifest: %v\n", err)
		}
	}

	return nil
}

// isExplicitYes checks if the user passed -y/--yes/--force-yes on the command line
func isExplicitYes() bool {
	for _, arg := range os.Args {
		if arg == "-y" || arg == "--yes" || arg == "-yes" || arg == "--force-yes" {
			return true
		}
	}
	return false
}

// isRemoteUpdate checks if the user is running a remote update (hokuto update --remote)
func isRemoteUpdate() bool {
	hasUpdate := false
	hasRemote := false
	for _, arg := range os.Args {
		if arg == "update" || arg == "u" {
			hasUpdate = true
		}
		if arg == "--remote" || arg == "-remote" {
			hasRemote = true
		}
	}
	return hasUpdate && hasRemote
}

// formatBackupFileName formats a relative file path (e.g. "etc/hokuto/hokuto.conf")
// into a backup file name (e.g. "etc_hokuto-hokuto.conf").
func formatBackupFileName(relPath string) string {
	clean := filepath.Clean(filepath.ToSlash(relPath))
	clean = strings.TrimPrefix(clean, "/")
	dir := filepath.Dir(clean)
	base := filepath.Base(clean)
	if dir == "." || dir == "" {
		return base
	}
	dirPart := strings.ReplaceAll(dir, "/", "_")
	return dirPart + "-" + base
}

// keepCurrentFileInStaging replaces the package's version of a modified file
// in staging with the installed one, so the install leaves it as it is.
func keepCurrentFileInStaging(currentFile, stagingFile string, execCtx *Executor) error {
	currentInfo, err := os.Lstat(currentFile)
	if err == nil && currentInfo.Mode()&os.ModeSymlink != 0 {
		// A symlink: recreate it in staging with the same target.
		linkTarget, err := os.Readlink(currentFile)
		if err != nil {
			return fmt.Errorf("failed to read symlink %s: %v", currentFile, err)
		}
		if os.Geteuid() == 0 {
			os.Remove(stagingFile)
			if err := os.Symlink(linkTarget, stagingFile); err != nil {
				return fmt.Errorf("failed to recreate symlink %s -> %s natively: %v", stagingFile, linkTarget, err)
			}
			return nil
		}
		rmCmd := exec.Command("rm", "-f", stagingFile)
		if err := execCtx.Run(rmCmd); err != nil {
			return fmt.Errorf("failed to remove existing file %s: %v", stagingFile, err)
		}
		lnCmd := exec.Command("ln", "-s", linkTarget, stagingFile)
		if err := execCtx.Run(lnCmd); err != nil {
			return fmt.Errorf("failed to recreate symlink %s -> %s: %v", stagingFile, linkTarget, err)
		}
		return nil
	}
	if os.Geteuid() == 0 {
		if err := copyFile(currentFile, stagingFile); err != nil {
			return fmt.Errorf("failed to overwrite %s natively: %v", stagingFile, err)
		}
		return nil
	}
	cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
	if err := execCtx.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
	}
	return nil
}

// moveRemovedFileToBackup moves a modified file that the new package no
// longer contains into SaveDir and returns where it went.
func moveRemovedFileToBackup(currentFile, relPath string, execCtx *Executor) (string, error) {
	if err := backupModifiedFile(currentFile, relPath, execCtx, nil); err != nil {
		return "", fmt.Errorf("failed to back up modified file %s: %w", currentFile, err)
	}
	if os.Geteuid() == 0 {
		if err := os.Remove(currentFile); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to remove %s natively: %w", currentFile, err)
		}
	} else if err := execCtx.Run(exec.Command("rm", "-f", currentFile)); err != nil {
		return "", fmt.Errorf("failed to remove %s: %w", currentFile, err)
	}
	return filepath.Join(SaveDir, formatBackupFileName(relPath)), nil
}

// copyRemovedFileIntoStaging puts a modified file the new package no longer
// contains into staging, so it is kept instead of removed.
func copyRemovedFileIntoStaging(currentFile, stagingFile string, execCtx *Executor) error {
	stagingFileDir := filepath.Dir(stagingFile)
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(stagingFileDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s natively: %v", stagingFileDir, err)
		}
		if err := copyFile(currentFile, stagingFile); err != nil {
			return fmt.Errorf("failed to copy %s to staging natively: %v", currentFile, err)
		}
		return nil
	}
	mkdirCmd := exec.Command("mkdir", "-p", stagingFileDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", stagingFileDir, err)
	}
	cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", currentFile, stagingFile)
	if err := execCtx.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy %s to staging: %v", currentFile, err)
	}
	return nil
}

// backupModifiedFile saves a backup copy of currentFile to SaveDir (e.g. /var/db/hokuto/save)
// using the format dir_path-filename.
func backupModifiedFile(currentFile, relPath string, execCtx *Executor, logger io.Writer) error {
	backupName := formatBackupFileName(relPath)
	backupPath := filepath.Join(SaveDir, backupName)
	backupDir := filepath.Dir(backupPath)

	if os.Geteuid() == 0 {
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			return fmt.Errorf("failed to create backup dir %s natively: %w", backupDir, err)
		}
		if err := copyFile(currentFile, backupPath); err != nil {
			return fmt.Errorf("failed to backup file %s to %s natively: %w", currentFile, backupPath, err)
		}
	} else {
		mkdirCmd := exec.Command("mkdir", "-p", backupDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create backup dir %s: %w", backupDir, err)
		}
		cpCmd := exec.Command("cp", "--remove-destination", "--preserve=mode,ownership,timestamps", currentFile, backupPath)
		if err := execCtx.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to backup file %s to %s: %w", currentFile, backupPath, err)
		}
	}

	if logger != nil {
		fmt.Fprintf(logger, "%s%s\n", colArrow.Sprint("-> "), colNote.Sprintf("Saved backup of %s to %s", currentFile, backupPath))
	}
	return nil
}

// rootOnlyReadable reports whether path exists and others may not read it,
// like /etc/shadow (0600 or 0000).
// Stat needs no read permission on the file itself.
func rootOnlyReadable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0o004 == 0
}

// styledPrompt is the text of a question in the standard colors: the parts
// alternate between text (blue) and names or paths (green).
func styledPrompt(parts ...string) string {
	var b strings.Builder
	for i, part := range parts {
		if i%2 == 0 {
			b.WriteString(colSuccess.Sprint(part))
		} else {
			b.WriteString(colNote.Sprint(part))
		}
	}
	return b.String()
}

// printKeyChoicePrompt is printChoicePrompt for choices spelled out as
// words ("[K]eep current, [u]se new"): the key of each, with its brackets,
// in the arrow's yellow, the words in the default color.
func printKeyChoicePrompt(question, choices string) {
	printQuestion(question, choiceKeyPattern.ReplaceAllStringFunc(choices, func(key string) string {
		return colArrow.Sprint(key)
	}))
}

// choiceKeyPattern matches the key of a choice: [K], [u], [A].
var choiceKeyPattern = regexp.MustCompile(`\[[A-Za-z]\]`)

// printChoicePrompt prints a question and its choices ([y/N],
// [Y/n/a(ll)/q(uit)]), the choices in the arrow's yellow, as the [Y/n]
// prompts do.
func printChoicePrompt(question, choices string) {
	printQuestion(question, colArrow.Sprint(choices))
}

func printQuestion(question, coloredChoices string) {
	colArrow.Print("-> ")
	fmt.Print(question)
	fmt.Printf(" %s: ", coloredChoices)
}

// affectedLibraryLine is one entry of the library rebuild list: the package
// and the libraries it needs that were removed or upgraded.
func affectedLibraryLine(pkg string, libs []string) string {
	return "   " + styledPrompt("", pkg, " (needs: ", strings.Join(libs, ", "), ")")
}

// renameManifestMetadataPaths rewrites the metadata entries of a staged
// manifest (/var/db/hokuto/installed/atkmm/...) for the parallel name the
// package is installed under (atkmm-2.28). They used to keep the archive's
// name, so the installed atkmm-2.28 claimed the metadata of the current
// atkmm, and removing it deleted that.
func renameManifestMetadataPaths(manifestPath, from, to string, execCtx *Executor) error {
	data, err := readFileAsRoot(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	oldPrefix := "/var/db/hokuto/installed/" + from + "/"
	newPrefix := "/var/db/hokuto/installed/" + to + "/"
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, line := range lines {
		if strings.HasPrefix(line, oldPrefix) {
			lines[i] = newPrefix + strings.TrimPrefix(line, oldPrefix)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return writeFileAsRoot(manifestPath, []byte(strings.Join(lines, "\n")), 0o644, execCtx)
}

// unpackPackageToStaging unpacks a package archive into stagingDir, where it
// is verified before anything reaches the root.
func unpackPackageToStaging(tarballPath, stagingDir string, execCtx *Executor) error {
	tarSuccess := false
	if _, err := exec.LookPath("tar"); err == nil {
		// A package packed into several zstd frames can be decoded on all cores
		// at once. Archives with a single frame -- everything packed by an older
		// hokuto, and every package small enough to fit in one chunk -- fall
		// through to the ordinary path.
		if err := unpackMultiFrame(tarballPath, stagingDir, execCtx); err == nil {
			tarSuccess = true
		} else if !errors.Is(err, errSingleFrameArchive) {
			debugf("Parallel unpack of %s failed, falling back to tar --zstd: %v\n", tarballPath, err)
		}

		if !tarSuccess {
			untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
			if !Debug {
				untarCmd.Stdout = io.Discard
				untarCmd.Stderr = io.Discard
			}
			if err := execCtx.Run(untarCmd); err == nil {
				tarSuccess = true
			} else {
				debugf("System tar failed for %s, falling back to internal tar+zstd: %v\n", tarballPath, err)
			}
		}
	}

	if !tarSuccess {
		// The internal unpacker runs in this process: only as root does it
		// give the files their owners. Run as a normal user (installing
		// through sudo or run0) it would stage, and so install, every file
		// owned by that user.
		if os.Geteuid() != 0 {
			return fmt.Errorf("cannot unpack %s: installing as a normal user needs a working tar with zstd (tar --zstd); install tar and zstd, or run hokuto as root", filepath.Base(tarballPath))
		}
		if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
			return fmt.Errorf("failed to unpack tarball (native): %v", err)
		}
	}

	return nil
}

// stagedPackageVersion is the version (without revision) of the package
// staged in stagingDir, read from its version file.
func stagedPackageVersion(stagingDir, pkgName string) (string, error) {
	data, err := readFileAsRoot(filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName, "version"))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("empty version file for %s", pkgName)
	}
	return fields[0], nil
}

// installedOnlyForPostInstall reports whether pkg is installed only because
// installed packages need it to run their post-install hooks ("dracut
// post-install" in a kernel's depends): nothing requested it (world,
// world_make) and no installed package depends on it otherwise.
func installedOnlyForPostInstall(pkg string) bool {
	for _, file := range []string{WorldFile, WorldMakeFile} {
		if fileHasLine(file, pkg) {
			return false
		}
	}
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return false
	}
	postInstallOnly := false
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == pkg {
			continue
		}
		data, err := os.ReadFile(filepath.Join(Installed, entry.Name(), "depends"))
		if err != nil {
			continue
		}
		deps, err := parseDependsData(data)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep.Suggest || (dep.Name != pkg && !slices.Contains(dep.Alternatives, pkg)) {
				continue
			}
			if !dep.PostInstall {
				return false
			}
			postInstallOnly = true
		}
	}
	return postInstallOnly
}

// fileHasLine reports whether path has a line that is exactly line, ignoring
// surrounding whitespace.
func fileHasLine(path, line string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}
