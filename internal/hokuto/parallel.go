package hokuto

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ParallelManager handles the execution of parallel builds
type ParallelManager struct {
	MaxJobs       int
	Config        *Config
	BuildPlan     *BuildPlan
	Context       context.Context
	Cancel        context.CancelFunc
	AutoYes       bool
	AutoInstall   bool
	UserRequested map[string]bool

	// State
	mu                sync.Mutex
	Pending           []string
	pendingRebuilds   []string
	Running           map[string]time.Time // Package name -> Start time
	Completed         map[string]bool      // Package name -> true
	Available         map[string]bool      // Installed/provided package names, including split outputs
	Failed            map[string]error
	DeferredInstalls  map[string]bool
	TemporaryInstalls map[string]bool
	LogFiles          map[string]*os.File
	SplitDepsBySource map[string][]string

	// Dep injection for testing
	Builder   func(string, *Config, *Executor, BuildOptions) (time.Duration, error)
	Installer func(string, io.Writer) (parallelInstallResult, error)

	// Channels
	resultChan  chan buildResult
	promptPause chan bool
	promptAck   chan struct{}
}

type buildResult struct {
	pkgName  string
	err      error
	duration time.Duration
	skipped  bool
}

type binaryPlanDependency struct {
	Name string
	Make bool
}

type parallelInstallResult struct {
	Rebuilds  []string
	Available []string
}

func snapshotInstalledPackageNames() map[string]bool {
	snapshot := make(map[string]bool)
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return snapshot
	}
	for _, entry := range entries {
		if entry.IsDir() {
			snapshot[entry.Name()] = true
		}
	}
	return snapshot
}

// RunParallelBuilds executes the build plan in parallel
func RunParallelBuilds(plan *BuildPlan, cfg *Config, maxJobs int, userRequestedMap map[string]bool, autoYes bool, autoInstall bool, splitDepsBySource map[string][]string, customBuilder func(string, *Config, *Executor, BuildOptions) (time.Duration, error)) ([]string, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := &ParallelManager{
		MaxJobs:           maxJobs,
		Config:            cfg,
		BuildPlan:         plan,
		Context:           ctx,
		Cancel:            cancel,
		Pending:           make([]string, len(plan.Order)),
		Running:           make(map[string]time.Time),
		Completed:         make(map[string]bool),
		Available:         make(map[string]bool),
		Failed:            make(map[string]error),
		DeferredInstalls:  make(map[string]bool),
		TemporaryInstalls: make(map[string]bool),
		LogFiles:          make(map[string]*os.File),
		SplitDepsBySource: splitDepsBySource,
		UserRequested:     userRequestedMap,
		resultChan:        make(chan buildResult, maxJobs),
		promptPause:       make(chan bool),
		promptAck:         make(chan struct{}),
		Builder:           pkgBuild,
		AutoYes:           autoYes,
		AutoInstall:       autoInstall,
	}

	if customBuilder != nil {
		pm.Builder = customBuilder
	}

	pm.Installer = func(pkg string, logger io.Writer) (parallelInstallResult, error) {
		return pm.installPackage(pkg, userRequestedMap, logger)
	}
	copy(pm.Pending, plan.Order)

	// Set prompt hooks to pause UI
	SetPromptHooks(func() {
		// fmt.Fprintln(os.Stderr, "DEBUG: Sending promptPause=true")
		pm.promptPause <- true
		// fmt.Fprintln(os.Stderr, "DEBUG: Waiting for promptAck")
		<-pm.promptAck // Wait for UI to acknowledge pause and clear line
		// fmt.Fprintln(os.Stderr, "DEBUG: Got promptAck")
	}, func() {
		// fmt.Fprintln(os.Stderr, "DEBUG: Sending promptPause=false")
		pm.promptPause <- false
		// fmt.Fprintln(os.Stderr, "DEBUG: Waiting for promptAck (Resume)")
		<-pm.promptAck // Wait for UI to acknowledge resume
		// fmt.Fprintln(os.Stderr, "DEBUG: Got promptAck (Resume)")
	})
	// Reset hooks on exit
	defer SetPromptHooks(nil, nil)

	// Start UI Loop
	uiDone := make(chan struct{})
	go pm.uiLoop(uiDone)

	// Disable interactive mode for executors in parallel mode
	oldUserInt := UserExec.Interactive
	oldRootInt := RootExec.Interactive
	UserExec.Interactive = false
	RootExec.Interactive = false
	defer func() {
		UserExec.Interactive = oldUserInt
		RootExec.Interactive = oldRootInt
	}()

	// Execute
	err := pm.Run()

	// Stop UI
	close(uiDone)
	// Clear the final status line
	fmt.Print("\r\033[K")
	SetPromptHooks(nil, nil)

	// Check for failures OR blocked packages (left in pending)
	if len(pm.Failed) > 0 || len(pm.Pending) > 0 {
		colArrow.Print("-> ")
		colError.Println("Failed or Blocked Packages:")

		// 1. Failures
		for pkg, err2 := range pm.Failed {
			fmt.Printf("  - %-20s: %v\n", pkg, err2)
		}

		// 2. Blocked
		for _, pkg := range pm.Pending {
			// Determine reason
			reason := "build cancelled"
			pkgDir, err := findPackageDir(pkg)
			if err == nil {
				if deps, err := parseDependsFile(pkgDir); err == nil {
					for _, dep := range deps {
						if !activeBuildDependency(dep, pm.Config, false) {
							continue
						}

						// Check status for the selected alternative, when this dep has alternatives.
						candidates, err := resolvedBuildDependencyCandidates(dep, false, pm.Config)
						if err != nil {
							reason = fmt.Sprintf("dependency not satisfied: %s", dep.Name)
							break
						}

						satisfied := false
						failedDep := ""
						for _, cand := range candidates {
							if shouldSkipMultilibMakeDep(dep, cand, pm.Config) {
								continue
							}
							if _, f := pm.Failed[cand]; f {
								failedDep = cand
							}
							if pm.Available[cand] || pm.Completed[cand] || isPackageInstalled(cand) {
								satisfied = true
								break
							}
						}

						if !satisfied {
							if failedDep != "" {
								reason = fmt.Sprintf("dependency failed: %s", failedDep)
							} else {
								reason = fmt.Sprintf("dependency not satisfied: %s", dep.Name)
							}
							break
						}
					}
				}
			}
			fmt.Printf("  - %-20s: %s\n", pkg, reason)
		}

		if err == nil {
			err = fmt.Errorf("parallel build incomplete: %d failed, %d blocked", len(pm.Failed), len(pm.Pending))
		}
		return nil, err
	}

	// colSuccess.Printf("All packages built successfully in %s\n", time.Since(time.Now()).Round(time.Second))

	// Show success summary
	var builtPkgs []string
	for pkg, done := range pm.Completed {
		if done {
			builtPkgs = append(builtPkgs, pkg)
		}
	}
	sort.Strings(builtPkgs)

	if len(builtPkgs) > 0 {
		colArrow.Print("-> ")
		if len(pm.DeferredInstalls) > 0 {
			colSuccess.Println("Built Packages:")
		} else {
			colSuccess.Println("Built/Installed Packages:")
		}
		for _, pkg := range builtPkgs {
			fmt.Printf("  - %s\n", colNote.Sprint(pkg))
		}
	}

	if err := pm.installDeferredTargets(); err != nil {
		return nil, err
	}

	temporaryInstalls := make([]string, 0, len(pm.TemporaryInstalls))
	for pkgName := range pm.TemporaryInstalls {
		temporaryInstalls = append(temporaryInstalls, pkgName)
	}
	sort.Strings(temporaryInstalls)
	return temporaryInstalls, nil
}

func (pm *ParallelManager) installDeferredTargets() error {
	if len(pm.DeferredInstalls) == 0 {
		return nil
	}
	if pm.BuildPlan.NoInstall {
		return nil
	}

	targets := make([]string, 0, len(pm.DeferredInstalls))
	for pkg := range pm.DeferredInstalls {
		targets = append(targets, pkg)
	}
	sort.Strings(targets)

	isCrossWithoutSystem := pm.Config.Values["HOKUTO_CROSS_ARCH"] != "" && pm.Config.Values["HOKUTO_CROSS_SYSTEM"] != "1"
	if isCrossWithoutSystem {
		return nil
	}

	shouldInstall := pm.AutoInstall
	if !shouldInstall {
		outputPkgNames := make([]string, len(targets))
		for i, pkg := range targets {
			outputPkgNames[i] = getOutputPackageName(pkg, pm.Config)
		}
		pkgNoun := "package"
		if len(outputPkgNames) > 1 {
			pkgNoun = "packages"
		}
		shouldInstall = askForConfirmation(colWarn, "-> Install built %s: %s", pkgNoun, colNote.Sprint(strings.Join(outputPkgNames, ", ")))
	}
	if !shouldInstall {
		return nil
	}

	for i, pkgName := range targets {
		version, revision, err := getRepoVersion2(pkgName)
		if err != nil {
			return fmt.Errorf("failed to determine version for %s: %w", pkgName, err)
		}
		outputPkgName := getOutputPackageName(pkgName, pm.Config)
		archivePkgName := getArchivePackageName(pkgName, pm.Config)
		arch := GetSystemArchForPackage(pm.Config, pkgName)
		variant := GetSystemVariantForPackage(pm.Config, pkgName)
		tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))

		isCriticalAtomic.Store(1)
		handlePreInstallUninstall(outputPkgName, pm.Config, RootExec, false, nil)
		if _, err := pkgInstall(tarballPath, outputPkgName, pm.Config, RootExec, false, false, false, nil); err != nil {
			isCriticalAtomic.Store(0)
			return fmt.Errorf("final installation failed for %s: %w", outputPkgName, err)
		}
		isCriticalAtomic.Store(0)

		if pm.UserRequested[pkgName] {
			addToWorld(pkgName)
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Installing:")
		colNote.Printf(" %s (%d/%d)\n", outputPkgName, i+1, len(targets))
	}

	return nil
}

func collectAvailableBinaryDependenciesForPlan(plan *BuildPlan, cfg *Config, noRemote bool) []binaryPlanDependency {
	if plan == nil || plan.NoDeps {
		return nil
	}

	inPlan := make(map[string]bool, len(plan.Order))
	for _, pkgName := range plan.Order {
		inPlan[pkgName] = true
	}

	seen := make(map[string]bool)
	var depsToInstall []binaryPlanDependency
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
				if seen[cand] || inPlan[cand] || isPackageInstalled(cand) {
					continue
				}
				if !dependencyBinaryAvailable(cand, cfg, noRemote) {
					if _, _, fallbackOK, _ := availableBuildDependencyBinaryTarball(cand, cfg, noRemote); !fallbackOK {
						continue
					}
				}
				seen[cand] = true
				depsToInstall = append(depsToInstall, binaryPlanDependency{Name: cand, Make: dep.Make})
				break
			}
		}
	}
	return depsToInstall
}

func installAvailableBinaryDependenciesForPlan(plan *BuildPlan, cfg *Config, noRemote bool) ([]string, error) {
	return installAvailableBinaryDependenciesForPlanWithOptions(plan, cfg, noRemote, false)
}

func installAvailableBinaryDependenciesForPlanWithOptions(plan *BuildPlan, cfg *Config, noRemote bool, quiet bool) ([]string, error) {
	depsToInstall := collectAvailableBinaryDependenciesForPlan(plan, cfg, noRemote)
	if len(depsToInstall) == 0 {
		return nil, nil
	}

	bar := newDependencyInstallProgress(len(depsToInstall), "Installing Build Dependencies", quiet)
	deactivateProgress := activateDependencyInstallProgress(bar)
	defer deactivateProgress()

	var installed []string
	for _, dep := range depsToInstall {
		describeDependencyInstallProgress(bar, dep.Name)
		if !quiet {
			colArrow.Print("-> ")
			colSuccess.Printf("Installing available binary dependency:")
			colNote.Printf(" %s\n", dep.Name)
		}
		ok, err := installAvailableBuildDependencyBinaryWithOptions(dep.Name, cfg, noRemote, quiet, false)
		if err != nil {
			return installed, fmt.Errorf("failed to install binary dependency %s: %w", dep.Name, err)
		}
		advanceDependencyInstallProgress(bar)
		if !ok {
			continue
		}
		installed = append(installed, dep.Name)
		if dep.Make {
			addToWorldMake(dep.Name)
		}
	}
	return installed, nil
}

func (pm *ParallelManager) isInteractive(pkgName string) bool {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return false
	}
	options := loadBuildOptions(pkgDir)
	return options["interactive"]
}

// Run executes the parallel build loop
func (pm *ParallelManager) Run() error {
	for len(pm.Pending) > 0 || len(pm.Running) > 0 || len(pm.pendingRebuilds) > 0 {
		// 1. Check if we can start new jobs
		pm.mu.Lock()
		// Check if any interactive job is currently running
		anyInteractiveRunning := false
		for rPkg := range pm.Running {
			if pm.isInteractive(rPkg) {
				anyInteractiveRunning = true
				break
			}
		}

		if !anyInteractiveRunning {
			// Identify candidates
			var nextPending []string
			canStartMore := true

			for _, pkgName := range pm.Pending {
				// Stop if we hit max jobs or just started/found an interactive job
				if !canStartMore || len(pm.Running) >= pm.MaxJobs {
					nextPending = append(nextPending, pkgName)
					continue
				}

				if pm.isInteractive(pkgName) {
					// Interactive packages must run ALONE
					if len(pm.Running) == 0 {
						if pm.canBuild(pkgName) {
							pm.startBuild(pkgName, len(pm.Completed)+len(pm.Running)+1, len(pm.BuildPlan.Order))
							canStartMore = false // Don't start anything else after starting an interactive job
						} else {
							nextPending = append(nextPending, pkgName)
						}
					} else {
						// Other jobs are running, wait for them to finish before starting this interactive one
						nextPending = append(nextPending, pkgName)
						canStartMore = false // Optimization: don't look ahead if we're waiting to isolate a job
					}
					continue
				}

				// Non-interactive package
				if pm.canBuild(pkgName) {
					pm.startBuild(pkgName, len(pm.Completed)+len(pm.Running)+1, len(pm.BuildPlan.Order))
				} else {
					nextPending = append(nextPending, pkgName)
				}
			}
			pm.Pending = nextPending
		}
		pm.mu.Unlock()

		// 2. Wait for a result if we are running jobs, otherwise just wait (shouldn't happen unless deadlock or done)
		if len(pm.Running) > 0 {
			res := <-pm.resultChan

			pm.mu.Lock()
			// Log file handling
			logFile := pm.LogFiles[res.pkgName]
			var logger io.Writer = io.Discard
			if logFile != nil {
				logger = logFile
			}

			if res.err != nil {
				pm.Failed[res.pkgName] = res.err
				// failed = true // We track failures but don't stop the world
			} else {
				if pm.shouldDeferInstallLocked(res.pkgName) {
					pm.Completed[res.pkgName] = true
					pm.Available[res.pkgName] = true
					pm.DeferredInstalls[res.pkgName] = true
				} else {
					// INSTALLATION (Sequential for safety)
					// We must install the package so that subsequent builds can find headers/libs.
					// Release lock during installation to allow UI loop (which needs lock) to run
					// and process prompts (which call back to UI loop).
					pm.mu.Unlock()
					var installErr error
					installResult := parallelInstallResult{Available: []string{res.pkgName}}
					if pm.isInteractive(res.pkgName) {
						WithPrompt(func() {
							UserExec.Interactive = true
							RootExec.Interactive = true
							installResult, installErr = pm.Installer(res.pkgName, logger)
							UserExec.Interactive = false
							RootExec.Interactive = false
						})
					} else if !pm.AutoYes {
						// Non-interactive package but prompts may appear (no -y flag).
						// Wrap in WithPrompt to pause the UI status line so modified-file
						// prompts are visible and the user can respond.
						WithPrompt(func() {
							installResult, installErr = pm.Installer(res.pkgName, logger)
						})
					} else {
						installResult, installErr = pm.Installer(res.pkgName, logger)
					}
					pm.mu.Lock()

					if installErr != nil {
						pm.Failed[res.pkgName] = fmt.Errorf("install failed: %w", installErr)
						// failed = true
					} else {
						pm.Completed[res.pkgName] = true
						if len(installResult.Available) == 0 {
							installResult.Available = []string{res.pkgName}
						}
						for _, availablePkg := range installResult.Available {
							pm.Available[availablePkg] = true
						}

						// 3. Dynamic Task Addition (Post-Build Rebuilds & Triggers)
						var rebuilds []string
						triggerSet := make(map[string]bool)

						// Add post-build rebuilds which are essentially triggers (force rebuild)
						if rbs, ok := pm.BuildPlan.PostBuildRebuilds[res.pkgName]; ok {
							rebuilds = append(rebuilds, rbs...)
							for _, t := range rbs {
								triggerSet[t] = true
							}
						}
						for _, parent := range pm.readyOptionalRebuildsLocked() {
							rebuilds = append(rebuilds, parent)
							triggerSet[parent] = true
						}
						// Add triggers returned by installer (e.g. library updates, filesystem triggers)
						if len(installResult.Rebuilds) > 0 {
							rebuilds = append(rebuilds, installResult.Rebuilds...)
						}

						// Identify which ones are filesystem triggers (e.g. DKMS) to ensure force-rebuild
						targetRoot := pm.Config.Values["HOKUTO_ROOT"]
						if targetRoot == "" {
							targetRoot = "/"
						}
						triggers := getRebuildTriggers(res.pkgName, targetRoot)
						for _, t := range triggers {
							triggerSet[t] = true
							// We don't append triggers to rebuilds again because they are already
							// included in derivedRebuilds from pm.Installer
						}

						if len(rebuilds) > 0 {
							var uniqueRebuilds []string
							seen := make(map[string]bool)

							// First pass: filter already completed/pending/duplicate packages
							for _, rPkg := range rebuilds {
								// Filesystem triggers (e.g. DKMS) must override the completed
								// status. If nvidia-modules was already installed from binary
								// earlier in this update, but a kernel update now triggers a
								// rebuild, the old binary is stale (wrong kernel modules).
								// Remove from Completed so it gets rebuilt from source.
								isTrigger := triggerSet[rPkg]
								if pm.Completed[rPkg] {
									if isTrigger {
										// Force re-queue: the previously installed binary is
										// stale (e.g. built against old kernel headers).
										delete(pm.Completed, rPkg)
									} else {
										continue
									}
								}
								if seen[rPkg] {
									continue
								}
								isPending := false
								for _, p := range pm.Pending {
									if p == rPkg {
										isPending = true
										break
									}
								}
								if isPending {
									continue
								}
								for _, p := range pm.pendingRebuilds {
									if p == rPkg {
										isPending = true
										break
									}
								}
								if isPending {
									continue
								}
								uniqueRebuilds = append(uniqueRebuilds, rPkg)
								seen[rPkg] = true
							}

							if len(uniqueRebuilds) > 0 {
								pm.pendingRebuilds = append(pm.pendingRebuilds, uniqueRebuilds...)
							}
						}
					}
				}
			}

			// NOW close and remove from map
			if f, ok := pm.LogFiles[res.pkgName]; ok {
				f.Close()
				// Only remove the log file if the build succeeded.
				// If it failed, we leave it for debugging.
				if res.err == nil {
					os.Remove(f.Name())
				}
				delete(pm.LogFiles, res.pkgName)
			}
			delete(pm.Running, res.pkgName)
			pm.mu.Unlock()
		} else if len(pm.Pending) > 0 || len(pm.pendingRebuilds) > 0 {
			// No running jobs but pending jobs exist.

			// 3. Batch Process Rebuild Prompts
			pm.mu.Lock()
			if len(pm.pendingRebuilds) > 0 {
				shouldRebuild := pm.AutoYes
				if !shouldRebuild {
					pm.mu.Unlock()
					WithPrompt(func() {
						fmt.Print("\r\033[K")
						cPrintf(colWarn, "\nThe following packages need to be rebuilt:\n")
						for _, p := range pm.pendingRebuilds {
							colArrow.Print("-> ")
							colInfo.Println(p)
						}
						cPrintf(colInfo, "Proceed with rebuild? [Y/n] ")
						reader := bufio.NewReader(os.Stdin)
						input, _ := reader.ReadString('\n')
						input = strings.TrimSpace(strings.ToLower(input))
						if input == "" || input == "y" || input == "yes" {
							shouldRebuild = true
						}
					})
					pm.mu.Lock()
				}

				if shouldRebuild {
					pm.Pending = append(pm.Pending, pm.pendingRebuilds...)
					if pm.BuildPlan.RebuildPackages == nil {
						pm.BuildPlan.RebuildPackages = make(map[string]bool)
					}
					for _, p := range pm.pendingRebuilds {
						pm.BuildPlan.RebuildPackages[p] = true
					}
				} else {
					fmt.Printf("Skipping rebuilds.\n")
				}
				// Clear pending rebuilds list since we've processed them
				pm.pendingRebuilds = nil
				pm.mu.Unlock()
				continue // Restart loop to immediately process the newly active pending jobs
			}
			pm.mu.Unlock()

			// If we have failures, assume pending jobs are blocked by them and exit gracefully.
			if len(pm.Failed) > 0 {
				break
			}
			return fmt.Errorf("parallel build deadlock: pending packages %v cannot be satisfied", pm.Pending)
		} else {
			// No running, no pending (or failed). Done.
			break
		}
	}
	return nil
}

func (pm *ParallelManager) shouldDeferInstallLocked(pkgName string) bool {
	if pm.AutoInstall || !pm.UserRequested[pkgName] {
		return false
	}
	if len(pm.SplitDepsBySource[pkgName]) > 0 || len(pm.BuildPlan.PostBuildRebuilds[pkgName]) > 0 {
		return false
	}
	for _, depPkg := range append([]string{}, pm.Pending...) {
		if pm.packageDependsOn(depPkg, pkgName) {
			return false
		}
	}
	for depPkg := range pm.Running {
		if depPkg != pkgName && pm.packageDependsOn(depPkg, pkgName) {
			return false
		}
	}
	for _, depPkg := range pm.pendingRebuilds {
		if pm.packageDependsOn(depPkg, pkgName) {
			return false
		}
	}
	return true
}

func (pm *ParallelManager) packageDependsOn(pkgName, dependency string) bool {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return false
	}
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return false
	}
	for _, dep := range deps {
		if !activeBuildDependency(dep, pm.Config, false) {
			continue
		}
		if parallelDepMatchesPackage(dep, dependency) {
			return true
		}
	}
	return false
}

func parallelDepMatchesPackage(dep DepSpec, pkgName string) bool {
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

func (pm *ParallelManager) installPackage(pkgName string, userRequestedMap map[string]bool, logger io.Writer) (parallelInstallResult, error) {
	if logger == nil {
		logger = io.Discard
	}
	result := parallelInstallResult{Available: []string{pkgName}}
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return result, err
	}

	outputPkgName := getOutputPackageName(pkgName, pm.Config)
	archivePkgName := getArchivePackageName(pkgName, pm.Config)
	arch := GetSystemArchForPackage(pm.Config, pkgName)
	variant := GetSystemVariantForPackage(pm.Config, pkgName)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))

	// We use RootExec for installation as it requires privileges
	isCriticalAtomic.Store(1)
	installExec := &Executor{
		Context:         RootExec.Context,
		ShouldRunAsRoot: RootExec.ShouldRunAsRoot,
		Interactive:     false,
		Stdout:          logger,
		Stderr:          logger,
	}

	// Fix: Skip install for cross-builds as we don't want to install target binaries to host
	// BUT, we MUST install cross-system packages (e.g. aarch64-gcc, aarch64-glibc)
	// OR if we are building the entire cross-system (HOKUTO_CROSS_SYSTEM=1), we install everything.
	if pm.Config.Values["HOKUTO_CROSS"] == "1" || pm.Config.Values["HOKUTO_CROSS_ARCH"] != "" {
		isCrossSystem := pm.Config.Values["HOKUTO_CROSS_SYSTEM"] == "1"
		crossArch := pm.Config.Values["HOKUTO_CROSS_ARCH"]
		if crossArch == "arm64" {
			crossArch = "aarch64"
		}

		isCrossSystemPkg := false
		if crossArch != "" {
			isCrossSystemPkg = strings.HasPrefix(pkgName, crossArch+"-")
		}

		// If it's a cross build but NOT building the whole system, ONLY install toolchain/libs
		// (those with the arch prefix). Everything else is a target package and should stay in BinDir.
		if !isCrossSystem && !isCrossSystemPkg {
			isCriticalAtomic.Store(0)
			if userRequestedMap[pkgName] {
				addToWorld(pkgName)
			}
			return result, nil
		}
	}

	beforeInstall := snapshotInstalledPackageNames()

	// Check for conflicts before install
	handlePreInstallUninstall(outputPkgName, pm.Config, installExec, pm.AutoYes, logger)
	rebuilds, err := pkgInstall(tarballPath, outputPkgName, pm.Config, installExec, pm.AutoYes, true, true, logger)
	isCriticalAtomic.Store(0)

	if err == nil {
		if userRequestedMap[pkgName] {
			addToWorld(pkgName)
		}

		for _, splitPkg := range pm.SplitDepsBySource[pkgName] {
			var err error
			if userRequestedMap[splitPkg] {
				err = installBuiltSplitTargetWithLogger(pkgName, splitPkg, pm.Config, logger, true)
			} else {
				err = installBuiltSplitDependencyWithLogger(pkgName, splitPkg, pm.Config, logger, true)
			}
			if err != nil {
				return result, fmt.Errorf("split dependency install failed for %s: %w", splitPkg, err)
			}
			if userRequestedMap[splitPkg] {
				addToWorld(splitPkg)
			}
			if logger != nil {
				fmt.Fprintf(logger, "Installing split dependency: %s\n", splitPkg)
			}
			result.Available = append(result.Available, splitPkg)
		}
		result.Rebuilds = rebuilds

		for installedPkg := range snapshotInstalledPackageNames() {
			if beforeInstall[installedPkg] || userRequestedMap[installedPkg] {
				continue
			}
			pm.TemporaryInstalls[installedPkg] = true
		}
	}

	return result, err
}

func (pm *ParallelManager) readyOptionalRebuildsLocked() []string {
	if len(pm.BuildPlan.PostRebuilds) == 0 {
		return nil
	}

	var rebuilds []string
	for parent, deps := range pm.BuildPlan.PostRebuilds {
		if !pm.Completed[parent] {
			continue
		}

		allAvailable := true
		for _, dep := range deps {
			if !pm.Available[dep] && !pm.Completed[dep] && !isPackageInstalled(dep) {
				allAvailable = false
				break
			}
		}
		if !allAvailable {
			continue
		}

		rebuilds = append(rebuilds, parent)
		delete(pm.BuildPlan.PostRebuilds, parent)
	}
	sort.Strings(rebuilds)
	return rebuilds
}

func (pm *ParallelManager) canBuild(pkgName string) bool {
	// Simplified dependency check reusing logic similar to executeBuildPass
	if pm.BuildPlan.NoDeps {
		return true
	}

	// Check manual prerequisites from hokuto.update
	if prereqs, ok := pm.BuildPlan.ManualPrereqs[pkgName]; ok {
		for _, prereq := range prereqs {
			if !pm.Completed[prereq] {
				return false
			}
		}
	}

	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return false // Should have been caught earlier
	}
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return false
	}

	for _, dep := range deps {
		if dep.RuntimeOnly || dep.Suggest {
			continue
		}
		if dep.Optional {
			continue
		}
		if dep.Cross && pm.Config.Values["HOKUTO_CROSS_ARCH"] == "" {
			continue
		}
		if dep.CrossNative {
			if pm.Config.Values["HOKUTO_CROSS_ARCH"] == "" || pm.Config.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
				continue
			}
		}

		candidates, err := resolvedBuildDependencyCandidates(dep, false, pm.Config)
		if err != nil {
			return false
		}

		satisfied := false
		for _, cand := range candidates {
			if shouldSkipMultilibMakeDep(dep, cand, pm.Config) {
				continue
			}
			splitSource := ""
			for sourcePkg, splitPkgs := range pm.SplitDepsBySource {
				for _, splitPkg := range splitPkgs {
					if splitPkg == cand {
						splitSource = sourcePkg
						break
					}
				}
				if splitSource != "" {
					break
				}
			}

			// If it failed in this run, we definitely can't be satisfied by it
			if pm.Failed[cand] != nil || (splitSource != "" && pm.Failed[splitSource] != nil) {
				continue
			}

			// Is it pending or running or in rebuild queue?
			isBuilding := false
			for _, p := range pm.Pending {
				if p == cand {
					isBuilding = true
					break
				}
			}
			if !isBuilding {
				for r := range pm.Running {
					if r == cand || (splitSource != "" && r == splitSource) {
						isBuilding = true
						break
					}
				}
			}
			if !isBuilding {
				for _, r := range pm.pendingRebuilds {
					if r == cand || (splitSource != "" && r == splitSource) {
						isBuilding = true
						break
					}
				}
			}
			if !isBuilding && splitSource != "" {
				for _, p := range pm.Pending {
					if p == splitSource {
						isBuilding = true
						break
					}
				}
			}

			// 1. Check if completed in this run
			if pm.Available[cand] || pm.Completed[cand] || (splitSource != "" && pm.Completed[splitSource] && pm.Available[cand]) {
				satisfied = true
				break
			}
			// 2. Check if installed in system. A make-time self dependency is a
			// bootstrap compiler/runtime deliberately installed before rebuilding
			// the same package, so it remains valid while that package is pending.
			selfBootstrap := dep.Make && cand == pkgName
			if (!isBuilding || selfBootstrap) && isPackageInstalled(cand) {
				satisfied = true
				break
			}
		}

		if !satisfied {
			return false
		}
	}
	return true
}

func (pm *ParallelManager) startBuild(pkgName string, idx, total int) {
	pm.Running[pkgName] = time.Now()
	interactive := pm.isInteractive(pkgName)

	// Create log file
	var logFile *os.File
	var logWriter io.Writer
	if !interactive {
		if err := os.MkdirAll(HokutoTmpDir, 0755); err == nil {
			if f, err := os.CreateTemp(HokutoTmpDir, fmt.Sprintf("hokuto-build-%s-*.log", pkgName)); err == nil {
				logFile = f
				pm.LogFiles[pkgName] = logFile
				logWriter = logFile // Write to file
			}
		}
	}

	if logWriter == nil && !interactive {
		logWriter = io.Discard
	}

	go func() {
		// Call pkgBuild with Quiet flag and LogWriter
		opts := BuildOptions{
			Bootstrap:     false, // TODO: Propagate from global?
			CurrentIndex:  idx,
			TotalCount:    total,
			Quiet:         !interactive,
			LogWriter:     logWriter,
			UpdateWebsite: UpdateWebsiteIndex,
		}

		var dur time.Duration
		var err error

		if interactive {
			WithPrompt(func() {
				UserExec.Interactive = true
				dur, err = pm.Builder(pkgName, pm.Config, UserExec, opts)
				UserExec.Interactive = false
			})
		} else {
			dur, err = pm.Builder(pkgName, pm.Config, UserExec, opts)
		}

		pm.resultChan <- buildResult{
			pkgName:  pkgName,
			err:      err,
			duration: dur,
			skipped:  dur == 0 && err == nil, // Rough proxy
		}

		if logFile != nil {
			if err != nil {
				// Print tail of log file to stdout?
				fmt.Fprintf(pm.LogFiles[pkgName], "\nBuild failed\n")
			}
		}
	}()
}

func (pm *ParallelManager) uiLoop(done chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond) // Faster ticker for responsiveness, checks reduction by diff
	defer ticker.Stop()

	lastStatus := ""
	paused := false
	ticks := 0

	for {
		select {
		case <-done:
			return
		case p := <-pm.promptPause:
			if p != paused {
				paused = p
				if paused {
					// ENTER PROMPT MODE:
					// Just ensure current line is clear.
					fmt.Print("\r\033[K")
				} else {
					// EXIT PROMPT MODE:
					// Force redraw of status on next tick
					lastStatus = ""
				}
			}
			pm.promptAck <- struct{}{}
		case <-ticker.C:
			// Continuous update
			// Note: When paused (prompt active), we skip updates to prevent
			// overwriting the prompt text (especially multi-line prompts).
			if paused {
				continue
			}

			// Force redraw every 2 seconds (20 ticks) to recover from log clobbering
			ticks++
			if ticks%20 == 0 {
				lastStatus = ""
			}

			newStatus := pm.getStatusString()
			if newStatus != lastStatus {
				fmt.Print("\r\033[K" + newStatus)
				lastStatus = newStatus
			}

		}
	}
}

func (pm *ParallelManager) getStatusString() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var building []string
	for p := range pm.Running {
		building = append(building, p)
	}
	sort.Strings(building) // Stabilize output

	// Use colors consistent with prompts
	// -> (Arrow) Building [N]: pkg1, pkg2 | Done: M Left: P

	prefix := colArrow.Sprint("->")

	// Limit list length
	listStr := strings.Join(building, ", ")
	if len(listStr) > 60 {
		listStr = listStr[:57] + "..."
	}

	return fmt.Sprintf("%s %s %s | %s",
		prefix,
		colSuccess.Sprintf("Building [%d]:", len(building)),
		colNote.Sprint(listStr),
		colSuccess.Sprintf("Done: %d Left: %d", len(pm.Completed), len(pm.Pending)))
}
