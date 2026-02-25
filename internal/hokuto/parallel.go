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
	MaxJobs   int
	Config    *Config
	BuildPlan *BuildPlan
	Context   context.Context
	Cancel    context.CancelFunc
	AutoYes   bool

	// State
	mu              sync.Mutex
	Pending         []string
	pendingRebuilds []string
	Running         map[string]time.Time // Package name -> Start time
	Completed       map[string]bool      // Package name -> true
	Failed          map[string]error
	LogFiles        map[string]*os.File

	// Dep injection for testing
	Builder   func(string, *Config, *Executor, BuildOptions) (time.Duration, error)
	Installer func(string, io.Writer) ([]string, error)

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

// RunParallelBuilds executes the build plan in parallel
func RunParallelBuilds(plan *BuildPlan, cfg *Config, maxJobs int, userRequestedMap map[string]bool, autoYes bool, customBuilder func(string, *Config, *Executor, BuildOptions) (time.Duration, error)) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pm := &ParallelManager{
		MaxJobs:     maxJobs,
		Config:      cfg,
		BuildPlan:   plan,
		Context:     ctx,
		Cancel:      cancel,
		Pending:     make([]string, len(plan.Order)),
		Running:     make(map[string]time.Time),
		Completed:   make(map[string]bool),
		Failed:      make(map[string]error),
		LogFiles:    make(map[string]*os.File),
		resultChan:  make(chan buildResult, maxJobs),
		promptPause: make(chan bool),
		promptAck:   make(chan struct{}),
		Builder:     pkgBuild,
		AutoYes:     autoYes,
	}

	if customBuilder != nil {
		pm.Builder = customBuilder
	}

	pm.Installer = func(pkg string, logger io.Writer) ([]string, error) {
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
						// Filter optional/cross
						if dep.Optional {
							continue
						}
						if dep.Cross && pm.Config.Values["HOKUTO_CROSS_ARCH"] == "" {
							continue
						}
						if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
							continue
						}

						// Check status involving alternatives
						candidates := []string{dep.Name}
						if len(dep.Alternatives) > 0 {
							candidates = dep.Alternatives
						}

						satisfied := false
						failedDep := ""
						for _, cand := range candidates {
							if !EnableMultilib && strings.HasSuffix(cand, "-32") {
								continue
							}
							if _, f := pm.Failed[cand]; f {
								failedDep = cand
							}
							if pm.Completed[cand] || isPackageInstalled(cand) {
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
		return err
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
		colSuccess.Println("Built/Installed Packages:")
		for _, pkg := range builtPkgs {
			fmt.Printf("  - %s\n", colNote.Sprint(pkg))
		}
	}

	return nil
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
	for len(pm.Pending) > 0 || len(pm.Running) > 0 {
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
			var logger io.Writer // default nil
			if logFile != nil {
				logger = logFile
			}

			if res.err != nil {
				pm.Failed[res.pkgName] = res.err
				// failed = true // We track failures but don't stop the world
			} else {
				// INSTALLATION (Sequential for safety)
				// We must install the package so that subsequent builds can find headers/libs.
				// Release lock during installation to allow UI loop (which needs lock) to run
				// and process prompts (which call back to UI loop).
				pm.mu.Unlock()
				var installErr error
				var derivedRebuilds []string
				if pm.isInteractive(res.pkgName) {
					WithPrompt(func() {
						UserExec.Interactive = true
						RootExec.Interactive = true
						derivedRebuilds, installErr = pm.Installer(res.pkgName, logger)
						UserExec.Interactive = false
						RootExec.Interactive = false
					})
				} else if !pm.AutoYes {
					// Non-interactive package but prompts may appear (no -y flag).
					// Wrap in WithPrompt to pause the UI status line so modified-file
					// prompts are visible and the user can respond.
					WithPrompt(func() {
						derivedRebuilds, installErr = pm.Installer(res.pkgName, logger)
					})
				} else {
					derivedRebuilds, installErr = pm.Installer(res.pkgName, logger)
				}
				pm.mu.Lock()

				if installErr != nil {
					pm.Failed[res.pkgName] = fmt.Errorf("install failed: %w", installErr)
					// failed = true
				} else {
					pm.Completed[res.pkgName] = true

					// 3. Dynamic Task Addition (Post-Build Rebuilds & Triggers)
					var rebuilds []string
					if rbs, ok := pm.BuildPlan.PostBuildRebuilds[res.pkgName]; ok {
						rebuilds = append(rebuilds, rbs...)
					}
					// Add triggers returned by installer (e.g. library updates)
					if len(derivedRebuilds) > 0 {
						rebuilds = append(rebuilds, derivedRebuilds...)
					}
					// Check for filesystem triggers (e.g. DKMS) in parallel mode
					targetRoot := pm.Config.Values["HOKUTO_ROOT"]
					if targetRoot == "" {
						targetRoot = "/"
					}
					triggers := getRebuildTriggers(res.pkgName, targetRoot)
					if len(triggers) > 0 {
						rebuilds = append(rebuilds, triggers...)
					}

					if len(rebuilds) > 0 {
						var uniqueRebuilds []string
						seen := make(map[string]bool)

						// First pass: filter already completed/pending/duplicate packages
						for _, rPkg := range rebuilds {
							if pm.Completed[rPkg] {
								continue
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
							uniqueRebuilds = append(uniqueRebuilds, rPkg)
							seen[rPkg] = true
						}

						if len(uniqueRebuilds) > 0 {
							pm.pendingRebuilds = append(pm.pendingRebuilds, uniqueRebuilds...)
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

func (pm *ParallelManager) installPackage(pkgName string, userRequestedMap map[string]bool, logger io.Writer) ([]string, error) {
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return nil, err
	}

	outputPkgName := getOutputPackageName(pkgName, pm.Config)
	arch := GetSystemArchForPackage(pm.Config, pkgName)
	variant := GetSystemVariantForPackage(pm.Config, pkgName)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(outputPkgName, version, revision, arch, variant))

	// We use RootExec for installation as it requires privileges
	isCriticalAtomic.Store(1)

	// Fix: Skip install for cross-builds as we don't want to install target binaries to host
	// BUT, we MUST install cross-system packages (e.g. aarch64-gcc, aarch64-glibc)
	if pm.Config.Values["HOKUTO_CROSS"] == "1" || pm.Config.Values["HOKUTO_CROSS_ARCH"] != "" {
		crossArch := pm.Config.Values["HOKUTO_CROSS_ARCH"]
		isCrossSystemPkg := false
		if crossArch != "" {
			isCrossSystemPkg = strings.HasPrefix(pkgName, crossArch+"-")
		}

		if !isCrossSystemPkg {
			isCriticalAtomic.Store(0)
			if userRequestedMap[pkgName] {
				addToWorld(pkgName)
			}
			return nil, nil
		}
	}

	// Check for conflicts before install
	handlePreInstallUninstall(outputPkgName, pm.Config, RootExec, pm.AutoYes, logger)                             // Pass AutoYes and logger
	rebuilds, err := pkgInstall(tarballPath, outputPkgName, pm.Config, RootExec, pm.AutoYes, false, true, logger) // Pass AutoYes, managed=true
	isCriticalAtomic.Store(0)

	if err == nil {
		if userRequestedMap[pkgName] {
			addToWorld(pkgName)
		}
	}

	return rebuilds, err
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
		if dep.Optional {
			continue
		}
		if dep.Cross && pm.Config.Values["HOKUTO_CROSS_ARCH"] == "" {
			continue
		}

		// Determine candidates: either the alternatives or just the single name
		candidates := []string{dep.Name}
		if len(dep.Alternatives) > 0 {
			candidates = dep.Alternatives
		}

		// Check if satisfied by ANY candidate
		satisfied := false
		for _, cand := range candidates {
			if !EnableMultilib && strings.HasSuffix(cand, "-32") {
				continue
			}

			// If it failed in this run, we definitely can't be satisfied by it
			if pm.Failed[cand] != nil {
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
					if r == cand {
						isBuilding = true
						break
					}
				}
			}
			if !isBuilding {
				for _, r := range pm.pendingRebuilds {
					if r == cand {
						isBuilding = true
						break
					}
				}
			}

			// 1. Check if completed in this run
			if pm.Completed[cand] {
				satisfied = true
				break
			}
			// 2. Check if installed in system (only if we're not planning to update/rebuild it!)
			if !isBuilding && isPackageInstalled(cand) {
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
			Bootstrap:    false, // TODO: Propagate from global?
			CurrentIndex: idx,
			TotalCount:   total,
			Quiet:        !interactive,
			LogWriter:    logWriter,
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
