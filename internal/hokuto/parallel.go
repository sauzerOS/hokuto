package hokuto

import (
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
	mu        sync.Mutex
	Pending   []string
	Running   map[string]time.Time // Package name -> Start time
	Completed map[string]bool      // Package name -> true
	Failed    map[string]error
	LogFiles  map[string]*os.File

	// Dep injection for testing
	Builder   func(string, *Config, *Executor, BuildOptions) (time.Duration, error)
	Installer func(string, io.Writer) error

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

	pm.Installer = func(pkg string, logger io.Writer) error {
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
			reason := "dependency not satisfied"
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

						// Check status
						if _, failed := pm.Failed[dep.Name]; failed {
							reason = fmt.Sprintf("dependency failed: %s", dep.Name)
							break
						}
						// Check if installed or built
						isBuilt := pm.Completed[dep.Name]
						isInstalled := isPackageInstalled(dep.Name)
						if !isBuilt && !isInstalled {
							reason = fmt.Sprintf("dependency not satisfied: %s", dep.Name)
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
	return nil
}

// Run executes the parallel build loop
func (pm *ParallelManager) Run() error {
	failed := false
	for len(pm.Pending) > 0 || len(pm.Running) > 0 {
		// 1. Check if we can start new jobs
		pm.mu.Lock()
		if !failed { // Stop starting new jobs if a failure occurred
			// Identify candidates
			var nextPending []string

			for _, pkgName := range pm.Pending {
				// Stop if we hit max jobs
				if len(pm.Running) >= pm.MaxJobs {
					nextPending = append(nextPending, pkgName)
					continue
				}

				// Check dependencies
				if pm.canBuild(pkgName) {
					// Start Build
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
				failed = true
			} else {
				// INSTALLATION (Sequential for safety)
				// We must install the package so that subsequent builds can find headers/libs.
				// Release lock during installation to allow UI loop (which needs lock) to run
				// and process prompts (which call back to UI loop).
				pm.mu.Unlock()
				installErr := pm.Installer(res.pkgName, logger)
				pm.mu.Lock()

				if installErr != nil {
					pm.Failed[res.pkgName] = fmt.Errorf("install failed: %w", installErr)
					failed = true
				} else {
					pm.Completed[res.pkgName] = true

					// 3. Dynamic Task Addition (Post-Build Rebuilds)
					if rebuilds, ok := pm.BuildPlan.PostBuildRebuilds[res.pkgName]; ok {
						for _, rPkg := range rebuilds {
							// Simple append for now. canBuild will gate it.
							if !pm.Completed[rPkg] {
								pm.Pending = append(pm.Pending, rPkg)
							}
						}
					}
				}
			}

			// NOW close and remove from map
			if f, ok := pm.LogFiles[res.pkgName]; ok {
				f.Close()
				delete(pm.LogFiles, res.pkgName)
			}
			delete(pm.Running, res.pkgName)
			pm.mu.Unlock()
		} else if len(pm.Pending) > 0 && !failed {
			// No running jobs but pending jobs exist, and we couldn't start any?
			return fmt.Errorf("parallel build deadlock: pending packages %v cannot be satisfied", pm.Pending)
		} else {
			// No running, no pending (or failed). Done.
			break
		}
	}
	return nil
}

func (pm *ParallelManager) installPackage(pkgName string, userRequestedMap map[string]bool, logger io.Writer) error {
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return err
	}

	outputPkgName := getOutputPackageName(pkgName, pm.Config)
	arch := GetSystemArch(pm.Config)
	variant := GetSystemVariantForPackage(pm.Config, pkgName)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(outputPkgName, version, revision, arch, variant))

	// We use RootExec for installation as it requires privileges
	isCriticalAtomic.Store(1)
	// Check for conflicts before install
	handlePreInstallUninstall(outputPkgName, pm.Config, RootExec, pm.AutoYes)             // Pass AutoYes
	err = pkgInstall(tarballPath, outputPkgName, pm.Config, RootExec, pm.AutoYes, logger) // Pass AutoYes
	isCriticalAtomic.Store(0)

	if err == nil {
		if userRequestedMap[pkgName] {
			addToWorld(pkgName)
		}
	}

	return err
}

func (pm *ParallelManager) canBuild(pkgName string) bool {
	// Simplified dependency check reusing logic similar to executeBuildPass

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

		if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
			continue
		}

		// Check if satisfied
		satisfied := false

		// 1. Check if completed in this run
		if pm.Completed[dep.Name] {
			satisfied = true
		} else {
			// 2. Check if installed in system
			if isPackageInstalled(dep.Name) { // Simplified check
				satisfied = true
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

	// Create log file
	logFile, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("hokuto-build-%s-*.log", pkgName))
	var logWriter io.Writer
	if err == nil {
		pm.LogFiles[pkgName] = logFile
		logWriter = logFile // Write to file
	} else {
		logWriter = io.Discard
	}

	go func() {
		// Call pkgBuild with Quiet=true and LogWriter
		opts := BuildOptions{
			Bootstrap:    false, // TODO: Propagate from global?
			CurrentIndex: idx,
			TotalCount:   total,
			Quiet:        true,
			LogWriter:    logWriter,
		}

		start := time.Now()
		// Use injected Builder
		dur, err := pm.Builder(pkgName, pm.Config, UserExec, opts)

		pm.resultChan <- buildResult{
			pkgName:  pkgName,
			err:      err,
			duration: dur,
			skipped:  dur == 0 && err == nil, // Rough proxy
		}

		if logFile != nil {
			if err != nil {
				// Print tail of log file to stdout?
				fmt.Fprintf(pm.LogFiles[pkgName], "\nBuild failed in %s\n", time.Since(start))
			}
		}
	}()
}

func (pm *ParallelManager) uiLoop(done chan struct{}) {
	ticker := time.NewTicker(100 * time.Millisecond) // Faster ticker for responsiveness, checks reduction by diff
	defer ticker.Stop()

	lastStatus := ""
	paused := false

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
	// -> (Arrow) Building [N]: pkg1, pkg2 | Done: M

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
		colSuccess.Sprintf("Done: %d", len(pm.Completed)))
}
