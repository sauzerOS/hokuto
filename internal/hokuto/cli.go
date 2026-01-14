package hokuto

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gookit/color"
)

// printHelp prints the commands table
func printHelp() {
	// General Usage Header
	colSuccess.Println("Usage: hokuto <command> [arguments]")
	colSuccess.Println("Run 'hokuto <command>' for advanced options")
	fmt.Println()
	color.Info.Println("Available Commands:")

	type cmdInfo struct {
		Cmd  string
		Args string
		Desc string
	}
	// Restore detailed descriptions including command-specific options
	cmds := []cmdInfo{
		{"version, --version", "", "Version information"},
		{"log", "", "TUI build log viewer"},
		{"list, ls", "<pkg>", "List installed packages, optionally filter by name"},
		{"checksum, c", "<pkg>", "Fetch sources and generate checksum file"},
		{"build, b", "<pkg>", "Build package(s)"},
		{"install, i", "<pkg>", "Install pre-built package(s)"},
		{"uninstall, r", "<pkg>", "Uninstall package(s)"},
		{"update, u", "[options]", "Update repositories and check for upgrades"},
		{"manifest, m", "<pkg>", "Show the file list for an installed package"},
		{"find, f", "<query>", "Find which package matches query string"},
		{"new, n", "<pkg>", "Create a new package skeleton"},
		{"edit, e", "<pkg>", "Edit a package's build files"},
		{"bump", "<pkgset> <old> <new>", "Batch update a set of packages"},
		{"cd", "<pkg>", "Change directory to package repository directory"},
		{"bootstrap", "<dir>", "Build a bootstrap rootfs in target directory"},
		{"chroot", "<dir> [cmd]", "Enter chroot and run command (default: /bin/bash)"},
		{"cleanup", "[options]", "Cleanup caches"},
		{"python-rebuild", "", "Rebuild all python packages"},
		{"alt", "<pkg>", "List packages with alternatives or show/switch alternatives for a package"},
		{"init-repos", "", "Initialize repositories"},
	}

	// --- Dynamic Padding Logic ---
	// 1. Find the longest usage string to calculate the ideal width for the first column.
	maxLen := 0
	for _, c := range cmds {
		length := len(c.Cmd) + len(c.Args)
		if c.Args != "" {
			length++ // Account for the space
		}
		if length > maxLen {
			maxLen = length
		}
	}
	// The final column width is the longest command plus some buffer space.
	columnWidth := maxLen + 4

	// 2. Print the formatted list with calculated padding.
	for _, c := range cmds {
		// This will hold the uncolored string to measure its length for padding
		var usageString string
		if c.Args != "" {
			usageString = fmt.Sprintf("  %s %s", c.Cmd, c.Args)
		} else {
			usageString = fmt.Sprintf("  %s", c.Cmd)
		}

		// Print the colored command and arguments
		fmt.Print("  ") // Indent
		color.Bold.Print(c.Cmd)
		if c.Args != "" {
			fmt.Print(" ")
			color.Cyan.Print(c.Args)
		}

		// Calculate the necessary padding and print it
		pad := columnWidth - len(usageString)
		if pad < 1 {
			pad = 1
		}
		fmt.Print(strings.Repeat(" ", pad))

		// Print the description
		color.Info.Println(c.Desc)
	}

	fmt.Println()

}

// Main is the CLI entrypoint for cmd/hokuto.
func Main() {
	// 1. CONTEXT AND SIGNAL SETUP
	// Create the main application context and the function to cancel it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. SIGNAL CHANNEL SETUP
	sigs := make(chan os.Signal, 1)
	// Register to receive SIGINT (Ctrl+C) and SIGTERM (kill command)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// 3. SIGNAL HANDLING GOROUTINE
	go func() {
		for {
			select {
			case sig := <-sigs:
				if isCriticalAtomic.Load() == 1 {
					// --- CRITICAL PHASE: Block 1st signal, force exit on 2nd ---
					colArrow.Print("\n-> ")
					colError.Printf("Critical operation in progress (e.g., install). Press Ctrl+C AGAIN to force exit NOW.\n")

					// Wait for a second signal or a short delay
					select {
					case <-sigs:
						colArrow.Print("\n-> ")
						colError.Printf("Forced immediate exit.")
						os.Exit(130) // Common exit code for SIGINT
					case <-time.After(5 * time.Second):
						// If no second signal, continue waiting for the loop to repeat
						continue
					case <-ctx.Done():
						return // Context cancelled from outside
					}
				} else {
					// --- NON-CRITICAL PHASE: Graceful Cancellation ---
					colArrow.Print("\n-> ")
					color.Danger.Printf("Received %v. Cancelling process gracefully\n", sig)
					cancel() // Cancel the context

					// Give the command a moment to die and flush its buffers
					time.Sleep(100 * time.Millisecond)

					// Wait for a second signal for immediate exit
					// NOTE: Don't check ctx.Done() here since we just cancelled it
					select {
					case <-sigs:
						colArrow.Print("\n-> ")
						color.Danger.Printf("Second interrupt received. Forcing immediate exit.")
						os.Exit(130)
					case <-time.After(2 * time.Second):
						// Give more time for graceful shutdown (increased from 500ms to 2s)
						colArrow.Print("\n-> ")
						color.Danger.Printf("Graceful shutdown timeout. Exiting.")
						os.Exit(0)
					}
				}

			case <-ctx.Done():
				return // Context cancelled from the main flow
			} // <-- Correctly closed 'select' statement
		} // <-- Correctly closed 'for' loop
	}() // <-- Correctly closed 'go func'

	// 4. MAIN LOGIC EXECUTION
	// Check for immediate cancellation before starting (e.g., if signal received early)
	if ctx.Err() != nil {
		// Already cancelled before we started the main logic
		return
	}

	if len(os.Args) < 2 {
		printHelp()
		return
	}

	cfg, err := loadConfig(ConfigFile)
	if err != nil {
		// handle error
	}
	mergeEnvOverrides(cfg)
	initConfig(cfg)

	// 4.5 Handle versioned package requests (pkg@version)
	// This allows commands like 'build gcc@1.2.3' to work by extracting the old version from Git history.
	if len(os.Args) >= 2 {
		cmd := os.Args[1]
		// List of commands that support package name arguments and should handle @version
		versionedSupportedCmds := map[string]bool{
			"build": true, "b": true, "checksum": true, "c": true, "edit": true, "e": true, "cd": true,
			"install": true, "i": true, "manifest": true, "m": true, "uninstall": true, "r": true, "remove": true,
		}

		if versionedSupportedCmds[cmd] {
			for i := 2; i < len(os.Args); i++ {
				arg := os.Args[i]
				// Basic check to see if it's a versioned package request and not a flag or file path
				if strings.Contains(arg, "@") && !strings.HasPrefix(arg, "-") && !strings.HasSuffix(arg, ".tar.zst") && !strings.Contains(arg, "/") {
					pkgName, err := prepareVersionedPackage(arg)
					if err == nil {
						os.Args[i] = pkgName // Replace gcc@1.2.3 with gcc in Args
					} else {
						// Only fail if it's not a direct tarball path (already checked above, but to be safe)
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
						os.Exit(1)
					}
				}
			}
		}
	}

	// 5. CHECK IF ROOT PRIVILEGES ARE NEEDED
	if needsRootPrivileges(os.Args[1:]) {
		if err := authenticateOnce(); err != nil {
			fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
			os.Exit(1)
		}
	}

	// 6. INITIALIZE EXECUTORS
	UserExec = &Executor{
		Context:         ctx,
		ShouldRunAsRoot: false,
	}
	RootExec = &Executor{
		Context:         ctx,
		ShouldRunAsRoot: true,
	}

	// 7. MAIN LOGIC
	var exitCode int

	switch os.Args[1] {
	case "log":
		exitCode = runTUI()

	case "chroot":
		// Call the new wrapper function that contains the defer logic
		exitCode = runChrootCommand(os.Args[2:], RootExec)

	case "cleanup":
		// Pass 'cfg' to the function
		if err := handleCleanupCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup failed: %v\n", err)
			os.Exit(1)
		}

	case "python-rebuild":
		if err := handlePythonRebuildCommand(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Python rebuild failed: %v\n", err)
			os.Exit(1)
		}

	case "alt":
		if err := handleAlternativesCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Alternatives command failed: %v\n", err)
			os.Exit(1)
		}

	case "init-repos":
		if err := handleInitReposCommand(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Repository initialization failed: %v\n", err)
			os.Exit(1)
		}

	case "version", "--version":
		// Try to pick and show a random embedded PNG from assets/
		imgs, err := listEmbeddedImages()
		if err != nil || len(imgs) == 0 {
			// No images available — nothing more to do
			if err != nil {
				debugf("warning: failed to list embedded images: %v\n", err)
			}
			break
		}

		// Choose a random image
		choice := imgs[rand.Intn(len(imgs))]

		// Display via chafa using the main context (ctx must be in scope in main)
		// Forward a small default set of chafa flags; you may change or pass none.
		if err := displayEmbeddedWithChafa(ctx, choice, "--symbols=block", "--size=80x40"); err != nil {
			debugf("error displaying image: %v\n", err)
		}

		// Print version and architecture
		colNote.Printf("hokuto %s (%s) built %s\n", version, arch, buildDate)

	case "list", "ls":
		pkg := ""
		if len(os.Args) >= 3 {
			pkg = os.Args[2]
		}
		if err := listPackages(pkg); err != nil {
			// If it's the "not found" error, the friendly message was already printed.
			if errors.Is(err, errPackageNotFound) {
				exitCode = 1
			} else {
				fmt.Fprintln(os.Stderr, "Error:", err)
				exitCode = 1
			}
		}

	case "check":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto check <pkgname>")
			os.Exit(1)
		}
		pkgName := os.Args[2]

		// Perform exact match check
		if checkPackageExactMatch(pkgName) {
			// Package found - silent success, exit 0
			os.Exit(0)
		} else {
			// Package not found - silent failure, exit 1
			os.Exit(1)
		}

	case "checksum", "c":
		force := false
		unpack := false

		if len(os.Args) < 3 {
			colNote.Println(" Usage: hokuto checksum [-unpack] <pkg1> [<pkg2> ...] [-f]")
			colSuccess.Println("  -unpack: Unpack the sources in build directory")
			colSuccess.Println("  -f: Force sources download")
			return
		}

		// Collect args after the command
		args := os.Args[2:]

		// Check for flags
		for i := len(args) - 1; i >= 0; i-- {
			switch args[i] {
			case "-f":
				force = true
				args = append(args[:i], args[i+1:]...)
			case "-unpack":
				unpack = true
				args = append(args[:i], args[i+1:]...)
			}
		}

		if len(args) == 0 {
			colNote.Println(" Usage: hokuto checksum [-unpack] <pkg1> [<pkg2> ...] [-f]")
			colSuccess.Println("  -unpack: Unpack the sources in build directory")
			colSuccess.Println("  -f: Force sources download")
			return
		}

		// args now contains one or more package names
		var overallErr error
		for _, pkg := range args {
			if err := hokutoChecksum(pkg, force, unpack); err != nil {
				fmt.Printf("Error for %s: %v\n", pkg, err)
				overallErr = err
				// continue to process remaining packages
			}
		}

		if overallErr != nil {
			os.Exit(1)
		}

	case "build", "b":
		if err := ensureHokutoOwnership(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Ownership check failed: %v\n", err)
		}
		if err := handleBuildCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Build failed: %v\n", err)
			os.Exit(1)
		}

	case "bootstrap":
		// 1. Verify that the bootstrap directory is provided.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: hokuto bootstrap <bootstrap-dir>")
			fmt.Fprintln(os.Stderr, "Error: Missing required argument: <bootstrap-dir>")
			os.Exit(1)
		}
		bootstrapDirArg := os.Args[2]

		// 2. Construct the arguments to pass to the build handler.
		// This effectively translates `hokuto bootstrap /mnt/lfs` into
		// `hokuto build --bootstrap --bootstrap-dir /mnt/lfs bootstrap`.
		buildArgs := []string{
			"-bootstrap",
			"-bootstrap-dir",
			bootstrapDirArg,
			"bootstrap", // The actual package name to build
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Starting bootstrap process in directory: %s\n", bootstrapDirArg)

		// 3. Call the generic build handler with the constructed arguments.
		if err := handleBuildCommand(buildArgs, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Bootstrap failed: %v\n", err)
			os.Exit(1)
		}

	case "install", "i":
		if err := ensureHokutoOwnership(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Ownership check failed: %v\n", err)
		}
		installCmd := flag.NewFlagSet("install", flag.ExitOnError)
		var yes = installCmd.Bool("y", false, "Assume 'yes' to all prompts and overwrite modified files.")
		var yesLong = installCmd.Bool("yes", false, "Assume 'yes' to all prompts and overwrite modified files.")
		var force = installCmd.Bool("force", false, "Install even if package is already installed.")
		var nodeps = installCmd.Bool("nodeps", false, "Ignore dependencies.")

		if err := installCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing install flags: %v\n", err)
			os.Exit(1)
		}
		packagesToInstall := installCmd.Args()
		if len(packagesToInstall) == 0 {
			fmt.Println("Usage: hokuto install [options] <tarball|pkgname>...")
			installCmd.PrintDefaults()
			os.Exit(1)
		}

		effectiveYes := *yes || *yesLong

		// We build a list of ALL packages to install (explicit + dependencies).
		var installPlan []string
		visited := make(map[string]bool)

		// Map to track which packages were explicitly requested by the user
		// so we only add those to the World file later.
		userRequestedMap := make(map[string]bool)

		for _, arg := range packagesToInstall {
			// If argument is a tarball file (ends in .tar.zst), we just add it to the plan directly.
			// We cannot auto-resolve dependencies for a raw file path easily.
			if strings.HasSuffix(arg, ".tar.zst") {
				installPlan = append(installPlan, arg)
				// We attempt to guess the package name for World file tracking
				// Format: pkgname-version-revision.tar.zst
				base := filepath.Base(arg)
				nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")
				// Find the last two dashes to separate name-version-revision
				parts := strings.Split(nameWithoutExt, "-")
				if len(parts) >= 3 {
					// Rejoin all but the last two parts (version and revision) as package name
					pkgName := strings.Join(parts[:len(parts)-2], "-")
					userRequestedMap[pkgName] = true
				} else if len(parts) >= 2 {
					// Fallback for old format: pkgname-version.tar.zst
					pkgName := parts[0]
					userRequestedMap[pkgName] = true
				}
				continue
			}

			// If argument is a package name
			pkgName := arg
			userRequestedMap[pkgName] = true

			if *nodeps {
				// Bypass dependency resolution if -nodeps is set
				// But still need to add the package itself if not installed, or if force is used
				if !checkPackageExactMatch(pkgName) || *force {
					installPlan = append(installPlan, pkgName)
				} else {
					colArrow.Print("-> ")
					colSuccess.Printf("Package %s is already installed. Skipping (use -force to reinstall).\n", pkgName)
				}
			} else {
				// Recursively find missing dependencies (always check if deps are installed, force doesn't apply to deps)
				if err := resolveBinaryDependencies(pkgName, visited, &installPlan, false, effectiveYes); err != nil {
					// Skip dependency resolution if source not found (e.g., renamed cross-system packages)
					// The package can still be installed from tarball without source
					if strings.Contains(err.Error(), "source not found in HOKUTO_PATH") {
						// Add the package to install plan even without dependency resolution
						// (it will be installed from tarball if available)
						if !checkPackageExactMatch(pkgName) {
							installPlan = append(installPlan, pkgName)
						}
						continue
					}
					fmt.Fprintf(os.Stderr, "Error resolving dependencies for %s: %v\n", pkgName, err)
					os.Exit(1)
				}
			}

			// If force is enabled, add the user-requested package even if it's already installed
			// (dependencies are handled above and won't be added if already installed)
			if *force {
				// Check if package is already in plan (from dependency resolution)
				alreadyInPlan := false
				for _, pkg := range installPlan {
					if pkg == pkgName {
						alreadyInPlan = true
						break
					}
				}
				// If not in plan (because it's already installed), add it anyway when force is enabled
				if !alreadyInPlan {
					installPlan = append(installPlan, pkgName)
				}
			}
		}

		if len(installPlan) == 0 && !*force {
			colArrow.Print("-> ")
			colSuccess.Println("All packages and dependencies are already installed.")
			os.Exit(0)
		}

		// Notify user if extra dependencies were pulled in
		if len(installPlan) > len(packagesToInstall) {
			var extraDeps []string
			for _, pkg := range installPlan {
				// Only add if it wasn't explicitly asked for by the user
				if !userRequestedMap[pkg] {
					extraDeps = append(extraDeps, pkg)
				}
			}

			if len(extraDeps) > 0 {
				colArrow.Print("-> ")
				colWarn.Printf("The following extra dependencies will be installed: %v\n", extraDeps)
			}
		}

		// Set to CRITICAL (1) for the entire installation process
		isCriticalAtomic.Store(1)
		// Ensure it is reset when the install function returns/panics
		defer isCriticalAtomic.Store(0)

		allSucceeded := true

		// Iterate through the calculated plan
		for i, arg := range installPlan {
			var tarballPath, pkgName string

			if strings.HasSuffix(arg, ".tar.zst") {
				// Case A: Direct Tarball
				// Format: pkgname-version-revision.tar.zst
				tarballPath = arg
				base := filepath.Base(tarballPath)
				nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")
				parts := strings.Split(nameWithoutExt, "-")
				if len(parts) < 3 {
					// Fallback for old format: pkgname-version.tar.zst
					lastDashIndex := strings.LastIndex(nameWithoutExt, "-")
					if lastDashIndex == -1 {
						fmt.Fprintf(os.Stderr, "Error: Could not determine package name from tarball file name: %s\n", arg)
						allSucceeded = false
						continue
					}
					pkgName = nameWithoutExt[:lastDashIndex]
				} else {
					// New format: pkgname-version-revision
					// Rejoin all but the last two parts as package name
					pkgName = strings.Join(parts[:len(parts)-2], "-")
				}
				if _, err := os.Stat(tarballPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: Tarball not found or inaccessible: %s\n", tarballPath)
					allSucceeded = false
					continue
				}
			} else {
				// Case B: Package Name (Auto-resolved or requested)
				pkgName = arg
				version, revision, err := getRepoVersion2(pkgName)
				tarballFoundDirectly := false
				if err != nil {
					// If source not found (e.g., renamed cross-system packages), try to find tarball
					if strings.Contains(err.Error(), "not found") {
						// Try to find the newest tarball matching this package name
						foundTarball, foundVersion, foundRevision := findNewestTarball(pkgName)
						if foundTarball != "" {
							tarballPath = foundTarball
							version = foundVersion
							revision = foundRevision
							tarballFoundDirectly = true
						} else {
							fmt.Fprintf(os.Stderr, "Error determining version for %s: %v\n", pkgName, err)
							allSucceeded = false
							continue
						}
					} else {
						fmt.Fprintf(os.Stderr, "Error determining version for %s: %v\n", pkgName, err)
						allSucceeded = false
						continue
					}
				} else {
					tarballPath = filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", pkgName, version, revision))
				}

				// 1. Check Local Cache (skip if we already found the tarball directly)
				if !tarballFoundDirectly {
					if _, err := os.Stat(tarballPath); err != nil {
						foundOnMirror := false

						// 2. Not in local cache? Try Mirror.
						if BinaryMirror != "" {
							if err := fetchBinaryPackage(pkgName, version, revision); err == nil {
								foundOnMirror = true
							} else {
								debugf("Mirror fetch failed for %s: %v\n", pkgName, err)
							}
						}

						// 3. If still not found, error out.
						if !foundOnMirror {
							cPrintf(colWarn, "Error: Binary package not found for %s.\n", pkgName)
							cPrintf(colInfo, "Expected path: %s\n", tarballPath)
							if BinaryMirror != "" {
								cPrintf(colInfo, "Mirror check failed or file missing on server.\n")
							}
							cPrintf(colInfo, "Tip: Run 'hokuto build %s' to create the binary.\n", pkgName)
							allSucceeded = false
							continue
						}
					}
				}
			}

			handlePreInstallUninstall(pkgName, cfg, RootExec)

			colArrow.Print("-> ")
			colSuccess.Printf("Installing:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, len(installPlan))

			if err := pkgInstall(tarballPath, pkgName, cfg, RootExec, effectiveYes); err != nil {
				fmt.Fprintf(os.Stderr, "Error installing package %s: %v\n", pkgName, err)
				allSucceeded = false
				continue
			}

			// --- Add to World File ---
			// Only if the user explicitly requested this package (not auto-deps)
			if userRequestedMap[pkgName] {
				if err := addToWorld(pkgName); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to add %s to world file: %v\n", pkgName, err)
				}
			}

			colArrow.Print("-> ")
			colSuccess.Printf("Package %s installed successfully.\n", pkgName)
		}

		if !allSucceeded {
			os.Exit(1)
		}

	case "uninstall", "remove", "r":
		// 1. Initialize a FlagSet for the "uninstall" subcommand
		uninstallCmd := flag.NewFlagSet("uninstall", flag.ExitOnError)
		var force = uninstallCmd.Bool("f", false, "Force uninstallation, ignoring dependency checks.")
		var yes = uninstallCmd.Bool("y", false, "Assume 'yes' to all prompts.")
		// Also support long flags for consistency
		var forceLong = uninstallCmd.Bool("force", false, "Force uninstallation, ignoring dependency checks.")
		var yesLong = uninstallCmd.Bool("yes", false, "Assume 'yes' to all prompts.")

		if err := uninstallCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing uninstall flags: %v\n", err)
			os.Exit(1)
		}

		packagesToUninstall := uninstallCmd.Args()

		if len(packagesToUninstall) == 0 {
			fmt.Println("Usage: hokuto uninstall [options] <pkgname> [pkgname...]")
			fmt.Println("Options:")
			uninstallCmd.PrintDefaults()
			os.Exit(1)
		}

		effectiveForce := *force || *forceLong
		effectiveYes := *yes || *yesLong

		// critical section for the entire operation
		isCriticalAtomic.Store(1)
		defer isCriticalAtomic.Store(0)

		allSucceeded := true
		for _, pkgName := range packagesToUninstall {
			colArrow.Print("-> ")
			colSuccess.Printf("Attempting to uninstall package: %s\n", pkgName)

			if err := pkgUninstall(pkgName, cfg, RootExec, effectiveForce, effectiveYes); err != nil {
				colArrow.Print("-> ")
				color.Light.Printf("Error uninstalling %s: %v\n", pkgName, err)
				allSucceeded = false
			} else {
				colArrow.Print("-> ")
				colSuccess.Printf("Package %s removed\n", pkgName)
				removeFromWorld(pkgName)
			}
		}

		if !allSucceeded {
			os.Exit(1)
		}

	case "update", "u":
		if err := ensureHokutoOwnership(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Ownership check failed: %v\n", err)
		}
		// Use a proper FlagSet to parse arguments and set buildPriority
		updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
		var idleBuild = updateCmd.Bool("i", false, "Use half CPU cores and lowest niceness for build process.")
		var superidleBuild = updateCmd.Bool("ii", false, "Use one CPU core and lowest niceness for build process.")
		var verbose = updateCmd.Bool("v", false, "Enable verbose output.")
		// Add long flags for consistency
		var idleBuildLong = updateCmd.Bool("idle", false, "Use half CPU cores and lowest niceness for build process.")
		var superidleBuildLong = updateCmd.Bool("superidle", false, "Use one CPU core and lowest niceness for build process.")
		var verboseLong = updateCmd.Bool("verbose", false, "Enable verbose output.")

		if err := updateCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing update flags: %v\n", err)
			os.Exit(1)
		}

		// Set the global variables that pkgBuild() reads
		if *superidleBuild || *superidleBuildLong {
			buildPriority = "superidle"
		} else if *idleBuild || *idleBuildLong {
			buildPriority = "idle"
		} else {
			buildPriority = "normal"
		}
		Verbose = *verbose || *verboseLong

		updateRepos()

		if err := PostInstallTasks(RootExec); err != nil {
			fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
		}

		if err := checkForUpgrades(ctx, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Upgrade process failed: %v\n", err)
			os.Exit(1)
		}

	case "manifest", "m":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto manifest <pkgname>")
			os.Exit(1)
		}
		pkg := os.Args[2]
		if err := showManifest(pkg); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	case "find", "f":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto find <string>")
			os.Exit(1)
		}
		query := os.Args[2]
		if err := findPackagesByManifestString(query); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	case "new", "n":
		newCmd := flag.NewFlagSet("new", flag.ExitOnError)
		var here = newCmd.Bool("here", false, "Create package in current working directory")
		if err := newCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing new flags: %v\n", err)
			os.Exit(1)
		}
		args := newCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: hokuto new [-here] <pkgname>")
			os.Exit(1)
		}
		pkg := args[0]
		var targetDir string
		if *here {
			// Use current working directory
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting current directory: %v\n", err)
				os.Exit(1)
			}
			targetDir = cwd
		} else {
			// Use default newPackageDir
			targetDir = ""
		}
		if err := newPackage(pkg, targetDir); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	case "cd":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto cd <pkgname>")
			os.Exit(1)
		}
		pkgName := os.Args[2]
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Package '%s' not found in any repository: %v\n", pkgName, err)
			os.Exit(1)
		}
		// Spawn a shell in the package directory
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
		cmd := exec.Command(shell)
		cmd.Dir = pkgDir
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error running shell: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)

	case "edit", "e":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto edit <pkgname> [-a]")
			os.Exit(1)
		}

		pkg := os.Args[2]
		openAll := false

		if len(os.Args) == 4 {
			if os.Args[3] == "-a" {
				openAll = true
			} else {
				fmt.Println("Usage: hokuto edit <pkgname> [-a]")
				os.Exit(1)
			}
		} else if len(os.Args) > 4 {
			fmt.Println("Usage: hokuto edit <pkgname> [-a]")
			os.Exit(1)
		}

		if err := editPackage(pkg, openAll); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	case "bump":
		bumpCmd := flag.NewFlagSet("bump", flag.ExitOnError)
		var isSet = bumpCmd.Bool("set", false, "Bump a package set")
		if err := bumpCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing bump flags: %v\n", err)
			os.Exit(1)
		}
		args := bumpCmd.Args()

		if *isSet {
			// Mode: Set Bump (hokuto bump -set <pkgset> <old> <new>)
			if len(args) < 3 {
				fmt.Println("Usage: hokuto bump -set <pkgset> <oldversion> <newversion>")
				os.Exit(1)
			}
			if err := handleSetBumpCommand(args[0], args[1], args[2]); err != nil {
				fmt.Fprintf(os.Stderr, "Bump failed: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Mode: Single Bump (hokuto bump <pkg> <new>)
			if len(args) < 2 {
				fmt.Println("Usage: hokuto bump <pkgname> <newversion>")
				os.Exit(1)
			}
			if err := handleSingleBumpCommand(args[0], args[1]); err != nil {
				fmt.Fprintf(os.Stderr, "Bump failed: %v\n", err)
				os.Exit(1)
			}
		}

	default:
		printHelp()
		exitCode = 1
	}
	os.Exit(exitCode)
}

// findNewestTarball finds the newest tarball matching the package name pattern
// Returns (tarballPath, version, revision) or ("", "", "") if not found
func findNewestTarball(pkgName string) (string, string, string) {
	// Search in all possible bin directories
	binDirs := []string{
		BinDir,                    // Default bin directory
		CacheDir + "/bin/generic", // Generic builds
		CacheDir + "/bin/cross",   // Cross builds
	}

	var newestTarball string
	var newestModTime time.Time
	var foundVersion, foundRevision string

	for _, binDir := range binDirs {
		// Pattern: pkgname-*-*.tar.zst (new format) or pkgname-*.tar.zst (old format)
		pattern := filepath.Join(binDir, pkgName+"-*.tar.zst")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}

			// Check if this is newer than what we've found so far
			if newestTarball == "" || info.ModTime().After(newestModTime) {
				newestTarball = match
				newestModTime = info.ModTime()

				// Parse version and revision from filename
				base := filepath.Base(match)
				nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")
				parts := strings.Split(nameWithoutExt, "-")
				if len(parts) >= 3 {
					// New format: pkgname-version-revision
					foundVersion = parts[len(parts)-2]
					foundRevision = parts[len(parts)-1]
				} else if len(parts) >= 2 {
					// Old format: pkgname-version (revision defaults to "1")
					foundVersion = parts[len(parts)-1]
					foundRevision = "1"
				}
			}
		}
	}

	return newestTarball, foundVersion, foundRevision
}
