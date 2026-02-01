package hokuto

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gookit/color"
	"github.com/ulikunitz/xz"
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
		{"install, i", "[-g] [-multi] <pkg>", "Install pre-built package(s)"},
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
		{"settings", "", "Manage hokuto configuration interactively"},
		{"init-repos", "", "Initialize repositories"},
		{"upload", "[options] [pkgname...]", "Upload local binaries to R2 and update index"},
		{"depends", "[--reverse] <pkg>", "Show package dependencies or reverse dependencies"},
		{"meta", "pkgname [-e] [-db]", "Show/edit package metadata or generate global DB"},
		{"search", "[query | -tag <tag>]", "Search global package database"},
		{"sync", "", "Manually sync global package database from mirror"},
		{"cross-sync", "", "Identify and build missing native cross packages"},
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

	configPath := ConfigFile
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		configPath = filepath.Join(root, "etc", "hokuto", "hokuto.conf")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		// handle error
	}
	mergeEnvOverrides(cfg)
	initConfig(cfg)

	// Ensure critical directories have correct ownership
	// Skip for 'check' command to avoid nested sudo prompts in builds
	if len(os.Args) > 1 && os.Args[1] != "check" {
		if err := ensureHokutoOwnership(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Ownership check failed: %v\n", err)
		}
	}

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
					// If it's an 'install --remote' command, we skip prepareVersionedPackage
					// because we want to resolve the version from the remote index, not Git.
					isRemoteInstall := false
					if cmd == "install" || cmd == "i" {
						for _, a := range os.Args {
							if a == "--remote" || a == "-remote" {
								isRemoteInstall = true
								break
							}
						}
					}

					if isRemoteInstall {
						continue
					}

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
		if err := authenticateOnce(false); err != nil {
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
		if len(os.Args) >= 3 {
			pkgName := os.Args[2]
			installedDir := filepath.Join(rootDir, "/var/db/hokuto/installed", pkgName)
			logXZPath := filepath.Join(installedDir, "log.xz")

			if _, err := os.Stat(logXZPath); err == nil {
				// Decompress and display
				f, err := os.Open(logXZPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening log: %v\n", err)
					os.Exit(1)
				}
				defer f.Close()

				xr, err := xz.NewReader(f)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating xz reader: %v\n", err)
					os.Exit(1)
				}

				// Pipe to a pager if possible, otherwise dump to stdout
				pager := os.Getenv("PAGER")
				var args []string
				if pager == "" {
					pager = "less"
					args = []string{"-r"}
				} else if pager == "less" {
					args = []string{"-r"}
				}

				cmd := exec.Command(pager, args...)
				cmd.Stdin = xr
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				if err := cmd.Run(); err != nil {
					// Fallback to plain stdout if pager fails
					f.Seek(0, 0)
					xr, _ = xz.NewReader(f)
					io.Copy(os.Stdout, xr)
				}
			} else {
				fmt.Fprintf(os.Stderr, "No build log found for package %s\n", pkgName)
				os.Exit(1)
			}
		} else {
			exitCode = runTUI()
		}

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

	case "settings":
		if err := handleSettingsCommand(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Settings command failed: %v\n", err)
			os.Exit(1)
		}

	case "init-repos":
		if err := handleInitReposCommand(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Repository initialization failed: %v\n", err)
			os.Exit(1)
		}

	case "upload":
		if err := handleUploadCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Upload failed: %v\n", err)
			os.Exit(1)
		}

	case "keys":
		if err := handleKeysCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Keys command failed: %v\n", err)
			os.Exit(1)
		}

	case "sign-file":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto sign-file <path>")
			os.Exit(1)
		}
		if err := handleSignFileCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Sign-file failed: %v\n", err)
			os.Exit(1)
		}

	case "depends":
		if err := handleDependsCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Depends command failed: %v\n", err)
			os.Exit(1)
		}

	case "cross-sync":
		if err := handleCrossSyncCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Cross-sync failed: %v\n", err)
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
		lsCmd := flag.NewFlagSet("list", flag.ExitOnError)
		var remote = lsCmd.Bool("remote", false, "List packages from the remote repository.")
		if err := lsCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ls flags: %v\n", err)
			os.Exit(1)
		}

		pkg := ""
		if lsCmd.NArg() > 0 {
			pkg = lsCmd.Arg(0)
		}

		if *remote {
			if err := listRemotePackages(pkg, cfg); err != nil {
				fmt.Fprintln(os.Stderr, "Error listing remote packages:", err)
				exitCode = 1
			}
		} else {
			if err := listPackages(pkg); err != nil {
				// If it's the "not found" error, the friendly message was already printed.
				if errors.Is(err, errPackageNotFound) {
					exitCode = 1
				} else {
					fmt.Fprintln(os.Stderr, "Error:", err)
					exitCode = 1
				}
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
		installCmd := flag.NewFlagSet("install", flag.ExitOnError)
		var yes = installCmd.Bool("y", false, "Assume 'yes' to all prompts and overwrite modified files.")
		var yesLong = installCmd.Bool("yes", false, "Assume 'yes' to all prompts and overwrite modified files.")
		var force = installCmd.Bool("force", false, "Install even if package is already installed.")
		var nodeps = installCmd.Bool("nodeps", false, "Ignore dependencies.")
		var genericFlag = installCmd.Bool("generic", false, "Install the generic variant of the package.")
		var genericShortFlag = installCmd.Bool("g", false, "Install the generic variant of the package.")
		var arm64Flag = installCmd.Bool("arm64", false, "Install arm64 version of the package.")
		var x86_64Flag = installCmd.Bool("x86_64", false, "Install x86_64 version of the package.")
		var multiFlag = installCmd.Bool("multi", false, "Install multilib variants of packages that support them.")
		var remote = installCmd.Bool("remote", false, "Install from remote mirror even if not in HOKUTO_PATH.")

		if err := installCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing install flags: %v\n", err)
			os.Exit(1)
		}

		if *genericFlag || *genericShortFlag {
			cfg.Values["HOKUTO_GENERIC"] = "1"
		}

		if *arm64Flag {
			cfg.Values["HOKUTO_ARCH"] = "aarch64"
		}
		if *x86_64Flag {
			cfg.Values["HOKUTO_ARCH"] = "x86_64"
		}

		// Handle multilib flag or HOKUTO_MULTILIB environment variable
		if *multiFlag || cfg.Values["HOKUTO_MULTILIB"] == "1" {
			cfg.Values["HOKUTO_MULTILIB"] = "1"
		}

		var remoteIndex []RepoEntry
		if *remote {
			var err error
			remoteIndex, err = FetchRemoteIndex(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching remote index: %v\n", err)
				os.Exit(1)
			}
		}

		packagesToInstall := installCmd.Args()
		if len(packagesToInstall) == 0 {
			fmt.Println("Usage: hokuto install [options] <tarball|pkgname>")
			installCmd.PrintDefaults()
			os.Exit(1)
		}

		// Ensure 'sauzeros-base' is installed first if missing
		if !checkPackageExactMatch("sauzeros-base") {
			alreadyRequested := slices.Contains(packagesToInstall, "sauzeros-base")
			if !alreadyRequested {
				colArrow.Print("-> ")
				colSuccess.Println("Adding implicit dependency: sauzeros-base")
				// Prepend to ensure it's processed first
				packagesToInstall = append([]string{"sauzeros-base"}, packagesToInstall...)
			}
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
			// Keep package name as-is, but will use multi variant in filename if multilib is enabled
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
				if err := resolveBinaryDependencies(pkgName, visited, &installPlan, false, effectiveYes, cfg, remoteIndex); err != nil {
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
		installPlan = MovePackageToFront(installPlan, "sauzeros-base")

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
					// New format: pkgname-version-revision[-arch-variant]
					// Check if it ends with known variant/arch pattern
					// Common variants: generic, optimized, multilib
					// Common archs: x86_64, aarch64

					isExtendedFormat := false
					if len(parts) >= 5 {
						last := parts[len(parts)-1]
						secondLast := parts[len(parts)-2]

						knownVariants := map[string]bool{"generic": true, "optimized": true, "multilib": true}
						knownArchs := map[string]bool{"x86_64": true, "aarch64": true}

						if knownVariants[last] && knownArchs[secondLast] {
							isExtendedFormat = true
						}
					}

					if isExtendedFormat {
						// Format: pkgname-version-revision-arch-variant
						pkgName = strings.Join(parts[:len(parts)-4], "-")
					} else {
						// Format: pkgname-version-revision
						pkgName = strings.Join(parts[:len(parts)-2], "-")
					}
				}
				if _, err := os.Stat(tarballPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: Tarball not found or inaccessible: %s\n", tarballPath)
					allSucceeded = false
					continue
				}
			} else {
				// Case B: Package Name (Auto-resolved or requested)
				pkgName = arg
				if idx := strings.Index(arg, "@"); idx != -1 {
					pkgName = arg[:idx]
				}
				// Keep package name as-is, but use multi variant in filename if multilib is enabled

				version, revision, err := "", "", error(nil)
				tarballFoundDirectly := false

				// If --remote is used and a version is specified with @, prioritize remote index.
				// This allows installing specific versions that might not be in the local HOKUTO_PATH.
				if *remote && strings.Contains(arg, "@") {
					rv, rr, rerr := GetRemotePackageVersion(arg, cfg, remoteIndex)
					if rerr == nil {
						version = rv
						revision = rr
						err = nil
					} else {
						// Fallback to local repo if remote doesn't have it (might be a local-only package)
						version, revision, err = getRepoVersion2(arg)
					}
				} else {
					version, revision, err = getRepoVersion2(arg)
					// If --remote is used and local lookup failed, try remote index
					if err != nil && *remote {
						rv, rr, rerr := GetRemotePackageVersion(arg, cfg, remoteIndex)
						if rerr == nil {
							version = rv
							revision = rr
							err = nil
						}
					}
				}

				if err != nil {
					// If source not found (e.g., renamed cross-system packages), try to find tarball
					if strings.Contains(err.Error(), "not found") {
						// Try to find the newest tarball matching this package name with appropriate variant
						variant := GetSystemVariantForPackage(cfg, pkgName)
						foundTarball, foundVersion, foundRevision := findNewestTarball(pkgName, variant)
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
					arch := GetSystemArchForPackage(cfg, pkgName)
					variant := GetSystemVariantForPackage(cfg, pkgName)
					tarballPath = filepath.Join(BinDir, StandardizeRemoteName(pkgName, version, revision, arch, variant))
				}

				// 1. Check Local Cache (skip if we already found the tarball directly)
				if !tarballFoundDirectly {
					if _, err := os.Stat(tarballPath); err != nil {
						foundOnMirror := false

						// 2. Not in local cache? Try Mirror.
						if BinaryMirror != "" {
							if err := fetchBinaryPackage(pkgName, version, revision, cfg, false); err == nil {
								foundOnMirror = true
							} else {
								debugf("Mirror fetch failed for %s: %v\n", pkgName, err)

								// 2a. FALLBACK: Try generic if optimized failed
								variant := GetSystemVariantForPackage(cfg, pkgName)
								if !strings.Contains(variant, "generic") {
									fallbackVariant := "generic"
									if strings.HasPrefix(variant, "multi-") {
										fallbackVariant = "multi-generic"
									}
									colArrow.Print("-> ")
									cPrintf(colInfo, "Optimized binary not found, trying fallback: %s\n", fallbackVariant)
									// Temporarily override HOKUTO_GENERIC for this lookup
									oldGeneric := cfg.Values["HOKUTO_GENERIC"]
									cfg.Values["HOKUTO_GENERIC"] = "1"

									if err := fetchBinaryPackage(pkgName, version, revision, cfg, false); err == nil {
										foundOnMirror = true
										// Update tarballPath for installation
										arch := GetSystemArchForPackage(cfg, pkgName)
										tarballPath = filepath.Join(BinDir, StandardizeRemoteName(pkgName, version, revision, arch, fallbackVariant))
									}

									cfg.Values["HOKUTO_GENERIC"] = oldGeneric
								}

								// 2b. FALLBACK: Try multi-lib variants if standard failed
								if !foundOnMirror && isMultilibPackage(pkgName) && cfg.Values["HOKUTO_MULTILIB"] != "1" {
									cPrintf(colInfo, "Standard binary not found, trying fallback: multi-lib\n")

									oldMulti := cfg.Values["HOKUTO_MULTILIB"]
									cfg.Values["HOKUTO_MULTILIB"] = "1"

									// Try multi-optimized (default for multilib=1)
									if err := fetchBinaryPackage(pkgName, version, revision, cfg, false); err == nil {
										foundOnMirror = true
										arch := GetSystemArchForPackage(cfg, pkgName)
										variant := GetSystemVariantForPackage(cfg, pkgName)
										tarballPath = filepath.Join(BinDir, StandardizeRemoteName(pkgName, version, revision, arch, variant))
									} else {
										// Try multi-generic
										oldGeneric := cfg.Values["HOKUTO_GENERIC"]
										if oldGeneric != "1" {
											cfg.Values["HOKUTO_GENERIC"] = "1"
											if err := fetchBinaryPackage(pkgName, version, revision, cfg, false); err == nil {
												foundOnMirror = true
												arch := GetSystemArchForPackage(cfg, pkgName)
												variant := GetSystemVariantForPackage(cfg, pkgName)
												tarballPath = filepath.Join(BinDir, StandardizeRemoteName(pkgName, version, revision, arch, variant))
											}
											cfg.Values["HOKUTO_GENERIC"] = oldGeneric
										}
									}
									cfg.Values["HOKUTO_MULTILIB"] = oldMulti
								}
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

			handlePreInstallUninstall(pkgName, cfg, RootExec, false)

			colArrow.Print("-> ")
			colSuccess.Printf("Installing:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, len(installPlan))

			if err := pkgInstall(tarballPath, pkgName, cfg, RootExec, effectiveYes, nil); err != nil {
				fmt.Fprintln(os.Stderr,
					colArrow.Sprint("->"),
					colSuccess.Sprintf("Error installing package"),
					colNote.Sprintf(" %s", pkgName),
					fmt.Sprintf("%v", err),
				)
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
			colSuccess.Printf("Package ")
			colNote.Printf("%s", pkgName)
			colSuccess.Printf(" installed successfully.\n")
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
		// Preprocess arguments to handle custom flag formats (e.g. -j4)
		args := PreprocessBuildArgs(os.Args[2:])

		// Use a proper FlagSet to parse arguments and set buildPriority
		updateCmd := flag.NewFlagSet("update", flag.ExitOnError)
		var idleBuild = updateCmd.Bool("i", false, "Use half CPU cores and lowest niceness for build process.")
		var superidleBuild = updateCmd.Bool("ii", false, "Use one CPU core and lowest niceness for build process.")
		var verbose = updateCmd.Bool("v", false, "Enable verbose output.")
		var parallel = updateCmd.Int("j", 1, "Number of parallel jobs (default: 1)")
		// Add long flags for consistency
		var idleBuildLong = updateCmd.Bool("idle", false, "Use half CPU cores and lowest niceness for build process.")
		var superidleBuildLong = updateCmd.Bool("superidle", false, "Use one CPU core and lowest niceness for build process.")
		var parallelLong = updateCmd.Int("parallel", 1, "Number of parallel jobs (default: 1)")

		var verboseLong = updateCmd.Bool("verbose", false, "Enable verbose output.")
		var remote = updateCmd.Bool("remote", false, "Check for updates from remote binary mirror only.")

		if err := updateCmd.Parse(args); err != nil {
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

		if *remote {
			if err := checkForRemoteUpgrades(ctx, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "Remote upgrade process failed: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0) // Exit after remote update
		}

		updateRepos()

		if err := PostInstallTasks(RootExec, nil); err != nil {
			fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
		}

		// Determine max jobs
		maxJobs := *parallel
		if *parallelLong > maxJobs {
			maxJobs = *parallelLong
		}

		if err := checkForUpgrades(ctx, cfg, maxJobs); err != nil {
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
		var fromArch = newCmd.Bool("from-arch", false, "Import package from Arch Linux official repos")
		var fromAUR = newCmd.Bool("from-aur", false, "Import package from AUR")
		if err := newCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing new flags: %v\n", err)
			os.Exit(1)
		}
		args := newCmd.Args()
		if len(args) < 1 {
			fmt.Println("Usage: hokuto new [-here] [--from-arch | --from-aur] <pkgname>")
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

		// Handle import from Arch/AUR
		if *fromArch || *fromAUR {
			source := "Arch"
			if *fromAUR {
				source = "AUR"
			}

			// Try exact match first
			if err := generatePackageFromArch(pkg, source, targetDir); err != nil {
				// If exact match fails, try fuzzy search
				colWarn.Printf("Exact match failed: %v\n", err)
				colArrow.Print("-> ")
				colNote.Println("Searching for similar packages...")

				candidates, searchErr := searchMetadata(pkg)
				if searchErr != nil || len(candidates) == 0 {
					fmt.Fprintf(os.Stderr, "Error: No packages found matching '%s'\n", pkg)
					os.Exit(1)
				}

				// Filter candidates by source if specified
				var filtered []MetadataCandidate
				for _, c := range candidates {
					if (*fromArch && c.Source == "Arch") || (*fromAUR && c.Source == "AUR") || (!*fromArch && !*fromAUR) {
						filtered = append(filtered, c)
					}
				}

				if len(filtered) == 0 {
					fmt.Fprintf(os.Stderr, "Error: No packages found in %s matching '%s'\n", source, pkg)
					os.Exit(1)
				}

				selected := promptSelection(filtered)
				if selected == nil {
					fmt.Println("Package creation cancelled.")
					os.Exit(0)
				}

				// Try again with selected package
				if err := generatePackageFromArch(selected.Name, selected.Source, targetDir); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			// Original behavior - create empty skeleton
			if err := newPackage(pkg, targetDir); err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
				os.Exit(1)
			}
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

	case "meta":
		if err := HandleMetaCommand(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Meta command failed: %v\n", err)
			os.Exit(1)
		}

	case "sync":
		if err := SyncPkgDB(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
			os.Exit(1)
		}

	case "search":
		if err := SearchPkgDB(os.Args[2:], cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Search failed: %v\n", err)
			os.Exit(1)
		}

	default:
		printHelp()
		exitCode = 1
	}
	os.Exit(exitCode)
}

// findNewestTarball finds the newest tarball matching the package name and variant pattern
// Returns (tarballPath, version, revision) or ("", "", "") if not found
func findNewestTarball(pkgName, variant string) (string, string, string) {
	// All packages are now stored directly in BinDir
	binDirs := []string{BinDir}

	var newestTarball string
	var newestModTime time.Time
	var foundVersion, foundRevision string

	for _, binDir := range binDirs {
		// Pattern: pkgname-ver-rev-arch-variant.tar.zst
		pattern := filepath.Join(binDir, fmt.Sprintf("%s-*-*-*-%s.tar.zst", pkgName, variant))
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
				// Parse version and revision from filename
				// Standardized format: name-version-revision-arch-variant.tar.zst
				base := filepath.Base(match)
				nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")
				parts := strings.Split(nameWithoutExt, "-")

				// We expect at least 5 parts for the new format: name, version, revision, arch, variant
				if len(parts) >= 5 {
					// Search for version and revision. They are at index len-4 and len-3.
					// But name can contain dashes. So we count from the end.
					v := parts[len(parts)-4]
					r := parts[len(parts)-3]

					newestTarball = match
					newestModTime = info.ModTime()
					foundVersion = v
					foundRevision = r
				} else if len(parts) >= 3 {
					// Fallback for transitional format: name-version-revision
					v := parts[len(parts)-2]
					r := parts[len(parts)-1]

					newestTarball = match
					newestModTime = info.ModTime()
					foundVersion = v
					foundRevision = r
				}
			}
		}
	}

	return newestTarball, foundVersion, foundRevision
}

func handleKeysCommand(args []string, cfg *Config) error {
	keysCmd := flag.NewFlagSet("keys", flag.ContinueOnError)
	var sync = keysCmd.Bool("sync", false, "Scan local keys and update remote keyring")
	if err := keysCmd.Parse(args); err != nil {
		return nil
	}
	if *sync {
		return SyncKeyring(context.Background(), cfg)
	}

	keyring, err := FetchKeyring(cfg)
	if err != nil {
		return err
	}
	colSuccess.Println("Trusted Public Keys (Keyring):")
	for _, e := range keyring {
		colNote.Printf("  %-15s ", e.ID)
		fmt.Printf("%s\n", e.Pub)
	}
	return nil
}

func handleSignFileCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing file path")
	}
	path := args[0]

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	priv, err := PromptForMasterPrivateKey()
	if err != nil {
		return err
	}

	sig := SignData(data, priv)
	sigHex := hex.EncodeToString(sig)

	sigPath := path + ".sig"
	if err := os.WriteFile(sigPath, []byte(sigHex), 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}
	colArrow.Printf("-> ")
	colSuccess.Printf("Signature written to %s\n", sigPath)
	return nil
}

func handleDependsCommand(args []string, cfg *Config) error {
	dependsCmd := flag.NewFlagSet("depends", flag.ContinueOnError)
	reverse := dependsCmd.Bool("reverse", false, "Show reverse dependencies")
	dependsCmd.BoolVar(reverse, "r", false, "Show reverse dependencies (shorthand)")

	if err := dependsCmd.Parse(args); err != nil {
		return err
	}

	remaining := dependsCmd.Args()
	if len(remaining) < 1 {
		return fmt.Errorf("missing package name")
	}

	pkgName := remaining[0]
	return ShowPackageDependencies(pkgName, *reverse, cfg)
}
