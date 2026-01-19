package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
	"github.com/ulikunitz/xz"
)

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
		if strings.HasPrefix(flag, "-march=x86-64") || strings.HasPrefix(flag, "-march=x86_64") {
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
	if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" && cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		// Rename package for cross-system builds: aarch64-pkgname
		normalizedArch := cfg.Values["HOKUTO_CROSS_ARCH"]
		if normalizedArch == "arm64" {
			normalizedArch = "aarch64"
		}
		return normalizedArch + "-" + pkgName
	}
	return pkgName
}

func pkgBuild(pkgName string, cfg *Config, execCtx *Executor, bootstrap bool, currentIndex int, totalCount int) (time.Duration, error) {

	// Define the ANSI escape code format for setting the terminal title.
	// \033]0; sets the title, and \a (bell character) terminates the sequence.
	const setTitleFormat = "\033]0;%s\a"
	debugf("INFO RUNNING pkgBuild function")

	// Helper function to set the title in the TTY.
	setTerminalTitle := func(title string) {
		//	// Outputting directly to os.Stdout sets the title in the terminal session.
		fmt.Printf(setTitleFormat, title)
	}

	// Track build time
	startTime := time.Now()

	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return 0, fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
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
		colArrow.Print("-> ")
		colWarn.Println(err)
		colWarn.Println("Permitting build, but installation will be blocked.")
	}

	// Special handling: Uninstall python before building/updating if it's already installed
	if pkgName == "python" && isPackageInstalled("python") {
		colArrow.Print("-> ")
		colWarn.Printf("Uninstalling python to ensure Pip is built\n")
		// Use force=true and yes=true to ensure non-interactive uninstallation
		if err := pkgUninstall("python", cfg, RootExec, true, true); err != nil {
			// This is a warning, not fatal - continue with build even if uninstall fails
			debugf("Warning: failed to uninstall python before build: %v\n", err)
		} else {
			debugf("Successfully uninstalled python before build.\n")
		}
	}

	// 1. Initialize a LOCAL temporary directory variable with the global default.
	currentTmpDir := tmpDir
	// override tmpDir if noram is set
	tmpDirfile := filepath.Join(pkgDir, "noram")
	if _, err := os.Stat(tmpDirfile); err == nil {
		currentTmpDir = cfg.Values["TMPDIR2"]
	}

	// set tmpdirs for build
	pkgTmpDir := filepath.Join(currentTmpDir, pkgName)
	logDir := filepath.Join(pkgTmpDir, "log")
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")

	// First try to cleanup pkgTmpDir with Go's os.RemoveAll
	if err := os.RemoveAll(pkgTmpDir); err != nil {
		// If that fails, fall back to system rm -rf with rootExec
		rmCmd := exec.Command("rm", "-rf", pkgTmpDir)
		if err2 := RootExec.Run(rmCmd); err2 != nil {
			return 0, fmt.Errorf("failed to clean pkgTmpDir %s: %v (fallback also failed: %v)", pkgTmpDir, err, err2)
		}
	}

	// Rereate build/output dirs (non-root, inside TMPDIR)
	for _, dir := range []string{buildDir, outputDir, logDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

	// 1. Determine the Execution Context for THIS PACKAGE.
	// This check MUST stay here as it is package-specific.
	asRootFile := filepath.Join(pkgDir, "asroot")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}

	//Check for an 'interactive' file to control build mode ---
	interactiveFile := filepath.Join(pkgDir, "interactive")
	needsInteractiveBuild := false
	if _, err := os.Stat(interactiveFile); err == nil {
		needsInteractiveBuild = true
		debugf("Local 'interactive' file found in %s. Enabling interactive build mode.\n", pkgDir)
	}

	// 2. CLONE AND SELECT EXECUTOR
	// Create a new Executor instance for the build phase.
	buildExec := &Executor{
		Context:         execCtx.Context,       // Inherit the main cancellation context
		ShouldRunAsRoot: needsRootBuild,        // Set the privilege based on 'asroot' file
		Interactive:     needsInteractiveBuild, // SET INTERACTIVE MODE
	}
	// Fetch all sources for the build, including git repositories.
	if err := fetchSources(pkgName, pkgDir, true); err != nil {
		return 0, fmt.Errorf("failed to fetch sources: %v", err)
	}

	// Perform checksum verification.
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false); err != nil {
		return 0, fmt.Errorf("source verification failed: %w", err)
	}

	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return 0, fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	noStripFile := filepath.Join(pkgDir, "nostrip")
	if _, err := os.Stat(noStripFile); err == nil {
		colArrow.Print("-> ")
		colSuccess.Printf("Disabling stripping.\n")
		shouldStrip = false // Override the global setting for this package only
	}

	// Check if LTO should be enabled
	shouldLTO := cfg.DefaultLTO
	noLTOFile := filepath.Join(pkgDir, "nolto")
	if _, err := os.Stat(noLTOFile); err == nil {
		colArrow.Print("-> ")
		colSuccess.Printf("Disabling LTO.\n")
		shouldLTO = false // Override the global setting for this package only
	}

	// (Version and revision were already read at the beginning of the function for the lock check)

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return 0, fmt.Errorf("build script not found: %v", err)
	}

	// Define the base C/C++/LD flags
	var defaultCFLAGS = "-O2 -march=x86-64 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// Define core count to use
	var numCores int
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

	// Check for 'clang' file to determine LTOJOBS value
	ltoJobString := fmt.Sprintf("%d", numCores) // Default to core count (for GCC)
	clangFlagFile := filepath.Join(pkgDir, "clang")
	if _, err := os.Stat(clangFlagFile); err == nil {
		// 'clang' file exists, use "auto" for LTO jobs
		ltoJobString = "auto"
		debugf("Local 'clang' file found. Setting LTOJOBS=auto.\n")
	} else {
		// No 'clang' file, use core count
		debugf("No 'clang' file found. Setting LTOJOBS=%s.\n", ltoJobString)
	}

	// Build environment
	// Start with environment, but filter out CFLAGS/CXXFLAGS/LDFLAGS to avoid conflicts
	// Our defaults should take precedence
	env := []string{}
	for _, e := range os.Environ() {
		// Skip CFLAGS, CXXFLAGS, and LDFLAGS from environment - we'll set them from defaults
		if strings.HasPrefix(e, "CFLAGS=") || strings.HasPrefix(e, "CXXFLAGS=") || strings.HasPrefix(e, "LDFLAGS=") {
			continue
		}
		env = append(env, e)
	}
	var defaults = map[string]string{}

	if bootstrap {
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
			cflags = "-O2 -march=x86-64 -mtune=generic -pipe -fPIC"

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
			"PATH":             filepath.Join(lfsRoot, "tools/bin") + ":/usr/bin:/bin",
			"MAKEFLAGS":        fmt.Sprintf("-j%d", numCores),
			"CONFIG_SITE":      filepath.Join(lfsRoot, "usr/share/config.site"),
			"HOKUTO_ROOT":      lfsRoot,
			"TMPDIR":           currentTmpDir,
			"HOKUTO_ARCH":      targetArch,
			"HOKUTO_BUILD_DIR": buildDir,
			"GNU_MIRROR":       cfg.Values["GNU_MIRROR"],
			"SET_HOKUTO_LTO":   cfg.Values["SET_HOKUTO_LTO"],
			"MULTILIB":         multilibVal,
		}

		if cfg.Values["HOKUTO_GENERIC"] == "1" {
			defaults["HOKUTO_GENERIC"] = "1"
		}

	} else {

		// 1. Detect Architecture
		// ----------------------
		targetArch := cfg.Values["HOKUTO_ARCH"]
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

		// Check if generic build is enabled (BinDir contains "/generic")
		isGeneric := strings.Contains(BinDir, "/generic")

		if isGeneric {
			// Generic build: use CFLAGS_GEN and CFLAGS_GEN_LTO
			if shouldLTO {
				// Case: Generic with LTO
				cflagsVal = cfg.Values["CFLAGS_GEN_LTO"]
				cxxflagsVal = cfg.Values["CXXFLAGS_GEN_LTO"]
				ldflagsVal = cfg.Values["LDFLAGS_LTO"]
			} else {
				// Case: Generic without LTO
				cflagsVal = cfg.Values["CFLAGS_GEN"]
				cxxflagsVal = cfg.Values["CXXFLAGS_GEN"]
				ldflagsVal = cfg.Values["LDFLAGS"]
			}
		} else if isCross {
			// Case: Cross-compilation
			// Use generic flags to ensure compatibility with host compiler
			cflagsVal = "-O2 -pipe -mtune=generic"
			cxxflagsVal = "-O2 -pipe -mtune=generic"
			ldflagsVal = cfg.Values["LDFLAGS"]
		} else if isARM {
			// Case A: Native ARM64 build ONLY
			// We only use CFLAGS_ARM64 (which might have -mcpu=native etc) if we are actually building ON ARM
			// and NOT doing a cross-compile.
			cflagsVal = cfg.Values["CFLAGS_ARM64"]
			cxxflagsVal = cfg.Values["CXXFLAGS_ARM64"]
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

		// --- Normal build environment---
		defaults = map[string]string{
			"AR":                         "gcc-ar",
			"CC":                         "cc",
			"CXX":                        "c++",
			"NM":                         "gcc-nm",
			"RANLIB":                     "gcc-ranlib",
			"CFLAGS":                     cflagsVal,
			"CXXFLAGS":                   cxxflagsVal,
			"LDFLAGS":                    ldflagsVal,
			"MAKEFLAGS":                  fmt.Sprintf("-j%d", numCores),
			"CMAKE_BUILD_PARALLEL_LEVEL": fmt.Sprintf("%d", numCores),
			"RUSTFLAGS":                  fmt.Sprintf("--remap-path-prefix=%s=.", buildDir),
			"GOFLAGS":                    "-trimpath -modcacherw",
			"GOPATH":                     filepath.Join(buildDir, "go"),
			"HOKUTO_ROOT":                cfg.Values["HOKUTO_ROOT"],
			"TMPDIR":                     currentTmpDir,
			"CONFIG_SITE":                ("/usr/share/config.site"),
			"HOKUTO_ARCH":                targetArch,
			"MULTILIB":                   multilibVal,
			"HOKUTO_BUILD_DIR":           buildDir,
			"GNU_MIRROR":                 cfg.Values["GNU_MIRROR"],
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

			// Normalize architecture name for toolchain prefix
			normalizedArch := crossArch
			if normalizedArch == "arm64" {
				normalizedArch = "aarch64"
			}

			// Set HOKUTO_ARCH to the normalized architecture for cross-compilation
			defaults["HOKUTO_ARCH"] = normalizedArch

			// Disable MULTILIB for cross-compilation
			defaults["MULTILIB"] = "0"

			// Replace compiler tools with cross-compilation toolchain (unless simple mode)
			if cfg.Values["HOKUTO_CROSS_SIMPLE"] != "1" {
				toolchainPrefix := normalizedArch + "-linux-gnu-"
				defaults["CC"] = toolchainPrefix + "gcc"
				defaults["CXX"] = toolchainPrefix + "g++"
				defaults["AR"] = toolchainPrefix + "ar"
				defaults["RANLIB"] = toolchainPrefix + "ranlib"
			}
			// In simple mode, keep normal compiler/linker settings (already set above)

			// Set CROSS_PREFIX based on system flag
			if cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
				// System cross-compilation: use /usr/<arch>-linux-gnu
				defaults["CROSS_PREFIX"] = fmt.Sprintf("/usr/%s-linux-gnu", normalizedArch)
			} else {
				// Regular cross-compilation: use /usr
				defaults["CROSS_PREFIX"] = "/usr"
			}
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

	// Sort keys for deterministic order
	keys := make([]string, 0, len(defaults))
	for k := range defaults {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var envVarsBuilder strings.Builder
	for _, k := range keys {
		v := defaults[k]
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
			cmd = exec.Command("script", "-q", "-f", "-c", cmdStr, logPath)
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
			logFile, err = os.Create(logPath)
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
						title := fmt.Sprintf("Building: %s (%d/%d) elapsed: %s", pkgName, currentIndex, totalCount, elapsed)
						setTerminalTitle(title)
						// Only print elapsed time to console if not in verbose mode
						// In verbose mode, the build output is already visible, so we only update the title
						if !Verbose {
							colArrow.Print("-> ")
							colSuccess.Printf("Building %s elapsed: %s\r", pkgName, elapsed)
						}

					case <-doneCh:
						fmt.Print("\r")
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
		colArrow.Print("-> ")
		color.Danger.Printf("Build failed for %s: %v\n", pkgName, runErr)
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

	// Determine output package name (rename if cross-system is enabled)
	outputPkgName := getOutputPackageName(pkgName, cfg)

	// Create /var/db/hokuto/installed/<outputPkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", outputPkgName)
	debugf("Creating metadata directory: %s\n", installedDir)
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := buildExec.Run(mkdirCmd); err != nil {
		return 0, fmt.Errorf("failed to create installed dir: %v", err)
	}

	// Generate libdeps
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if err := generateLibDeps(outputDir, libdepsFile, buildExec); err != nil {
		fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
	} else {
		debugf("Library dependencies written to %s\n", libdepsFile)
	}

	// Generate depends (use outputPkgName for cross-system builds)
	if err := generateDepends(outputPkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
		return 0, fmt.Errorf("failed to generate depends: %v", err)
	}
	debugf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	debugf("%s built successfully, output in %s\n", pkgName, outputDir)

	// Strip the package
	if shouldStrip {
		// NOTE: stripPackage uses buildExec (UserExec) to run the external 'strip' command
		if err := stripPackage(outputDir, buildExec); err != nil {
			// Treat strip failure as a build failure (or a warning, depending on policy)
			return 0, fmt.Errorf("build failed during stripping phase for %s: %w", pkgName, err)
		}
	} else {
		debugf("Skipping binary stripping for %s (NoStrip is true).\n", pkgName)
	}

	// Copy version file from pkgDir
	versionSrc := filepath.Join(pkgDir, "version")
	versionDst := filepath.Join(installedDir, "version")
	cpCmd := exec.Command("cp", "--remove-destination", versionSrc, versionDst)
	if err := buildExec.Run(cpCmd); err != nil {
		return 0, fmt.Errorf("failed to copy version file: %v", err)
	}

	// Copy build file from pkgDir
	buildSrc := filepath.Join(pkgDir, "build")
	buildDst := filepath.Join(installedDir, "build")
	cpbCmd := exec.Command("cp", "--remove-destination", buildSrc, buildDst)
	if err := buildExec.Run(cpbCmd); err != nil {
		return 0, fmt.Errorf("failed to copy build file: %v", err)
	}

	// Copy post-install file from pkgDir if it exists
	postinstallSrc := filepath.Join(pkgDir, "post-install")
	postinstallDst := filepath.Join(installedDir, "post-install")

	if fi, err := os.Stat(postinstallSrc); err == nil && !fi.IsDir() {
		// ensure installedDir exists
		if err := os.MkdirAll(filepath.Dir(postinstallDst), 0o755); err != nil {
			return 0, fmt.Errorf("failed to create installed dir: %v", err)
		}

		cpCmd := exec.Command("cp", "--remove-destination", postinstallSrc, postinstallDst)
		if err := buildExec.Run(cpCmd); err != nil {
			return 0, fmt.Errorf("failed to copy post-install file: %v", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("failed to stat post-install file: %v", err)
	}

	// Add asroot file to package metadata if the package was built as root
	if buildExec.ShouldRunAsRoot {
		asRootFile := filepath.Join(installedDir, "asroot")
		touchCmd := exec.Command("touch", asRootFile)
		if err := buildExec.Run(touchCmd); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create asroot marker file %s: %v\n", asRootFile, err)
		}
		debugf("Added asroot marker file to package metadata (package built as root)\n")
	}

	// Calculate the elapsed time
	elapsed = time.Since(startTime)

	// Format the duration into a string (e.g., "1m30.5s")
	durationStr := fmt.Sprintf("%v", elapsed)

	// Define the output file path
	buildTimeFile := filepath.Join(installedDir, "buildtime")

	// Save the duration to the file silently using 'echo' and 'tee' via the Executor.
	echoCmd := exec.Command("sh", "-c",
		// The shell command is wrapped with '> /dev/null 2>&1' to redirect all output to null.
		fmt.Sprintf("echo '%s' | tee %s > /dev/null 2>&1", durationStr, buildTimeFile))

	// We use the same Executor context that was used for the build directory creation
	if err := buildExec.Run(echoCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save build time to %s: %v\n", buildTimeFile, err)
	}

	// delete /usr/share/info/dir
	infodirPath := filepath.Join(outputDir, "/usr/share/info/dir")
	infoRmCmd := exec.Command("rm", "-rf", infodirPath)
	if err := buildExec.Run(infoRmCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to delete /usr/share/info/dir: %v\n", err)
	}

	// delete /usr/lib/perl5/*/core_perl/perllocal.pod
	// Check both /lib/perl5 and /usr/lib/perl5 locations
	perllocalPatterns := []string{
		filepath.Join(outputDir, "lib", "perl5", "*", "core_perl", "perllocal.pod"),
		filepath.Join(outputDir, "usr", "lib", "perl5", "*", "core_perl", "perllocal.pod"),
	}

	var matches []string
	for _, p := range perllocalPatterns {
		m, err := filepath.Glob(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to glob for perllocal.pod pattern %s: %v\n", p, err)
			continue
		}
		matches = append(matches, m...)
	}
	if len(matches) > 0 {
		// Prepare the command arguments: ["rm", "-f"] followed by all file paths
		rmArgs := []string{"rm", "-f"}
		rmArgs = append(rmArgs, matches...)

		// The "rm" command is run against all gathered paths
		perlRmCmd := exec.Command(rmArgs[0], rmArgs[1:]...)

		if err := buildExec.Run(perlRmCmd); err != nil {
			// Note: rm -f will not return an error if the files were not found,
			// but it will if permission is denied, or other fatal errors occur.
			fmt.Fprintf(os.Stderr, "Warning: failed to delete perllocal.pod files: %v\n", err)
		}
	}

	// delete non-en locales in /usr/share/locale
	localePattern := filepath.Join(outputDir, "usr", "share", "locale", "*")
	if localeMatches, err := filepath.Glob(localePattern); err == nil {
		for _, path := range localeMatches {
			base := filepath.Base(path)
			if !strings.HasPrefix(base, "en") {
				rmCmd := exec.Command("rm", "-rf", path)
				if err := buildExec.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to delete locale %s: %v\n", base, err)
				}
			}
		}
	}

	// Determine architecture and flags for metadata
	targetArch := defaults["HOKUTO_ARCH"]
	cflagsVal := defaults["CFLAGS"]
	isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1"

	// 1. Generate pkginfo (before manifest) so it's included in the manifest
	if err := WritePackageInfo(outputDir, outputPkgName, version, revision, targetArch, cflagsVal, isGeneric); err != nil {
		return 0, fmt.Errorf("failed to write pkginfo: %v", err)
	}

	// 2. Generate manifest (includes pkginfo and itself)
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return 0, fmt.Errorf("failed to generate manifest: %v", err)
	}

	// 3. Sign the package metadata and manifest
	if err := SignPackage(outputDir, outputPkgName, buildExec); err != nil {
		return 0, fmt.Errorf("failed to sign package: %v", err)
	}

	// Generate package archive (using output package name if cross-system is enabled)
	if err := createPackageTarball(outputPkgName, version, revision, outputDir, buildExec); err != nil {
		return 0, fmt.Errorf("failed to package tarball: %v", err)
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
	return time.Since(startTime), nil

}

// pkgBuildRebuild is used after an uninstall/upgrade to rebuild dependent packages.
// It skips tarball creation, cleanup, and runs with an adjusted environment.
// oldLibsDir is the path to the temporary directory containing backed-up libraries.

func pkgBuildRebuild(pkgName string, cfg *Config, execCtx *Executor, oldLibsDir string) error {

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

	// Determine package source directory (Same as pkgBuild)
	paths := strings.Split(repoPaths, ":")
	var pkgDir string
	found := false
	for _, repo := range paths {
		tryPath := filepath.Join(repo, pkgName)
		if info, err := os.Stat(tryPath); err == nil && info.IsDir() {
			pkgDir = tryPath
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("package %s not found in HOKUTO_PATH", pkgName)
	}

	// 1. Initialize a LOCAL temporary directory variable with the global default.
	currentTmpDir := tmpDir
	// override tmpDir if noram is set
	tmpDirfile := filepath.Join(pkgDir, "noram")
	if _, err := os.Stat(tmpDirfile); err == nil {
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
	asRootFile := filepath.Join(pkgDir, "asroot")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}

	//Check for an 'interactive' file to control build mode ---
	interactiveFile := filepath.Join(pkgDir, "interactive")
	needsInteractiveBuild := false
	if _, err := os.Stat(interactiveFile); err == nil {
		needsInteractiveBuild = true
		debugf("Local 'interactive' file found in %s. Enabling interactive build mode.\n", pkgDir)
	}

	buildExec := &Executor{
		Context:         execCtx.Context,
		ShouldRunAsRoot: needsRootBuild,
		Interactive:     needsInteractiveBuild,
	}

	// Fetch all sources for the build, including git repositories.
	if err := fetchSources(pkgName, pkgDir, true); err != nil {
		return fmt.Errorf("failed to fetch sources: %v", err)
	}

	// Perform a strict, non-interactive checksum verification.
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false); err != nil {
		return fmt.Errorf("source verification failed: %w", err)
	}
	// Prepare sources
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	noStripFile := filepath.Join(pkgDir, "nostrip")
	if _, err := os.Stat(noStripFile); err == nil {
		cPrintf(colInfo, "Local 'nostrip' file found in %s. Disabling stripping.\n", pkgDir)
		shouldStrip = false // Override the global setting for this package only
	}

	// Check if LTO should be enabled
	shouldLTO := cfg.DefaultLTO
	noLTOFile := filepath.Join(pkgDir, "nolto")
	if _, err := os.Stat(noLTOFile); err == nil {
		cPrintf(colInfo, "Local 'nolto' file found in %s. Disabling LTO.\n", pkgDir)
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
	var defaultCFLAGS = "-O2 -march=x86-64 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// Define core count to use
	var numCores int
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

	// Check for 'clang' file to determine LTOJOBS value
	ltoJobString := fmt.Sprintf("%d", numCores) // Default to core count (for GCC)
	clangFlagFile := filepath.Join(pkgDir, "clang")
	if _, err := os.Stat(clangFlagFile); err == nil {
		ltoJobString = "auto"
		debugf("Local 'clang' file found. Setting LTOJOBS=auto.\n")
	} else {
		debugf("No 'clang' file found. Setting LTOJOBS=%s.\n", ltoJobString)
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
		"RUSTFLAGS":                  fmt.Sprintf("--remap-path-prefix=%s=.", buildDir),
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

	// 1. Detect Architecture
	// ----------------------
	targetArch := cfg.Values["HOKUTO_ARCH"]
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

	multilibVal := "0"
	if isX86 && cfg.Values["HOKUTO_MULTILIB"] == "1" {
		multilibVal = "1"
	} else if cfg.Values["HOKUTO_MULTILIB"] == "1" {
		debugf("Disabling MULTILIB for %s architecture (rebuild).\n", targetArch)
	}

	// 3. Select Compiler Flags
	var cflagsVal, cxxflagsVal, ldflagsVal string

	// Check if cross-compilation is enabled
	isCross := cfg.Values["HOKUTO_CROSS_ARCH"] != ""

	if isCross || isARM {
		// Case A: ARM64 (either native ARM64 or cross-compiling to ARM64)
		cflagsVal = cfg.Values["CFLAGS_ARM64"]
		cxxflagsVal = cfg.Values["CXXFLAGS_ARM64"]
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
	// --- END REFACTORED FLAG LOGIC ---

	// Prepare Environment Array
	// Start with environment, but filter out CFLAGS/CXXFLAGS/LDFLAGS to avoid conflicts
	// Our defaults should take precedence
	env := []string{}
	for _, e := range os.Environ() {
		// Skip CFLAGS, CXXFLAGS, and LDFLAGS from environment - we'll set them from defaults
		if strings.HasPrefix(e, "CFLAGS=") || strings.HasPrefix(e, "CXXFLAGS=") || strings.HasPrefix(e, "LDFLAGS=") {
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
	newPath := fmt.Sprintf("PATH=%s:%s:%s", oldLibBin, oldLibUsrBin, currentPath)
	env = append(env, newPath)

	// Update LD_LIBRARY_PATH
	currentLdLibPath := os.Getenv("LD_LIBRARY_PATH")
	newLdLibPath := fmt.Sprintf("LD_LIBRARY_PATH=%s:%s:%s", oldLibLib, oldLibUsrLib, currentLdLibPath)
	env = append(env, newLdLibPath)

	// 5. Final loop to assemble the environment array
	for k, def := range defaults {
		// Check if the current key should be excluded from being appended.
		// This prevents the build process from overriding the system's PATH
		// or LD_LIBRARY_PATH with an (potentially empty) value from 'defaults'.
		if k == "PATH" || k == "LD_LIBRARY_PATH" {
			continue // Skip appending the variable to respect the system's value
		}

		// Append the build variable and its calculated value.
		env = append(env, fmt.Sprintf("%s=%s", k, def))
	}

	// Run build script
	debugf("Rebuilding %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	// 1. Define the log file path
	logPath := filepath.Join(logDir, "build-log.txt")
	// Ensure logDir exists (already created above, but ensure it's there)
	// script will create the log file itself

	// Use script command to create a PTY, preserving colors and progress bars
	// Build the command string to execute
	cmdStr := fmt.Sprintf("cd %s && %s %s %s %s", buildDir, buildScript, outputDir, version, pkgName)

	// Use script to create PTY and preserve colors
	// -q: quiet mode (don't print script start/end messages)
	// -f: flush output immediately (for real-time viewing)
	// -c: command to run
	// script writes the PTY session to the log file automatically
	// script also outputs to stdout/stderr, which we capture for console
	cmd := exec.Command("script", "-q", "-f", "-c", cmdStr, logPath)
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
					// Only print elapsed time to console if not in verbose mode
					// In verbose mode, the build output is already visible, so we only update the title
					if !Verbose {
						colArrow.Print("-> ")
						colSuccess.Printf("Building %s elapsed: %s\r", pkgName, elapsed)
					}
				case <-doneCh:
					fmt.Print("\r")
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
	outputPkgName := getOutputPackageName(pkgName, cfg)

	// Create /var/db/hokuto/installed/<outputPkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", outputPkgName)
	debugf("Creating metadata directory: %s\n", installedDir)
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := buildExec.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installed dir: %v", err)
	}

	// Generate libdeps
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if err := generateLibDeps(outputDir, libdepsFile, buildExec); err != nil {
		fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
	} else {
		debugf("Library dependencies written to %s\n", libdepsFile)
	}

	// Generate depends (use outputPkgName for cross-system builds)
	if err := generateDepends(outputPkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate depends: %v", err)
	}
	debugf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	debugf("%s built successfully, output in %s\n", pkgName, outputDir)

	// Strip the package
	if shouldStrip {
		// NOTE: stripPackage uses buildExec (UserExec) to run the external 'strip' command
		if err := stripPackage(outputDir, buildExec); err != nil {
			// Treat strip failure as a build failure (or a warning, depending on policy)
			return fmt.Errorf("build failed during stripping phase for %s: %w", pkgName, err)
		}
	} else {
		debugf("Skipping binary stripping for %s (NoStrip is true).\n", pkgName)
	}

	// Copy version file from pkgDir
	versionSrc := filepath.Join(pkgDir, "version")
	versionDst := filepath.Join(installedDir, "version")
	cpCmd := exec.Command("cp", "--remove-destination", versionSrc, versionDst)
	if err := buildExec.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy version file: %v", err)
	}

	// Copy build file from pkgDir
	buildSrc := filepath.Join(pkgDir, "build")
	buildDst := filepath.Join(installedDir, "build")
	cpbCmd := exec.Command("cp", "--remove-destination", buildSrc, buildDst)
	if err := buildExec.Run(cpbCmd); err != nil {
		return fmt.Errorf("failed to copy build file: %v", err)
	}

	// Copy post-install file from pkgDir if it exists
	postinstallSrc := filepath.Join(pkgDir, "post-install")
	postinstallDst := filepath.Join(installedDir, "post-install")

	if fi, err := os.Stat(postinstallSrc); err == nil && !fi.IsDir() {
		// ensure installedDir exists
		if err := os.MkdirAll(filepath.Dir(postinstallDst), 0o755); err != nil {
			return fmt.Errorf("failed to create installed dir: %v", err)
		}

		cpCmd := exec.Command("cp", "--remove-destination", postinstallSrc, postinstallDst)
		if err := buildExec.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to copy post-install file: %v", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat post-install file: %v", err)
	}

	// Add asroot file to package metadata if the package was built as root
	if buildExec.ShouldRunAsRoot {
		asRootFile := filepath.Join(installedDir, "asroot")
		touchCmd := exec.Command("touch", asRootFile)
		if err := buildExec.Run(touchCmd); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create asroot marker file %s: %v\n", asRootFile, err)
		}
		debugf("Added asroot marker file to package metadata (package built as root)\n")
	}

	// Calculate the elapsed time
	elapsed = time.Since(startTime)

	// Format the duration into a string (e.g., "1m30.5s")
	durationStr := fmt.Sprintf("%v", elapsed)

	// Define the output file path
	buildTimeFile := filepath.Join(installedDir, "buildtime")

	// Save the duration to the file silently using 'echo' and 'tee' via the Executor.
	echoCmd := exec.Command("sh", "-c",
		// The shell command is wrapped with '> /dev/null 2>&1' to redirect all output to null.
		fmt.Sprintf("echo '%s' | tee %s > /dev/null 2>&1", durationStr, buildTimeFile))

	// We use the same Executor context that was used for the build directory creation
	if err := buildExec.Run(echoCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save build time to %s: %v\n", buildTimeFile, err)
	}

	// delete /usr/share/info/dir
	infodirPath := filepath.Join(outputDir, "/usr/share/info/dir")
	infoRmCmd := exec.Command("rm", "-rf", infodirPath)
	if err := buildExec.Run(infoRmCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to delete /usr/share/info/dir: %v\n", err)
	}

	// delete /usr/lib/perl5/*/core_perl/perllocal.pod
	// Check both /lib/perl5 and /usr/lib/perl5 locations
	perllocalPatterns := []string{
		filepath.Join(outputDir, "lib", "perl5", "*", "core_perl", "perllocal.pod"),
		filepath.Join(outputDir, "usr", "lib", "perl5", "*", "core_perl", "perllocal.pod"),
	}

	var matches []string
	for _, p := range perllocalPatterns {
		m, err := filepath.Glob(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to glob for perllocal.pod pattern %s: %v\n", p, err)
			continue
		}
		matches = append(matches, m...)
	}
	if len(matches) > 0 {
		// Prepare the command arguments: ["rm", "-f"] followed by all file paths
		rmArgs := []string{"rm", "-f"}
		rmArgs = append(rmArgs, matches...)

		// The "rm" command is run against all gathered paths
		perlRmCmd := exec.Command(rmArgs[0], rmArgs[1:]...)

		if err := buildExec.Run(perlRmCmd); err != nil {
			// Note: rm -f will not return an error if the files were not found,
			// but it will if permission is denied, or other fatal errors occur.
			fmt.Fprintf(os.Stderr, "Warning: failed to delete perllocal.pod files: %v\n", err)
		}
	}

	// delete non-en locales in /usr/share/locale
	localePattern := filepath.Join(outputDir, "usr", "share", "locale", "*")
	if localeMatches, err := filepath.Glob(localePattern); err == nil {
		for _, path := range localeMatches {
			base := filepath.Base(path)
			if !strings.HasPrefix(base, "en") {
				rmCmd := exec.Command("rm", "-rf", path)
				if err := buildExec.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to delete locale %s: %v\n", base, err)
				}
			}
		}
	}

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	// Normalize ownership to root:root if the build was NOT run as root.
	// This ensures that when rsyncStaging copies these files to the root filesystem,
	// they have the correct system ownership.
	if !buildExec.ShouldRunAsRoot {
		debugf("Normalizing ownership of output directory to root:root\n")
		chownCmd := exec.Command("chown", "-R", "0:0", outputDir)
		if err := RootExec.Run(chownCmd); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to normalize ownership of %s: %v\n", outputDir, err)
		}
	}

	// Generate package archive (using output package name if cross-system is enabled)
	// This ensures the binary cache is kept in sync with the rebuild.
	if err := createPackageTarball(outputPkgName, version, revision, outputDir, buildExec); err != nil {
		return fmt.Errorf("failed to package tarball: %v", err)
	}

	//Set title to success status
	finalTitle := fmt.Sprintf("✅ SUCCESS: %s", pkgName)
	setTerminalTitle(finalTitle)

	// Note: We skip cleanup of outputDir here to allow pkgInstall to sync from it.
	return nil
}

// handleBuildCommand orchestrates the entire build process, intelligently selecting the
// correct dependency resolution strategy based on the build mode (normal, bootstrap, or alldeps).
func handleBuildCommand(args []string, cfg *Config) error {
	// --- 1. Flag Parsing & Initial Setup ---
	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	var autoInstall = buildCmd.Bool("a", false, "Automatically install the package(s) after successful build.")
	var idleBuild = buildCmd.Bool("i", false, "Use half CPU cores and lowest niceness for build process.")
	var superidleBuild = buildCmd.Bool("ii", false, "Use one CPU core and lowest niceness for build process.")
	var verbose = buildCmd.Bool("v", false, "Enable verbose output.")
	var verboseLong = buildCmd.Bool("verbose", false, "Enable verbose output.")
	var bootstrap = buildCmd.Bool("bootstrap", false, "Enable bootstrap build mode.")
	var bootstrapDir = buildCmd.String("bootstrap-dir", "", "Specify the bootstrap directory.")
	var allDeps = buildCmd.Bool("alldeps", false, "Force rebuild of all dependencies")
	var withRebuilds = buildCmd.Bool("rebuilds", false, "Enable post-build actions for dependencies marked with 'rebuild'.")
	var withRebuildsShort = buildCmd.Bool("r", false, "Alias for -rebuilds.")
	var orderedBuild = buildCmd.Bool("ordered", false, "Force build order based on the target package's depends file.")
	var genericBuild = buildCmd.Bool("generic", false, "Use _GEN flags and store packages in generic subfolder")
	var crossArch = buildCmd.String("cross", "", "Enable cross-compilation for target architecture (e.g., arm64)")

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

	// Handle generic build flag
	if *genericBuild {
		// Set BinDir to generic subdirectory
		BinDir = CacheDir + "/bin/generic"
		// Ensure directory exists
		if err := os.MkdirAll(BinDir, 0o755); err != nil {
			return fmt.Errorf("failed to create generic bin directory: %v", err)
		}
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

		// Set BinDir to cross subdirectory
		BinDir = CacheDir + "/bin/cross"
		// Ensure directory exists
		if err := os.MkdirAll(BinDir, 0o755); err != nil {
			return fmt.Errorf("failed to create cross bin directory: %v", err)
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
			resp, err := http.Get(url)
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

	packagesToProcess := buildCmd.Args()
	if len(packagesToProcess) == 0 {
		buildCmd.Usage()
		return fmt.Errorf("no packages specified")
	}
	userRequestedMap := make(map[string]bool)
	for _, pkg := range packagesToProcess {
		userRequestedMap[pkg] = true
	}

	// --- SELECT DEPENDENCY STRATEGY and EXECUTE BUILD ---
	var failedBuilds = make(map[string]error)
	var totalElapsedTime time.Duration
	var totalBuildCount int

	// ** STRATEGY 1: Bootstrap or --alldeps mode **
	if *bootstrap || *allDeps {
		colArrow.Print("-> ")
		colSuccess.Println("Using forward-dependency build strategy for bootstrap/--alldeps mode.")
		var fullBuildList []string
		for _, pkgName := range packagesToProcess {
			deps, err := getPackageDependenciesForward(pkgName)
			if err != nil {
				return fmt.Errorf("error resolving forward dependencies for %s: %v", pkgName, err)
			}
			fullBuildList = append(fullBuildList, deps...)
			fullBuildList = append(fullBuildList, pkgName) // Add the target itself
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
			duration, err := pkgBuild(pkgName, cfg, UserExec, *bootstrap, i+1, totalBuildCount)
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
			tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputPkgName, version, revision))
			isCriticalAtomic.Store(1)
			handlePreInstallUninstall(outputPkgName, cfg, RootExec)
			colArrow.Print("-> ")
			colSuccess.Printf("Installing:")
			colNote.Printf(" %s (%d/%d)\n", outputPkgName, i+1, totalBuildCount)
			if installErr := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true); installErr != nil {
				isCriticalAtomic.Store(0)
				failedBuilds[pkgName] = fmt.Errorf("post-build installation failed: %w", installErr)
				break // Fatal error
			}
			// Add to world file
			// Only add if user specifically asked for this package
			if userRequestedMap[pkgName] {
				addToWorld(pkgName)
			}
			isCriticalAtomic.Store(0)
		}

	} else {
		// ** STRATEGY 2: Normal Build Mode **
		colArrow.Print("-> ")
		colSuccess.Println("Discovering all required dependencies")
		masterProcessed := make(map[string]bool)
		var missingDeps []string
		for _, pkgName := range packagesToProcess {
			if err := resolveMissingDeps(pkgName, masterProcessed, &missingDeps, userRequestedMap); err != nil {
				return fmt.Errorf("error resolving dependencies for %s: %v", pkgName, err)
			}
		}
		packagesThatMustBeBuilt := make(map[string]bool)
		for pkg := range userRequestedMap {
			packagesThatMustBeBuilt[pkg] = true
		}

		for _, depPkg := range missingDeps {
			if packagesThatMustBeBuilt[depPkg] {
				continue
			}
			version, revision, err := getRepoVersion2(depPkg)
			if err != nil {
				return fmt.Errorf("error: could not get version for dependency %s: %v", depPkg, err)
			}
			// Use output package name for dependencies too (may be renamed for cross-system)
			outputDepPkg := getOutputPackageName(depPkg, cfg)
			tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputDepPkg, version, revision))
			if _, err := os.Stat(tarballPath); err == nil {
				if askForConfirmation(colInfo, "Dependency '%s' is missing. Use available binary package?", depPkg) {
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputDepPkg, cfg, RootExec)
					if err := pkgInstall(tarballPath, outputDepPkg, cfg, RootExec, false); err != nil {
						isCriticalAtomic.Store(0)
						return fmt.Errorf("fatal error installing binary %s: %v", depPkg, err)
					}
					isCriticalAtomic.Store(0)
				} else {
					packagesThatMustBeBuilt[depPkg] = true
				}
			} else {
				packagesThatMustBeBuilt[depPkg] = true
			}
		}

		if len(packagesThatMustBeBuilt) == 0 {
			fmt.Println("All packages and dependencies are already installed.")
			return nil
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

				plan, err := resolveBuildPlan([]string{pkgName}, userRequestedMap, effectiveRebuilds)
				if err != nil {
					return fmt.Errorf("error generating build plan for '%s': %v", pkgName, err)
				}
				if len(plan.Order) == 0 {
					colSuccess.Printf("Package '%s' is already built and up to date. Skipping.\n\n", pkgName)
					continue
				}

				colInfo.Printf("Build order for this group: %s\n\n", strings.Join(plan.Order, " -> "))

				failedThisGroup, _, elapsedThisGroup := executeBuildPass(plan, pkgName, true, cfg, bootstrap, userRequestedMap)
				totalElapsedTime += elapsedThisGroup
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

			colArrow.Print("-> ")
			colSuccess.Println("Generating Build Plan")
			initialPlan, err := resolveBuildPlan(buildListInput, userRequestedMap, effectiveRebuilds)
			if err != nil {
				return fmt.Errorf("error generating build plan: %v", err)
			}
			if len(initialPlan.Order) == 0 {
				fmt.Println("All packages are up to date. Nothing to build.")
				return nil
			}

			colArrow.Print("-> ")
			colSuccess.Printf("Build Order:")
			colNote.Printf(" %s\n", strings.Join(initialPlan.Order, " -> "))
			if len(initialPlan.Order) > 1 {
				// Prefetch the plan list, skipping the first one which starts immediately
				go prefetchSources(initialPlan.Order[1:])
			}
			if len(initialPlan.PostRebuilds) > 0 {
				var rebuilds []string
				for parent, deps := range initialPlan.PostRebuilds {
					rebuilds = append(rebuilds, fmt.Sprintf("%s (for %s)", parent, strings.Join(deps, ",")))
				}
				sort.Strings(rebuilds)
				colArrow.Print("-> ")
				colWarn.Printf("Packages scheduled for inline rebuild with optional features: %s\n", strings.Join(rebuilds, ", "))
			}

			failedPass1, targetsPass1, elapsedPass1 := executeBuildPass(initialPlan, "Initial Pass", false, cfg, bootstrap, userRequestedMap)
			totalElapsedTime = elapsedPass1
			failedBuilds = failedPass1

			if len(targetsPass1) > 0 {
				// Skip installation prompt and installation for cross-compilation without system flag
				// (cross-compiled packages without system are not meant to be installed on build host)
				isCrossWithoutSystem := cfg.Values["HOKUTO_CROSS_ARCH"] != "" && cfg.Values["HOKUTO_CROSS_SYSTEM"] != "1"

				shouldInstall := *autoInstall
				if !shouldInstall && !isCrossWithoutSystem {
					sort.Strings(targetsPass1)
					// Convert to output package names for display (may be renamed for cross-system)
					outputPkgNames := make([]string, len(targetsPass1))
					for i, pkg := range targetsPass1 {
						outputPkgNames[i] = getOutputPackageName(pkg, cfg)
					}
					shouldInstall = askForConfirmation(colWarn, "-> Do you want to install the following built package(s): %s?", strings.Join(outputPkgNames, ", "))
				}
				if shouldInstall && !isCrossWithoutSystem {
					for i, finalPkg := range targetsPass1 {
						if _, failed := failedBuilds[finalPkg]; failed {
							continue
						}
						version, revision, _ := getRepoVersion2(finalPkg)
						outputFinalPkg := getOutputPackageName(finalPkg, cfg)
						tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputFinalPkg, version, revision))
						isCriticalAtomic.Store(1)
						handlePreInstallUninstall(outputFinalPkg, cfg, RootExec)
						colArrow.Print("-> ")
						colSuccess.Printf("Installing:")
						colNote.Printf(" %s (%d/%d)\n", outputFinalPkg, i+1, len(targetsPass1))
						if err := pkgInstall(tarballPath, outputFinalPkg, cfg, RootExec, false); err != nil {
							isCriticalAtomic.Store(0)
							failedBuilds[finalPkg] = fmt.Errorf("final installation failed: %w", err)
						} else {
							// Add package to world file
							if userRequestedMap[finalPkg] {
								addToWorld(finalPkg)
							}
						}
						isCriticalAtomic.Store(0)
					}
				}
			}
		}
	}

BuildSummary:

	// --- Final Report ---
	if len(failedBuilds) == 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("All packages built and installed successfully (%d/%d) Time: %s\n", totalBuildCount, totalBuildCount, totalElapsedTime.Truncate(time.Second))
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

func executeBuildPass(plan *BuildPlan, _ string, installAllTargets bool, cfg *Config, bootstrap *bool, userRequestedMap map[string]bool) (map[string]error, []string, time.Duration) {

	toBuild := plan.Order
	failed := make(map[string]error)
	var successfullyBuiltTargets []string
	builtThisPass := make(map[string]bool)
	var totalElapsedTime time.Duration
	passInProgress := true
	for passInProgress && len(toBuild) > 0 {
		progressThisPass := false
		var remainingAfterPass []string
		for i, pkgName := range toBuild {
			if _, isFailed := failed[pkgName]; isFailed {
				continue
			}
			canBuild := true
			pkgDir, _ := findPackageDir(pkgName)
			deps, _ := parseDependsFile(pkgDir)
			for _, dep := range deps {
				if dep.Optional {
					continue
				}

				// FILTER: Ignore 32-bit dependencies if multilib is disabled
				if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
					continue
				}

				isSatisfied := false

				// Helper to check if a package is available (installed or just built)
				isDepAvailable := func(name string, op string, ver string) bool {
					// 1. Check if it was built this pass (using exact name)
					if builtThisPass[name] {
						return true
					}

					// 2. Check if any satisfying package is installed (including renamed ones)
					if sat := findInstalledSatisfying(name, op, ver); sat != "" {
						return true
					}

					// 3. Fallback: if it was built this pass under a renamed name,
					// we need to check if that renamed name satisfies the constraint.
					// This is complex, but for now we can check if any key in builtThisPass
					// matches name-MAJOR if we can derive MAJOR from the constraint.
					// However, if it was built this pass, it was also INSTALLED,
					// so findInstalledSatisfying should have caught it.
					// The only edge case is if it's built but not yet installed (not possible in current sequential flow).

					return false
				}

				if len(dep.Alternatives) > 0 {
					for _, alt := range dep.Alternatives {
						if isDepAvailable(alt, "", "") {
							isSatisfied = true
							break
						}
					}
				} else {
					if isDepAvailable(dep.Name, dep.Op, dep.Version) {
						isSatisfied = true
					}
				}

				if !isSatisfied {
					// Check if we are blocked by a SPECIFIC failure in the alternatives
					if len(dep.Alternatives) > 0 {
						for _, alt := range dep.Alternatives {
							if _, hasFailed := failed[alt]; hasFailed {
								failed[pkgName] = fmt.Errorf("blocked by failed dependency '%s'", alt)
								break
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
			if !canBuild {
				remainingAfterPass = append(remainingAfterPass, pkgName)
				continue
			}
			totalInPlan := len(plan.Order) // Get the original total count
			colArrow.Print("-> ")
			colSuccess.Print("Building: ")
			colNote.Printf("%s (%d/%d)\n", pkgName, i+1, totalInPlan)

			duration, err := pkgBuild(pkgName, cfg, UserExec, *bootstrap, i+1, totalInPlan)
			if err != nil {
				failed[pkgName] = err
				color.Danger.Printf("Build failed for %s: %v\n\n", pkgName, err)
				continue
			} else {
				progressThisPass = true
				totalElapsedTime += duration // Accumulate the time from the successful build

				// Check if this package is required by any SUBSEQUENT package in the current build pass.
				// This ensures we only auto-install user-requested packages if absolutely necessary for the build chain.
				isDependencyForThisPass := false

				// Only check look-ahead if it's a user requested package.
				// Implicit dependencies (!userRequestedMap) are auto-installed by default logic below.
				if userRequestedMap[pkgName] {
					// Look ahead in the remaining list for packages that depend on this one
					for k := i + 1; k < len(toBuild); k++ {
						futurePkg := toBuild[k]

						// Check dependencies of futurePkg
						fDir, err := findPackageDir(futurePkg)
						if err == nil {
							fDeps, err := parseDependsFile(fDir)
							if err == nil {
								for _, d := range fDeps {
									if d.Name == pkgName {
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

				// We install immediately IF:
				//  - It's a dependency, OR
				//  - It's a user target that is a dependency for something else in this batch, OR
				//  - It's a user target that triggers a post-build rebuild.
				shouldInstallNow := !userRequestedMap[pkgName] || isDependencyForThisPass || triggersRebuilds

				if installAllTargets || shouldInstallNow {
					// Install the package immediately.
					version, revision, _ := getRepoVersion2(pkgName)
					outputPkgName := getOutputPackageName(pkgName, cfg)
					tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputPkgName, version, revision))
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputPkgName, cfg, RootExec)
					colArrow.Print("-> ")
					colSuccess.Printf("Installing:")
					colNote.Printf(" %s (%d/%d) Time: %s\n", outputPkgName, i+1, totalInPlan, duration.Truncate(time.Second))
					if installErr := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, true); installErr != nil {
						isCriticalAtomic.Store(0)
						failed[pkgName] = fmt.Errorf("post-build installation failed: %w", installErr)
						// We must 'continue' here to stop processing this package's post-build actions.
						continue
					}
					// Add to World file
					// Only add if this was an explicit user target,
					// NOT if it was just installed because it's a dependency (shouldInstallNow check logic)
					if userRequestedMap[pkgName] {
						addToWorld(pkgName)
					}

					// Check if it's a Make Dependency
					// If the user did NOT request it explicitly, check if it was pulled in
					// as a 'make' dependency by any other package in the toBuild list.
					if !userRequestedMap[pkgName] {
						isMakeDep := false
						// Scan all packages in the plan (including those already built or waiting)
						// to see if any of them list 'pkgName' as a 'make' dependency.
						for _, otherPkg := range plan.Order {
							pDir, err := findPackageDir(otherPkg)
							if err == nil {
								deps, err := parseDependsFile(pDir)
								if err == nil {
									for _, d := range deps {
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

						// Rebuild the parent package
						duration, err := pkgBuild(parent, cfg, UserExec, *bootstrap, i+1, totalInPlan)
						if err != nil {
							color.Danger.Printf("Inline rebuild of '%s' failed: %v\n", parent, err)
							failed[parent] = fmt.Errorf("inline rebuild failed: %w", err)
							continue // Move to check the next parent
						}
						totalElapsedTime += duration
						// Install the newly rebuilt parent
						version, revision, _ := getRepoVersion2(parent)
						outputParent := getOutputPackageName(parent, cfg)
						tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputParent, version, revision))
						isCriticalAtomic.Store(1)
						handlePreInstallUninstall(outputParent, cfg, RootExec)
						if installErr := pkgInstall(tarballPath, outputParent, cfg, RootExec, true); installErr != nil {
							isCriticalAtomic.Store(0)
							color.Danger.Printf("Installation of rebuilt '%s' failed: %v\n", parent, installErr)
							failed[parent] = fmt.Errorf("install of rebuilt '%s' failed: %w", parent, installErr)
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
					duration, err := pkgBuild(rebuildPkg, cfg, UserExec, *bootstrap, i+1, totalInPlan)
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
					tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s-%s.tar.zst", outputRebuildPkg, version, revision))
					isCriticalAtomic.Store(1)
					handlePreInstallUninstall(outputRebuildPkg, cfg, RootExec)
					// Always run this non-interactively
					if installErr := pkgInstall(tarballPath, outputRebuildPkg, cfg, RootExec, true); installErr != nil {
						isCriticalAtomic.Store(0)
						color.Danger.Printf("Installation of rebuilt '%s' failed: %v\n", rebuildPkg, installErr)
						failed[pkgName] = fmt.Errorf("install of post-built '%s' failed: %w", rebuildPkg, installErr)
						break
					}
					isCriticalAtomic.Store(0)
				}
			}

		}
		toBuild = remainingAfterPass
		passInProgress = progressThisPass
	}
	for _, pkg := range toBuild {
		if _, exists := failed[pkg]; !exists {
			// Find which dependency is missing to provide a better error message
			pkgDir, _ := findPackageDir(pkg)
			deps, _ := parseDependsFile(pkgDir)
			missingDep := "unknown"
			for _, dep := range deps {
				if dep.Optional {
					continue
				}

				// FILTER: Ignore 32-bit dependencies if multilib is disabled
				if !EnableMultilib && strings.HasSuffix(dep.Name, "-32") {
					continue
				}

				isSatisfied := false
				if len(dep.Alternatives) > 0 {
					for _, alt := range dep.Alternatives {
						if builtThisPass[alt] || findInstalledSatisfying(alt, "", "") != "" {
							isSatisfied = true
							break
						}
					}
				} else {
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
	return failed, successfullyBuiltTargets, totalElapsedTime
}
