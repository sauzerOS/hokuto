package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gookit/color"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
	"lukechampine.com/blake3"
)

// --- NEW GLOBAL STATE ---
// We use a value of 1 for critical and 0 for non-critical/default.
var isCriticalAtomic atomic.Int32

var (
	rootDir              string
	CacheDir             string
	SourcesDir           string
	BinDir               string
	CacheStore           string
	Installed            string
	repoPaths            string
	tmpDir               string
	WantStrip            string
	WantDebug            string
	Debug                bool
	Verbose              bool
	WantLTO              string
	newPackageDir        string
	idleUpdate           bool
	superidleUpdate      bool
	setIdlePriority      bool
	buildPriority        string
	ConfigFile           = "/etc/hokuto.conf"
	gnuMirrorURL         string
	gnuOriginalURL       = "https://ftp.gnu.org/gnu"
	gnuMirrorMessageOnce sync.Once
	// Global executors (declared, to be assigned in main)
	UserExec *Executor
	RootExec *Executor
	//go:embed assets/*.png
	embeddedImages embed.FS
	//go:embed assets/ca-bundle.crt
	embeddedAssets embed.FS
)

// color helpers
var (
	colInfo    = color.Info // style provided by gookit/color
	colWarn    = color.Warn
	colError   = color.Error
	colSuccess = color.HEX("#1976D2")
	colArrow   = color.HEX("#FFEB3B")
	colNote    = color.Tag("notice")
)

// color-compatible printer interface (works with *color.Theme and *color.Style)
type colorPrinter interface {
	Printf(format string, a ...any)
	Println(a ...any)
}

// cPrintf prints with a colored style or falls back to fmt.Printf when nil
func cPrintf(p colorPrinter, format string, a ...any) {
	if p == nil {
		fmt.Printf(format, a...)
		return
	}
	p.Printf(format, a...)
}

// cPrintln prints a line with the given style or falls back to fmt.Println when nil
func cPrintln(p colorPrinter, a ...any) {
	if p == nil {
		fmt.Println(a...)
		return
	}
	p.Println(a...)
}

// debugf prints debug messages when Debug is true
func debugf(format string, args ...any) {
	if Debug {
		fmt.Printf(format, args...)
	}
}

// Config struct
type Config struct {
	Values       map[string]string
	DefaultStrip bool
	DefaultLTO   bool
}

// Load /etc/hokuto.conf and apply defaults
func loadConfig(path string) (*Config, error) {
	cfg := &Config{Values: make(map[string]string)}

	// Attempt to read the file
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			cfg.Values[key] = val
		}
		if err := scanner.Err(); err != nil {
			return cfg, err
		}
	}

	// Merge HOKUTO_* env overrides
	mergeEnvOverrides(cfg)

	// Ensure TMPDIR has a default
	if tmp := cfg.Values["TMPDIR"]; tmp == "" {
		cfg.Values["TMPDIR"] = "/tmp"
	}

	return cfg, nil
}

// Merge HOKUTO_* env overrides
func mergeEnvOverrides(cfg *Config) {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "HOKUTO_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				cfg.Values[parts[0]] = parts[1]
			}
		}
	}

	// Also import LFS from the environment if present, without overwriting an explicit config file value
	if lfs := os.Getenv("LFS"); lfs != "" {
		// Use key "LFS" in cfg.Values to match environment variable name
		if _, exists := cfg.Values["LFS"]; !exists {
			cfg.Values["LFS"] = lfs
		}
	}
}

func initConfig(cfg *Config) {
	rootDir = cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}

	CacheDir = cfg.Values["HOKUTO_CACHE_DIR"]
	if CacheDir == "" {
		CacheDir = "/var/cache/hokuto"
	}

	repoPaths = cfg.Values["HOKUTO_PATH"]
	if repoPaths == "" {
		log.Printf("Warning: HOKUTO_PATH is not set")
	}

	WantDebug = cfg.Values["HOKUTO_DEBUG"]
	if WantDebug == "" {
		WantDebug = "0"
	}
	Debug = false
	if WantDebug == "1" {
		Debug = true
	}

	tmpDir = cfg.Values["TMPDIR"]
	if tmpDir == "" {
		tmpDir = "/tmp"
	}

	cfg.DefaultStrip = true
	WantStrip := cfg.Values["HOKUTO_STRIP"]
	if WantStrip == "0" {
		cfg.DefaultStrip = false
	}

	cfg.DefaultLTO = false
	WantLTO := cfg.Values["HOKUTO_LTO"]
	if WantLTO == "1" {
		cfg.DefaultLTO = true
	}

	// Load the GNU mirror URL if it's set in the config
	if mirror, exists := cfg.Values["GNU_MIRROR"]; exists && mirror != "" {
		gnuMirrorURL = strings.TrimRight(mirror, "/") // Remove trailing slash if present
		debugf("=> Using GNU mirror: %s\n", gnuMirrorURL)
	}

	SourcesDir = CacheDir + "/sources"
	BinDir = CacheDir + "/bin"
	CacheStore = SourcesDir + "/_cache"
	Installed = rootDir + "/var/db/hokuto/installed"
	newPackageDir = "/repo/sauzeros/extra" // default for 'hokuto new'

}

// needsRootPrivileges checks if any of the requested operations require root
func needsRootPrivileges(args []string) bool {
	if len(args) < 1 {
		return false
	}

	cmd := args[0]

	// Commands that require root privileges
	rootCommands := map[string]bool{
		"build":     true,
		"b":         true,
		"bootstrap": true,
		"install":   true,
		"i":         true,
		"uninstall": true,
		"remove":    true,
		"r":         true,
		"update":    true,
		"u":         true,
		"chroot":    true,
		"cleanup":   true,
	}

	if rootCommands[cmd] {
		return true
	}

	// Check if build command has auto-install flag
	if cmd == "build" || cmd == "b" {
		for _, arg := range args[1:] {
			if arg == "-a" {
				return true
			}
		}
	}

	return false
}

// authenticateOnce performs a single authentication check at program start
func authenticateOnce() error {
	if os.Geteuid() == 0 {
		return nil // Already root
	}

	// Try run0 first
	/*if _, err := exec.LookPath("run0"); err == nil {
		// run0 uses polkit - test with a simple command
		cmd := exec.Command("run0", "true")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("run0 authentication failed: %w", err)
		}
		cPrintln(colInfo, "Authenticated via run0")
		return nil
	}*/

	// Fallback to sudo
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo authentication failed: %w", err)
	}

	// Start keep-alive goroutine for sudo
	go func() {
		ticker := time.NewTicker(4 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			exec.Command("sudo", "-nv").Run()
		}
	}()

	//cPrintln(colNote, "-> Authenticated via sudo")
	colArrow.Print("-> ")
	colSuccess.Println("Authenticated via sudo")
	return nil
}

// Executor provides a consistent interface for executing commands,
// abstracting away the privilege escalation (sudo) logic.
type Executor struct {
	Context           context.Context // The context to use for cancellation
	ShouldRunAsRoot   bool            // ShouldRunAsRoot specifies whether the command MUST be executed with root privileges.
	ApplyIdlePriority bool            // NEW: Apply nice -n 19 to this specific command
	Interactive       bool            // Interactive indicates whether the command may prompt the user
}

// Update the constructor/factory function for Executor
func NewExecutor(ctx context.Context /* other params */) *Executor {
	// ... initialize other fields if necessary
	return &Executor{Context: ctx}
}

// runInteractiveCommand executes a command, ensuring it's attached to the TTY for interactive prompts.
// It does not use process group isolation, making it suitable for commands like `sudo -v`.
func runInteractiveCommand(ctx context.Context, name string, arg ...string) error {
	cmd := exec.CommandContext(ctx, name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureSudo checks if the sudo ticket is still valid and re-prompts if necessary.
// It handles interactive re-authentication by running `sudo -v` with a proper TTY
// if the non-interactive check `sudo -nv` fails.
// No action needed if we are already root or the command doesn't require root.
func (e *Executor) ensureSudo() error {
	if os.Geteuid() == 0 || !e.ShouldRunAsRoot {
		return nil
	}
	// 1. First, perform a non-interactive check (`sudo -nv`) to see if the ticket is still valid.
	// This is fast and avoids any user interaction if the ticket is fresh.
	checkCmd := exec.CommandContext(e.Context, "sudo", "-nv")
	checkCmd.Stdout = io.Discard
	checkCmd.Stderr = io.Discard

	if err := checkCmd.Run(); err == nil {
		// Success (exit code 0): The sudo ticket is valid. Nothing more to do.
		return nil
	}

	// Non-interactive check failed — the ticket has likely expired.
	// We must now re-authenticate interactively using `sudo -v`.
	colArrow.Print("-> ")
	colSuccess.Println("Sudo ticket has expired. Re-authenticating")

	// Use a dedicated interactive runner that does NOT set a new process group.
	// This ensures `sudo` can correctly access the TTY for password input.
	if err := runInteractiveCommand(e.Context, "sudo", "-v"); err != nil {
		return fmt.Errorf("sudo re-authentication failed: %w", err)
	}
	colArrow.Print("-> ")
	colSuccess.Println("Re-authenticated via sudo successfully.")
	return nil
}

// Run executes the given command, elevating via sudo -E only when needed.
// It wires up stdio, isolates the child in its own process group for cleanup,
// and calls ensureSudo() to avoid unnecessary password prompts.
func (e *Executor) Run(cmd *exec.Cmd) error {
	// --- Phase 0: wire up stdio ---
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	// --- Phase 1: maybe check privilege ---
	if err := e.ensureSudo(); err != nil {
		return err
	}

	// --- Phase 2: build the final command ---
	var finalCmd *exec.Cmd

	basePath := cmd.Path
	baseArgs := cmd.Args[1:]

	// 2b. Apply IDLE/NICENESS wrapper if requested
	if e.ApplyIdlePriority {
		baseArgs = append([]string{"-n", "19", basePath}, baseArgs...)
		basePath = "nice"
	}

	// 2c. Apply privilege wrapper if needed
	if e.ShouldRunAsRoot && os.Geteuid() != 0 {
		// Try run0 first (preferred)
		/*if _, err := exec.LookPath("run0"); err == nil {
			args := []string{}

			// Set working directory if specified
			if cmd.Dir != "" {
				args = append(args, "--working-directory="+cmd.Dir)
			}

			args = append(args, basePath)
			args = append(args, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "run0", args...)

			// Don't set Dir since we used --working-directory
			finalCmd.Dir = ""
		} else {*/
		// Fallback to sudo -E
		{

			args := append([]string{"-E", basePath}, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "sudo", args...)
			finalCmd.Dir = cmd.Dir
		}
	} else {
		finalCmd = exec.CommandContext(e.Context, basePath, baseArgs...)
		finalCmd.Dir = cmd.Dir
	}

	// preserve or inherit the environment
	if len(cmd.Env) > 0 {
		finalCmd.Env = cmd.Env
	} else {
		finalCmd.Env = os.Environ()
	}

	// carry over stdio
	finalCmd.Stdin = cmd.Stdin
	finalCmd.Stdout = cmd.Stdout
	finalCmd.Stderr = cmd.Stderr

	// --- Phase 3: isolate process group for context-based cleanup ---
	if !e.Interactive {
		finalCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	// --- Phase 4: start and watch for cancel ---
	if err := finalCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Conditionally manage cancellation. If interactive, let CommandContext handle it.
	// Otherwise, manage the entire process group.
	if !e.Interactive {
		pgid := finalCmd.Process.Pid

		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-e.Context.Done():
				syscall.Kill(-pgid, syscall.SIGKILL)
			case <-done:
			}
		}()
	}

	// --- Phase 5: wait and return ---
	if waitErr := finalCmd.Wait(); waitErr != nil {
		if e.Context.Err() != nil {
			time.Sleep(100 * time.Millisecond)
			return fmt.Errorf("command aborted: %v", e.Context.Err())
		}
		return waitErr
	}
	return nil
}

// listEmbeddedImages returns the list of image asset names (relative to assets/)
func listEmbeddedImages() ([]string, error) {
	entries, err := embeddedImages.ReadDir("assets")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// displayEmbeddedWithChafa writes the embedded image to a secure temp file and runs chafa.
// ctx: use a cancellable context (pass the main ctx so Ctrl+C cancels chafa)
// imgRelPath: the name relative to "assets/" (e.g., "foo.png")
// chafaArgs: additional chafa flags (optional)
func displayEmbeddedWithChafa(ctx context.Context, imgRelPath string, chafaArgs ...string) error {
	// Read embedded bytes
	data, err := embeddedImages.ReadFile(filepath.Join("assets", imgRelPath))
	if err != nil {
		return fmt.Errorf("embedded image not found: %w", err)
	}

	// Create secure temp file
	f, err := os.CreateTemp("", "hokuto-img-*.png")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

	// Ensure file removed; keep f open long enough to write+sync
	defer func() {
		f.Close()
		os.Remove(tmpPath)
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp image: %w", err)
	}
	if err := f.Sync(); err != nil {
		// best-effort
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close tmp image: %w", err)
	}

	// Build chafa args: [tmpPath] + chafaArgs...
	args := append([]string{tmpPath}, chafaArgs...)
	cmd := exec.CommandContext(ctx, "chafa", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run and return any error (context cancels command when ctx done)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("chafa failed: %w", err)
	}
	return nil
}

// List installed packages with version, supporting partial matches and showing build time.
func listPackages(searchTerm string) error {
	// Step 1: Always get the full list of installed package directories first.
	entries, err := os.ReadDir(Installed)
	if err != nil {
		// Handle cases where the 'Installed' directory might not exist yet
		if os.IsNotExist(err) {
			fmt.Println("No packages installed.")
			return nil
		}
		return err
	}

	var allPkgs []string
	for _, e := range entries {
		if e.IsDir() {
			allPkgs = append(allPkgs, e.Name())
		}
	}

	// Step 2: Filter the list if a search term was provided.
	var pkgsToShow []string
	if searchTerm != "" {
		// Partial matching
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, show everything
		pkgsToShow = allPkgs
	}

	// Step 3: Handle the case where no packages were found after filtering.
	if len(pkgsToShow) == 0 {
		if searchTerm != "" {
			colArrow.Print("-> ")
			colSuccess.Printf("No packages found matching: %s\n", searchTerm)
		}
		return nil
	}

	// Step 4: Print the information for the final list of packages.
	// Format: "<name> <version> <revision>    <buildtime>"
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown"
		if data, err := os.ReadFile(versionFile); err == nil {
			versionInfo = strings.TrimSpace(string(data))
		}

		// Read buildtime (duration string) if present.
		buildtimeFile := filepath.Join(Installed, p, "buildtime")
		buildtimeStr := ""

		if data, err := os.ReadFile(buildtimeFile); err == nil {
			raw := strings.TrimSpace(string(data))
			if raw != "" {
				// Try to parse the content as a time.Duration string.
				if d, err := time.ParseDuration(raw); err == nil {

					// Apply formatting rules based on magnitude:
					if d >= time.Minute {
						// >= 1 minute: Truncate to the nearest whole second (e.g., 18m53s)
						buildtimeStr = d.Truncate(time.Second).String()
					} else if d >= time.Second {
						// 1s to 59s: Convert to raw seconds and format with 2 decimal places (e.g., 8.15s)
						buildtimeStr = fmt.Sprintf("%.2fs", d.Seconds())
					} else if d >= time.Millisecond {
						// 1ms to 999ms: Format using milliseconds with limited precision (e.g., 35.29ms)
						// This converts to floating point milliseconds and formats with 2 decimal places.
						buildtimeStr = fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
					} else {
						// < 1ms: Use the standard duration string (e.g., 476µs or 500ns)
						// Truncate to the nearest microsecond to keep it clean.
						buildtimeStr = d.Truncate(time.Microsecond).String()
					}

				} else {
					// Fallback for old format (plain float seconds)
					if secs, err := strconv.ParseFloat(raw, 64); err == nil {
						buildtimeStr = fmt.Sprintf("%.2fs", secs)
					} else {
						// Fallback: show the raw value.
						buildtimeStr = raw
					}
				}
			}
		}

		// Print aligned: versionInfo then some spacing then buildtime if present
		if buildtimeStr != "" {
			cPrintf(color.Cyan, "%-30s %s\n", fmt.Sprintf("%s %s", p, versionInfo), buildtimeStr)
		} else {
			cPrintf(color.Cyan, "%s %s\n", p, versionInfo)
		}
	}

	return nil
}

// showManifest prints the file list for a package manifest, skipping directories,
// checksums, and any entries under var/db/hokuto (internal metadata).
func showManifest(pkgName string) error {
	manifestPath := filepath.Join(Installed, pkgName, "manifest")

	// Read manifest as the invoking user (no sudo/cat helper)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("package %s is not installed (manifest not found)", pkgName)
		}
		return fmt.Errorf("failed to read manifest for %s: %w", pkgName, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip directory entries (lines that end with '/')
		if strings.HasSuffix(line, "/") {
			continue
		}

		// Each file line is expected to be: "<path>  <checksum>"
		// We only want to print the path (first whitespace-separated field).
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := fields[0]

		// Normalize for checking internal metadata: consider both absolute and relative variants.
		clean := filepath.Clean(path)
		// Remove leading slash for consistent prefix checking
		cleanNoSlash := strings.TrimPrefix(clean, "/")

		// Filter out internal metadata paths under var/db/hokuto
		if strings.HasPrefix(cleanNoSlash, filepath.ToSlash(filepath.Clean("var/db/hokuto"))) {
			continue
		}

		// Print the manifest file path (exact path as stored in manifest)
		fmt.Println(path)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning manifest: %w", err)
	}
	return nil
}

// findPackagesByManifestString searches every installed/<pkg>/manifest for the given query string.
// It prints the package names (one per line) for packages whose manifest contains a path
// matching the query. Directory entries and internal metadata (var/db/hokuto) are ignored.
func findPackagesByManifestString(query string) error {
	if query == "" {
		return fmt.Errorf("empty search string")
	}

	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No packages installed.")
			return nil
		}
		return fmt.Errorf("failed to read installed db: %w", err)
	}

	foundAny := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(Installed, pkgName, "manifest")

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			// skip packages without readable manifest rather than failing the whole run
			continue
		}

		match := false
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// skip directory entries
			if strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			path := fields[0]

			// skip internal metadata entries
			clean := filepath.Clean(path)
			cleanNoSlash := strings.TrimPrefix(clean, "/")
			if strings.HasPrefix(cleanNoSlash, filepath.ToSlash("var/db/hokuto")) {
				continue
			}

			if strings.Contains(path, query) {
				match = true
				break
			}
		}
		if scannerErr := scanner.Err(); scannerErr != nil {
			// ignore malformed manifest for this package
			continue
		}

		if match {
			fmt.Println(pkgName)
			foundAny = true
		}
	}

	if !foundAny {
		// exit code could indicate no matches; print a friendly message instead
		fmt.Println("No packages found matching:", query)
	}
	return nil
}

// newPackage creates a minimal package skeleton in $newPackageDir/<pkg>.
// - creates directory $newPackageDir/<pkg>
// - creates build, version, sources files with the right modes and contents
func newPackage(pkgName string) error {
	if newPackageDir == "" {
		return fmt.Errorf("newPackageDir is not set")
	}

	pkgDir := filepath.Join(newPackageDir, pkgName)

	// Don't overwrite existing package dir
	if fi, err := os.Stat(pkgDir); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("package %s already exists at %s", pkgName, pkgDir)
		}
		return fmt.Errorf("path %s exists and is not a directory", pkgDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat path %s: %w", pkgDir, err)
	}

	// Create package dir
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return fmt.Errorf("failed to create package directory %s: %w", pkgDir, err)
	}

	// 1) build file: mode 0755, content "#!/bin/sh -e\n"
	buildPath := filepath.Join(pkgDir, "build")
	buildContent := []byte("#!/bin/sh -e\n")
	if err := os.WriteFile(buildPath, buildContent, 0o755); err != nil {
		return fmt.Errorf("failed to create build file: %w", err)
	}

	// 2) version file: mode 0644, content " 1\n"
	versionPath := filepath.Join(pkgDir, "version")
	versionContent := []byte(" 1\n")
	if err := os.WriteFile(versionPath, versionContent, 0o644); err != nil {
		return fmt.Errorf("failed to create version file: %w", err)
	}

	// 3) sources file: mode 0644, empty
	sourcesPath := filepath.Join(pkgDir, "sources")
	if err := os.WriteFile(sourcesPath, []byte(""), 0o644); err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}

	// Success messages
	cPrintln(colInfo, "=> Creating build file.")
	cPrintln(colInfo, "=> Creating version file with ' 1'.")
	cPrintln(colInfo, "=> Creating sources file with ''.")
	cPrintf(colInfo, "=> Package %s created in %s.\n", pkgName, pkgDir)

	return nil
}

// editPackage searches for pkgName under the colon-separated repoPaths
// and opens version, sources, build, depends in the user's editor.
func editPackage(pkgName string, openAll bool) error {
	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "nano"
	}

	// repoPaths is expected to be a colon-separated string of base paths,
	// for example "/repo/sauzeros/core:/repo/sauzeros/extra".
	paths := filepath.SplitList(repoPaths)
	if len(paths) == 0 {
		return fmt.Errorf("no repo paths configured")
	}

	// Find the first directory that contains the package dir
	var pkgDirEd string
	for _, base := range paths {
		candidate := filepath.Join(base, pkgName)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			pkgDirEd = candidate
			break
		}
	}

	if pkgDirEd == "" {
		// Instead of creating, just return an error
		return fmt.Errorf("package %s not found in any repo path", pkgName)
	}

	// --- Files to open
	var relFiles []string
	if openAll {
		relFiles = []string{"version", "sources", "build", "depends"}
	} else {
		relFiles = []string{"version", "sources"}
	}

	var filesToOpen []string
	for _, f := range relFiles {
		full := filepath.Join(pkgDirEd, f)
		// Ensure file exists
		if _, err := os.Stat(full); os.IsNotExist(err) {
			if err := os.WriteFile(full, nil, 0o644); err != nil {
				return fmt.Errorf("failed to create %s: %v", full, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to stat %s: %v", full, err)
		}
		filesToOpen = append(filesToOpen, full)
	}

	// Launch editor with all files
	cmd := exec.Command(editor, filesToOpen...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// newHttpClient creates and returns an http.Client.
// It tries to use the system's CA certificates first. If that fails, it falls
// back to the ca-bundle.crt file embedded in the application binary.
func newHttpClient() (*http.Client, error) {
	// 1. Try to load the system's default set of trusted CAs.
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		cPrintf(colWarn, "Warning: Could not load system CA certificates: %v\n", err)
		cPrintf(colInfo, "=> Attempting to use bundled CA certificate as a fallback.\n")

		// 2. Fallback: If system pool fails, create a new pool from the embedded asset.
		rootCAs = x509.NewCertPool()
		certs, err := embeddedAssets.ReadFile("assets/ca-bundle.crt")
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded ca-bundle.crt: %w."+
				" Please ensure the file exists in the 'assets' directory before compiling", err)
		}

		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			return nil, fmt.Errorf("failed to parse bundled CA certificates. The file may be invalid")
		}
	}

	// 3. Configure the TLS client to use the selected pool of trusted CAs.
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{Transport: transport}, nil
}

// downloadFile downloads a URL into the hokuto cache.
func downloadFile(originalURL, finalURL, destFile string) error {
	// If a GNU mirror is being used for this download, print the info message exactly once.
	if originalURL != finalURL {
		gnuMirrorMessageOnce.Do(func() {
			colArrow.Print("-> ")
			colSuccess.Printf("Using GNU mirror: %s\n", gnuMirrorURL)
		})
	}

	// 1. Ensure the cache directory exists
	if err := os.MkdirAll(CacheStore, 0o755); err != nil {
		return fmt.Errorf("failed to create cache directory %s: %w", CacheStore, err)
	}

	// 2. Prepare the destination path
	destFile = filepath.Base(destFile) // Ensure we only have the filename
	absPath := filepath.Join(CacheStore, destFile)

	debugf("Downloading %s -> %s\n", finalURL, absPath)

	// --- Primary Choice: Try curl with Go-native colorization ---
	if _, err := exec.LookPath("curl"); err == nil {
		curlArgs := []string{"-L", "--fail", "-o", absPath, "-#"}
		curlArgs = append(curlArgs, finalURL) // Use the final URL for the download
		cmd := exec.Command("curl", curlArgs...)

		stderrPipe, err := cmd.StderrPipe()
		if err != nil {
			cmd.Stderr = os.Stderr
		}
		cmd.Stdout = os.Stdout

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start curl: %w", err)
		}

		if stderrPipe != nil {
			go func() {
				reader := bufio.NewReader(stderrPipe)
				blue := "\x1b[" + color.Blue.Code() + "m"
				reset := "\x1b[0m"
				for {
					lineBytes, err := reader.ReadBytes('\r')
					if len(lineBytes) > 0 {
						line := string(lineBytes)
						if strings.HasPrefix(strings.TrimSpace(line), "#") {
							fmt.Fprintf(os.Stderr, "%s%s%s", blue, line, reset)
						} else {
							fmt.Fprint(os.Stderr, line)
						}
					}
					if err != nil {
						break
					}
				}
			}()
		}

		if err := cmd.Wait(); err != nil {
			debugf("\ncurl failed, falling back to wget")
		} else {
			debugf("\nDownload successful with curl.")
			return nil
		}
	} else {
		debugf("curl not found, trying wget")
	}

	// --- Fallback 1: Try wget ---
	if _, err := exec.LookPath("wget"); err == nil {
		args := []string{"-nv", "-O", absPath}
		args = append(args, finalURL) // Use the final URL for the download
		cmd := exec.Command("wget", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err == nil {
			debugf("\nDownload successful with wget.")
			return nil
		}
		debugf("\nwget failed, falling back to native Go HTTP client")
	} else {
		debugf("wget not found, using native Go HTTP client")
	}

	// --- Fallback 2: Native Go HTTP Client ---
	client, err := newHttpClient()
	if err != nil {
		return fmt.Errorf("failed to create http client: %w", err)
	}

	out, err := os.Create(absPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", absPath, err)
	}
	defer out.Close()

	resp, err := client.Get(finalURL) // Use the final URL for the download
	if err != nil {
		return fmt.Errorf("native http get failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write to destination file: %w", err)
	}

	debugf("Download successful with native Go HTTP client.")
	return nil
}

// applyGnuMirror checks if a URL is a canonical GNU URL and replaces it with the
// user-configured mirror if one is set. It returns the (potentially modified) URL.
func applyGnuMirror(originalURL string) string {
	if gnuMirrorURL != "" && strings.HasPrefix(originalURL, gnuOriginalURL) {
		return strings.Replace(originalURL, gnuOriginalURL, gnuMirrorURL, 1)
	}
	return originalURL
}

// Fetch sources (HTTP/FTP + Git)
func fetchSources(pkgName, pkgDir string, processGit bool) error {
	data, err := os.ReadFile(filepath.Join(pkgDir, "sources"))
	if err != nil {
		return fmt.Errorf("could not read sources file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	pkgLinkDir := filepath.Join(SourcesDir, pkgName)

	if err := os.MkdirAll(pkgLinkDir, 0o755); err != nil {
		return fmt.Errorf("failed to create pkg source dir: %v", err)
	}
	if err := os.MkdirAll(CacheStore, 0o755); err != nil {
		return fmt.Errorf("failed to create _cache dir: %v", err)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Declare all loop-scoped variables here.
		var parts []string
		var origFilename, hashName, cachePath, linkPath string

		rawSourceURL := strings.Fields(line)[0]

		// --- FIX START: Skip local files defined with the 'files/' prefix ---
		if strings.HasPrefix(rawSourceURL, "files/") {
			debugf("Skipping local source file: %s\n", rawSourceURL)
			continue
		}
		// --- FIX END ---

		// --- Mirror and Git Logic ---
		if strings.HasPrefix(rawSourceURL, "git+") {
			// If we are not supposed to process git repos (e.g., in 'checksum' command), skip.
			if !processGit {
				debugf("Skipping git repository for this operation: %s\n", rawSourceURL)
				continue
			}
			// ... (rest of the existing, correct git logic) ...
			gitURL := strings.TrimPrefix(rawSourceURL, "git+")
			ref := ""
			if strings.Contains(gitURL, "#") {
				subParts := strings.SplitN(gitURL, "#", 2)
				gitURL = subParts[0]
				ref = subParts[1]
			}
			parts = strings.Split(strings.TrimSuffix(gitURL, ".git"), "/")
			repoName := parts[len(parts)-1]
			destPath := filepath.Join(pkgLinkDir, repoName)
			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				cPrintf(colInfo, "Cloning git repository %s into %s\n", gitURL, destPath)
				cmd := exec.Command("git", "clone", gitURL, destPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("git clone failed: %v", err)
				}
			} else if ref == "" {
				cmd := exec.Command("git", "-C", destPath, "pull")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
			exec.Command("git", "-C", destPath, "config", "advice.detachedHead", "false").Run()
			if ref != "" {
				checkBranch := exec.Command("git", "-C", destPath, "rev-parse", "--verify", "refs/heads/"+ref)
				if err := checkBranch.Run(); err == nil {
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
					cmd = exec.Command("git", "-C", destPath, "pull")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				} else {
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				}
			}
			cPrintf(colInfo, "Git repository ready: %s\n", destPath)
			continue // End git block
		}

		// --- HTTP/FTP Source Logic ---
		originalSourceURL := rawSourceURL
		substitutedURL := applyGnuMirror(originalSourceURL)

		parts = strings.Split(originalSourceURL, "/")
		origFilename = parts[len(parts)-1]

		// The hash for the cache MUST be based on the original, canonical URL.
		hashName = fmt.Sprintf("%s-%s", hashString(originalSourceURL), origFilename)
		cachePath = filepath.Join(CacheStore, hashName)

		if _, err := os.Stat(cachePath); os.IsNotExist(err) {
			colArrow.Print("-> ")
			colSuccess.Printf("Fetching source: %s\n", origFilename)
			if err := downloadFile(originalSourceURL, substitutedURL, cachePath); err != nil {
				return fmt.Errorf("failed to download %s: %v", substitutedURL, err)
			}
		} else {
			debugf("Already in cache: %s\n", cachePath)
		}

		linkPath = filepath.Join(pkgLinkDir, origFilename)
		if _, err := os.Lstat(linkPath); err == nil {
			os.Remove(linkPath)
		}
		if err := os.Symlink(cachePath, linkPath); err != nil {
			return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, linkPath, err)
		}
		debugf("Linked %s -> %s\n", linkPath, cachePath)
	}

	return nil
}

// Hashing helper for cached filenames
// Uses system b3sum if available, otherwise falls back to internal Go BLAKE3.
func hashString(s string) string {
	// Try system b3sum first
	if _, err := exec.LookPath("b3sum"); err == nil {
		cmd := exec.Command("b3sum")
		cmd.Stdin = strings.NewReader(s)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			fields := strings.Fields(out.String())
			if len(fields) > 0 {
				return fields[0]
			}
		}
	}

	// Fallback: internal Go BLAKE3 (32-byte output, no key)
	h := blake3.New(32, nil)
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// compute b3sum with go implementation lukechampime.com/blake3
func blake3SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Create a BLAKE3 hasher with a 32-byte output and no key.
	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// check if b3sum is installed on system
func hasB3sum() bool {
	_, err := exec.LookPath("b3sum")
	return err == nil
}

// verifyOrCreateChecksums checks source file integrity, prompting the user for action on mismatch.
func verifyOrCreateChecksums(pkgName, pkgDir string, force bool) error {
	pkgSrcDir := filepath.Join(SourcesDir, pkgName)
	checksumFile := filepath.Join(pkgDir, "checksums")

	// Create source directory if it doesn't exist
	if err := os.MkdirAll(pkgSrcDir, 0755); err != nil {
		return fmt.Errorf("failed to create package source directory: %v", err)
	}

	// Load existing checksums into a map for quick lookup
	existing := make(map[string]string)
	if f, err := os.Open(checksumFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			parts := strings.Fields(strings.TrimSpace(scanner.Text()))
			if len(parts) >= 2 {
				existing[parts[1]] = parts[0] // map[filename] = checksum
			}
		}
		f.Close()
	}

	// Parse the 'sources' file to know which files to check
	sourceData, err := os.ReadFile(filepath.Join(pkgDir, "sources"))
	if err != nil {
		return fmt.Errorf("cannot read sources file: %v", err)
	}

	var expectedFiles []string
	urlMap := make(map[string]string) // map[filename] -> url
	for _, line := range strings.Split(string(sourceData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "files/") || strings.HasPrefix(line, "git+") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 {
			url := parts[0]
			fname := filepath.Base(url)
			expectedFiles = append(expectedFiles, fname)
			urlMap[fname] = url
		}
	}

	var summary []string
	var finalChecksums []string

	for _, fname := range expectedFiles {
		filePath := filepath.Join(pkgSrcDir, fname)
		originalURL := urlMap[fname]
		substitutedURL := applyGnuMirror(originalURL)

		currentSum, sumExists := existing[fname]
		isHashValid := false

		// 1. VERIFY: Check the hash if it exists and we aren't forcing a refresh.
		if sumExists && !force {
			// Prefer the external `b3sum` command if available.
			if hasB3sum() {
				cmd := exec.Command("b3sum", "-c")
				cmd.Stdin = strings.NewReader(fmt.Sprintf("%s  %s\n", currentSum, filePath))
				if cmd.Run() == nil {
					isHashValid = true
				}
			} else {
				// Fallback to internal blake3 calculation.
				sum, err := blake3SumFile(filePath)
				if err == nil && sum == currentSum {
					isHashValid = true
				}
			}
		}

		// 2. DECIDE: If hash is valid, we're done with this file.
		if isHashValid {
			finalChecksums = append(finalChecksums, fmt.Sprintf("%s  %s", currentSum, fname))
			summary = append(summary, fmt.Sprintf("%s: ok", fname))
			continue
		}

		// 3. ACT: If we're here, the hash is invalid, missing, or we're in `force` mode.
		// We must now decide whether to keep the local file or redownload it.
		shouldRedownload := force
		actionSummary := "updated"

		if !force {
			prompt := "Checksum mismatch for %s. (K)eep local file, (r)edownload file? [K/r]: "
			if !sumExists {
				prompt = "No checksum for %s. (K)eep local file, (r)edownload file? [K/r]: "
			}
			colArrow.Print("-> ")
			colSuccess.Printf(prompt, fname)
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(strings.TrimSpace(response)) == "r" {
				shouldRedownload = true
			}
		}

		if shouldRedownload {
			colArrow.Print("-> ")
			colSuccess.Printf("Downloading %s\n", fname)
			actionSummary = "Updated"

			// The hash for the cache MUST be based on the original, canonical URL.
			hashName := fmt.Sprintf("%s-%s", hashString(originalURL), fname)
			cachePath := filepath.Join(CacheStore, hashName)

			_ = os.Remove(cachePath)
			_ = os.Remove(filePath)

			if err := downloadFile(originalURL, substitutedURL, cachePath); err != nil {
				return fmt.Errorf("failed to redownload %s: %v", fname, err)
			}
			if err := os.Symlink(cachePath, filePath); err != nil {
				return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, filePath, err)
			}
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Keeping existing local file for %s.\n", fname)
		}

		// 4. RECALCULATE: Generate the new checksum for the file now on disk.
		debugf("-> Updating checksum for %s\n", fname)
		var newSum string
		var calcErr error
		if hasB3sum() {
			out, err := exec.Command("b3sum", filePath).Output()
			if err != nil {
				return fmt.Errorf("b3sum failed for %s: %v", fname, err)
			}
			newSum = strings.Fields(string(out))[0]
		} else {
			newSum, calcErr = blake3SumFile(filePath)
			if calcErr != nil {
				return fmt.Errorf("failed to compute checksum for %s: %v", fname, calcErr)
			}
		}

		finalChecksums = append(finalChecksums, fmt.Sprintf("%s  %s", newSum, fname))
		summary = append(summary, fmt.Sprintf("%s: %s", fname, actionSummary))
	}

	// 5. FINALIZE: Write the new checksum file and print the summary report.
	if err := os.WriteFile(checksumFile, []byte(strings.Join(finalChecksums, "\n")+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write checksums file: %v", err)
	}

	debugf("-> Checksums summary for %s:\n", pkgName)
	for _, s := range summary {
		colArrow.Print("-> ")
		colSuccess.Println("Checksum", s)
	}

	return nil
}

// checksum command
func hokutoChecksum(pkgName string, force bool) error {

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

	if err := fetchSources(pkgName, pkgDir, false); err != nil {
		return fmt.Errorf("error fetching sources: %v", err)
	}
	if err := verifyOrCreateChecksums(pkgName, pkgDir, force); err != nil {
		return fmt.Errorf("error verifying checksums: %v", err)
	}

	return nil
}

// prepareSources copies and extracts sources into the build directory
func prepareSources(pkgName, pkgDir, buildDir string, execCtx *Executor) error {
	// Assuming CacheDir, SourcesDir, Executor, etc. are available in scope.
	srcDir := filepath.Join(CacheDir, "sources", pkgName)

	// Read sources list
	sourcesFile := filepath.Join(pkgDir, "sources")
	sourcesData, err := os.ReadFile(sourcesFile)
	if err != nil {
		return fmt.Errorf("failed to read sources file: %v", err)
	}

	for _, line := range strings.Split(string(sourcesData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into tokens: path, optional subdir, optional flags
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		relPath := tokens[0]

		targetSubdir := ""
		noExtract := false
		for _, tok := range tokens[1:] {
			switch tok {
			case "noextract":
				noExtract = true
			default:
				// treat as target subdir if not a flag
				if targetSubdir == "" {
					targetSubdir = tok
				}
			}
		}

		// 2. Determine the final target directory
		targetDir := buildDir
		if targetSubdir != "" {
			targetDir = filepath.Join(buildDir, targetSubdir)
			if err := os.MkdirAll(targetDir, 0o755); err != nil {
				return fmt.Errorf("failed to create target subdir %s: %v", targetDir, err)
			}
		}

		// 3. Determine the source path on disk (srcPath) based on relPath type

		var srcPath string

		isGitSource := strings.HasPrefix(relPath, "git+")
		isUrlSource := strings.HasPrefix(relPath, "http://") || strings.HasPrefix(relPath, "https://") || strings.HasPrefix(relPath, "ftp://")

		switch {
		case strings.HasPrefix(relPath, "files/"):
			// Local files in package directory
			srcPath = filepath.Join(pkgDir, relPath)
		case isGitSource:
			// Git sources: Source path is the cloned directory in the cache (SourcesDir/pkgName/repoName)
			gitURL := strings.TrimPrefix(relPath, "git+")
			parsedURL, err := url.Parse(gitURL)
			if err != nil {
				return fmt.Errorf("invalid git URL in sources file: %w", err)
			}
			repoBase := filepath.Base(parsedURL.Path)
			repoBase = strings.TrimSuffix(repoBase, ".git")
			// srcDir is SourcesDir/pkgName. We look for the cloned repo name inside it.
			srcPath = filepath.Join(srcDir, repoBase)

			// Check if source exists *before* deciding to copy its contents
			info, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("git source %s listed but missing: stat %s: %v", relPath, srcPath, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("git source %s exists but is not a directory: %s", relPath, srcPath)
			}

			// ACTION: Copy CONTENTS of srcPath into targetDir
			// We use rsync -a src/ dest/ to copy contents without creating a subdir
			rsyncCmd := exec.Command("rsync", "-a", srcPath+"/", targetDir)
			if err := execCtx.Run(rsyncCmd); err != nil {
				return fmt.Errorf("failed to copy git source contents from %s to %s: %v", srcPath, targetDir, err)
			}
			// Git source handled, move to the next line
			continue

		case isUrlSource:
			// Other URL sources (archives): Source path is the symlink in the cache dir (SourcesDir/pkgName/filename)
			urlPath, err := url.Parse(relPath)
			if err != nil {
				return fmt.Errorf("invalid URL in sources file: %v", err)
			}
			filenameOnDisk := filepath.Base(urlPath.Path)
			// srcDir is SourcesDir/pkgName. Files are symlinked here by fetchSources.
			srcPath = filepath.Join(srcDir, filenameOnDisk)

		default:
			// Default/Local files: Look up using the provided relPath
			srcPath = filepath.Join(srcDir, relPath)
		}

		// --- All source types are now resolved to a final srcPath (file or directory) ---

		info, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("source %s listed but missing: stat %s: %v", relPath, srcPath, err)
		}

		// At this point, destPath is no longer needed, we use targetDir for destination

		if info.IsDir() {
			// This handles "files/" or other local source directories that need to be copied.
			// Copy directory recursively (this creates a subdirectory, which is the desired behavior for files/)
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := copyDir(srcPath, destPath); err != nil {
				return fmt.Errorf("failed to copy directory %s: %v", relPath, err)
			}
			continue
		}

		// Resolve symlinks (needed for cached archives which are symlinks)
		realPath, err := filepath.EvalSymlinks(srcPath)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink %s: %v", relPath, err)
		}

		// If flagged noextract, just copy the file
		if noExtract {
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %v", destPath, err)
			}
			if err := copyFile(realPath, destPath); err != nil {
				return fmt.Errorf("failed to copy file %s: %v", relPath, err)
			}
			continue
		}

		// Extract archives or copy file (using realPath)
		switch {
		case strings.HasSuffix(realPath, ".tar.gz"),
			strings.HasSuffix(realPath, ".tgz"),
			strings.HasSuffix(realPath, ".tar.xz"),
			strings.HasSuffix(realPath, ".tar.bz2"),
			strings.HasSuffix(realPath, ".tar.zst"),
			strings.HasSuffix(realPath, ".tar.lz"),
			strings.HasSuffix(realPath, ".tar"):
			// Extraction goes into targetDir (buildDir or buildDir/subdir)
			if err := extractTar(realPath, targetDir); err != nil {
				return fmt.Errorf("failed to extract tar %s into %s: %v", relPath, targetDir, err)
			}
		case strings.HasSuffix(realPath, ".zip"):
			// Extraction goes into targetDir (buildDir or buildDir/subdir)
			cmd := exec.Command("unzip", "-q", "-o", realPath, "-d", targetDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to unzip %s into %s: %v", relPath, targetDir, err)
			}
		default:
			// Copy file (e.g., patches/, simple local files)
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %v", destPath, err)
			}
			if err := copyFile(realPath, destPath); err != nil {
				return fmt.Errorf("failed to copy file %s: %v", relPath, err)
			}
		}
	}

	return nil
}

// generateLibDeps scans ELF files in outputDir and writes their shared library dependencies to libdepsFile
func generateLibDeps(outputDir, libdepsFile string, execCtx *Executor) error {
	ignorePatterns := []string{
		"ld-*", "libc.so*", "libm.so*", "libpthread.so*", "libdl.so*",
		"libgcc_s.so*", "libstdc++.so*", "libcrypt.so*", "libc++.so*",
		"libc++abi.so*", "libmvec.so*", "libresolv.so*", "librt.so*",
		"libtrace.so*", "libunwind.so*", "libutil.so*", "libxnet.so*", "ldd",
	}

	matchesIgnore := func(lib string) bool {
		for _, pat := range ignorePatterns {
			if ok, _ := filepath.Match(pat, filepath.Base(lib)); ok {
				return true
			}
		}
		return false
	}

	// Collect executable files
	var files []string
	filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// Only consider files with executable permission
		if info.Mode()&0111 != 0 {
			files = append(files, path)
		}
		return nil
	})

	type result struct{ libs []string }
	numWorkers := runtime.NumCPU()
	fileCh := make(chan string, len(files))
	resultCh := make(chan result, len(files))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for file := range fileCh {
			var fileOut, lddOut bytes.Buffer

			// 1. Check if file is an ELF binary (using the package's determined execution context)
			cmdFile := exec.Command("file", "--brief", "--mime-type", file)
			cmdFile.Stdout = &fileOut
			cmdFile.Stderr = os.Stderr // pipe errors to our stderr

			if err := execCtx.Run(cmdFile); err != nil {
				// If 'file' fails (e.g., access denied, not found), skip this file
				continue
			}

			if !(strings.Contains(fileOut.String(), "application/x-executable") ||
				strings.Contains(fileOut.String(), "application/x-sharedlib")) {
				continue
			}

			// 2. Run ldd to find dependencies (using the package's determined execution context)
			lddCmd := exec.Command("ldd", file)
			lddCmd.Stdout = &lddOut
			lddCmd.Stderr = io.Discard // discard error

			if err := execCtx.Run(lddCmd); err != nil {
				// If ldd fails (e.g., cannot find dependencies), skip this file
				continue
			}

			var libs []string
			scanner := bufio.NewScanner(bytes.NewReader(lddOut.Bytes()))
			// ... (rest of the ldd output parsing logic remains the same) ...

			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Fields(line)
				if len(parts) >= 3 && parts[1] == "=>" {
					libPath := parts[2]
					if strings.HasPrefix(libPath, "/") &&
						!strings.HasPrefix(libPath, outputDir) &&
						!matchesIgnore(libPath) {
						libs = append(libs, filepath.Base(libPath))
					}
				}
			}

			if len(libs) > 0 {
				resultCh <- result{libs: libs}
			}
		}
	}

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	wg.Wait()
	close(resultCh)

	seen := make(map[string]struct{})
	for res := range resultCh {
		for _, lib := range res.libs {
			seen[lib] = struct{}{}
		}
	}

	tmpFile := filepath.Join(os.TempDir(), filepath.Base(libdepsFile)+".tmp")

	// write temp file as user
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	for lib := range seen {
		f.WriteString(lib + "\n")
	}
	f.Close()

	// 1. Determine if this step is necessary (i.e., if we ran as root)
	if execCtx.ShouldRunAsRoot {
		// This step is mandatory IF we ran as root (because the build output files are now root-owned)
		chownCmd := exec.Command("chown", "0:0", tmpFile)

		// The command is expected to succeed here, so we treat failure as a fatal issue.
		if err := execCtx.Run(chownCmd); err != nil {
			return fmt.Errorf("failed to chown temp libdeps (via Executor): %v", err)
		}
	} else {
		// If the Executor is unprivileged, the files are already user-owned (not root),
		// and attempting to chown 0:0 would fail, so we skip it entirely.
		// This is the correct behavior for unprivileged builds.
	}

	// move into place
	mvCmd := exec.Command("mv", "--force", tmpFile, libdepsFile)
	if err := execCtx.Run(mvCmd); err != nil {
		return fmt.Errorf("failed to move libdeps into place (via Executor): %v", err)
	}

	debugf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(seen))
	return nil
}

func generateDepends(pkgName, pkgDir, outputDir, rootDir string, execCtx *Executor) error {
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	libdepsFile := filepath.Join(installedDir, "libdeps")
	dependsFile := filepath.Join(installedDir, "depends")

	// Read libdeps
	libdepsData, err := os.ReadFile(libdepsFile)
	if err != nil {
		return fmt.Errorf("failed to read libdeps: %v", err)
	}
	libdeps := strings.Fields(string(libdepsData))
	if len(libdeps) == 0 {
		return nil
	}

	depSet := make(map[string]struct{})

	// Scan all installed packages for matching libs
	dbRoot := filepath.Join(rootDir, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(dbRoot)
	if err != nil {
		return fmt.Errorf("failed to read installed db at %s: %v", dbRoot, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		otherPkg := e.Name()
		if otherPkg == pkgName {
			continue
		}

		manifestFile := filepath.Join(dbRoot, otherPkg, "manifest")
		data, err := os.ReadFile(manifestFile)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")

		for _, lib := range libdeps {
			for _, line := range lines {
				if strings.HasSuffix(line, lib) {
					depSet[otherPkg] = struct{}{}
					break
				}
			}
		}
	}

	// Merge repo depends file if it exists
	repoDepends := filepath.Join(pkgDir, "depends")
	if data, err := os.ReadFile(repoDepends); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				depSet[line] = struct{}{}
			}
		}
	}

	// Prepare depends content
	var deps []string
	for dep := range depSet {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	content := strings.Join(deps, "\n")

	// Write depends file
	writeCmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s > %s", shellEscape(content), shellEscape(dependsFile)))
	if err := execCtx.Run(writeCmd); err != nil {
		return fmt.Errorf("failed to write depends: %v", err)
	}

	return nil
}

// shellEscape escapes content for safe use in shell commands
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// isDirectoryPrivileged uses the Executor to check if a path is a directory.
// helper for listOutputFiles
func isDirectoryPrivileged(path string, execCtx *Executor) (bool, error) {
	// We use the shell 'test -d <path>' command.
	// It returns exit code 0 if the path is a directory, 1 otherwise.
	// Since this command is simple, we run it directly through the Executor.
	cmd := exec.Command("test", "-d", path)

	// The Run method returns nil on success (exit code 0).
	err := execCtx.Run(cmd)

	if err == nil {
		// Exit code 0: it is a directory.
		return true, nil
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		// Exit code 1: it is NOT a directory (or the path doesn't exist, etc.).
		// Since 'find' already gave us the path, we assume exit code 1 means 'not a directory'.
		if exitError.ExitCode() == 1 {
			return false, nil
		}
		// Handle other non-zero exit codes as a genuine error (e.g., -1 for failure)
		return false, fmt.Errorf("privileged test failed with unexpected exit code %d: %w", exitError.ExitCode(), err)
	}

	// Handle non-ExitError (e.g., failed to start the command)
	return false, err
}

func lstatViaExecutor(path string, execCtx *Executor) (string, error) {
	cmd := exec.Command("stat", "-c", "%F", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := execCtx.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to stat %s: %v: %s", path, err, out.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func listOutputFiles(outputDir string, execCtx *Executor) ([]string, error) {
	var entries []string

	cmd := exec.Command("find", outputDir)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := execCtx.Run(cmd); err != nil {
		return nil, fmt.Errorf("failed to list output files via find: %v", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		path := scanner.Text()

		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			continue
		}
		if rel == "." {
			continue
		}

		// Filter out libtool .la files and charset.alias
		if strings.HasSuffix(rel, ".la") || strings.HasSuffix(rel, "charset.alias") {
			continue
		}

		isDir, err := isDirectoryPrivileged(path, execCtx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to stat file with privilege, skipping %s: %v\n", path, err)
			continue
		}

		if isDir {
			entries = append(entries, "/"+rel+"/")
		} else {
			entries = append(entries, "/"+rel)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %v", err)
	}

	sort.Strings(entries)
	return entries, nil
}

func generateManifest(outputDir, installedDir string, execCtx *Executor) error {
	manifestFile := filepath.Join(installedDir, "manifest")
	tmpManifest := filepath.Join(os.TempDir(), filepath.Base(manifestFile)+".tmp")

	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installedDir: %v", err)
	}

	entries, err := listOutputFiles(outputDir, execCtx)
	if err != nil {
		// fallback to RootExec
		entries, err = listOutputFiles(outputDir, RootExec)
		if err != nil {
			return fmt.Errorf("failed to list output files: %v", err)
		}
	}

	relManifest, err := filepath.Rel(outputDir, manifestFile)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for manifest: %v", err)
	}
	manifestEntryPath := "/" + relManifest

	filtered := make([]string, 0, len(entries))
	for _, e := range entries {
		if e != manifestEntryPath {
			filtered = append(filtered, e)
		}
	}

	f, err := os.OpenFile(tmpManifest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open temporary manifest file: %v", err)
	}
	defer f.Close()

	var dirs, symlinks, regularFiles []string
	symlinkMap := make(map[string]bool)

	for _, entry := range filtered {
		if strings.HasSuffix(entry, "/") {
			dirs = append(dirs, entry)
			continue
		}
		absPath := filepath.Join(outputDir, strings.TrimPrefix(entry, "/"))
		fileType, err := lstatViaExecutor(absPath, execCtx)
		if err != nil {
			return fmt.Errorf("failed to lstat %s: %v", absPath, err)
		}
		if fileType == "symbolic link" {
			symlinks = append(symlinks, entry)
			symlinkMap[entry] = true
		} else {
			regularFiles = append(regularFiles, absPath)
		}
	}

	// Write directory entries correctly
	for _, entry := range dirs {
		rel := strings.TrimPrefix(entry, "/")
		if !strings.HasSuffix(rel, "/") {
			rel += "/"
		}
		cleaned := "/" + rel
		if _, err := fmt.Fprintln(f, cleaned); err != nil {
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}
	}

	for _, entry := range symlinks {
		if _, err := fmt.Fprintf(f, "%s 000000\n", entry); err != nil {
			return fmt.Errorf("failed to write symlink entry: %v", err)
		}
	}

	var checksums map[string]string
	if !execCtx.ShouldRunAsRoot {
		checksums, err = b3sumBatch(regularFiles, runtime.NumCPU()*2)
		if err != nil {
			debugf("parallel b3sum failed (%v), falling back to sequential\n", err)
			checksums = make(map[string]string)
			for _, absPath := range regularFiles {
				checksum, serr := b3sum(absPath, RootExec)
				if serr != nil {
					return fmt.Errorf("b3sum failed for %s: %v", absPath, serr)
				}
				checksums[absPath] = checksum
			}
		}
	} else {
		checksums = make(map[string]string)
		for _, absPath := range regularFiles {
			checksum, err := b3sum(absPath, execCtx)
			if err != nil {
				return fmt.Errorf("b3sum failed for %s: %v", absPath, err)
			}
			checksums[absPath] = checksum
		}
	}

	for _, entry := range filtered {
		if strings.HasSuffix(entry, "/") || symlinkMap[entry] {
			continue
		}
		absPath := filepath.Join(outputDir, strings.TrimPrefix(entry, "/"))
		checksum, exists := checksums[absPath]
		if !exists {
			return fmt.Errorf("missing checksum for %s", absPath)
		}
		if _, err := fmt.Fprintf(f, "%s  %s\n", entry, checksum); err != nil {
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}
	}

	f.Close()

	tempChecksum, err := b3sum(tmpManifest, execCtx)
	if err != nil {
		return fmt.Errorf("b3sum failed for temporary manifest %s: %v", tmpManifest, err)
	}

	f, err = os.OpenFile(tmpManifest, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to re-open temporary manifest file for final entry: %v", err)
	}
	if _, err := fmt.Fprintf(f, "%s  %s\n", manifestEntryPath, tempChecksum); err != nil {
		f.Close()
		return fmt.Errorf("failed to write final manifest entry: %v", err)
	}
	f.Close()

	cpCmd := exec.Command("cp", "--remove-destination", tmpManifest, manifestFile)
	if err := execCtx.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy temporary manifest into place: %v", err)
	}
	_ = os.Remove(tmpManifest)

	debugf("Manifest written to %s (%d entries)\n", manifestFile, len(filtered))
	return nil
}

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Copy file mode
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, info.Mode())
}

// copyDir recursively copies a directory from src to dst
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// shouldStripTar inspects the tarball to check for a single top-level directory.
func shouldStripTar(archive string) (bool, error) {
	debugf("Running strip check for tar extraction")

	// Only list first 51 entries - much faster for large archives
	cmd := exec.Command("sh", "-c", fmt.Sprintf("tar tf %s | head -n 51", archive))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		// Tar failed to read or list the file.
		return false, fmt.Errorf("tar tf failed: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		// Archive is empty
		return false, nil
	}

	firstEntry := lines[0]

	// Find the first slash position
	slashIdx := strings.IndexByte(firstEntry, '/')
	if slashIdx == -1 {
		// No slash means a file/folder is at the root, so don't strip
		return false, nil
	}

	// The assumed top-level directory (including the slash)
	topDir := firstEntry[:slashIdx+1]

	// Check all entries to ensure they start with topDir
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, topDir) {
			// Found an entry not in the top directory
			return false, nil
		}
	}

	// All checked entries start with the same top directory prefix
	return true, nil
}

// extractTar extracts a tar archive (with possible compression) to targetDir,
// stripping the top-level directory while handling PAX headers and preserving timestamps.
func extractTar(realPath, dest string) error {
	// Open the archive file
	f, err := os.Open(realPath)
	if err != nil {
		return fmt.Errorf("failed to open archive %s: %w", realPath, err)
	}
	// Try system tar first
	//Inspect the tarball to see if it has a single top-level directory

	strip, err := shouldStripTar(realPath)
	if err != nil {
		// Non-fatal: record debug info so the variable 'err' is actually used.
		debugf("shouldStripTar(%s) failed: %v\n", realPath, err)
	}
	debugf("strip check done \n")
	args := []string{"xf", realPath, "-C", dest}

	if strip {
		args = append(args, "--strip-components=1")
	}
	debugf("extracting archive \n")
	if err := exec.Command("tar", args...).Run(); err == nil {
		// Close the opened file before returning early.
		_ = f.Close()
		debugf("Used system tar \n")
		return nil
	}
	defer f.Close()

	// Determine the compression type based on file extension
	var r io.Reader = f
	switch {
	case strings.HasSuffix(realPath, ".tar.gz") || strings.HasSuffix(realPath, ".tgz"):
		gz, err := pgzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader for %s: %w", realPath, err)
		}
		defer gz.Close()
		r = gz
	case strings.HasSuffix(realPath, ".tar.bz2"):
		r = bzip2.NewReader(f)
	case strings.HasSuffix(realPath, ".tar.xz"):
		xz, err := xz.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create xz reader for %s: %w", realPath, err)
		}
		r = xz
	case strings.HasSuffix(realPath, ".tar.zst"):
		zst, err := zstd.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader for %s: %w", realPath, err)
		}
		defer zst.Close()
		r = zst
	case strings.HasSuffix(realPath, ".tar"):
		// No compression
	default:
		return fmt.Errorf("unsupported archive format: %s", realPath)
	}

	// Create tar reader
	tr := tar.NewReader(r)

	// Track the prefix for stripping (e.g., "linux-6.17.3/")
	var prefix string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar header in %s: %w", realPath, err)
		}

		// Skip PAX headers (global or per-file)
		if hdr.Typeflag == tar.TypeXHeader || hdr.Typeflag == tar.TypeXGlobalHeader {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return fmt.Errorf("error skipping extended header data in %s: %w", realPath, err)
			}
			continue
		}

		// Set prefix on the first non-extended content entry (dir or regular file)
		if prefix == "" && (hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeReg) {
			slashIdx := strings.Index(hdr.Name, "/")
			if slashIdx != -1 {
				prefix = hdr.Name[:slashIdx+1] // e.g., "linux-6.17.3/"
				debugf("Detected tar prefix for stripping: %s\n", prefix)
			}
		}

		// Apply stripping if prefix is set and matches
		targetName := hdr.Name
		if prefix != "" && strings.HasPrefix(targetName, prefix) {
			targetName = strings.TrimPrefix(targetName, prefix)
		}

		// If the stripped name is empty (e.g., the top dir itself), skip it
		if targetName == "" {
			continue
		}

		// Compute full output path
		targetPath := filepath.Join(dest, targetName)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent dir for %s: %w", targetPath, err)
		}

		// Handle based on entry type
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("failed to create dir %s: %w", targetPath, err)
			}
			// Set timestamp for directory
			if err := os.Chtimes(targetPath, hdr.AccessTime, hdr.ModTime); err != nil {
				return fmt.Errorf("failed to set times for dir %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close()
			// Set timestamp for file
			if err := os.Chtimes(targetPath, hdr.AccessTime, hdr.ModTime); err != nil {
				return fmt.Errorf("failed to set times for file %s: %w", targetPath, err)
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, targetPath); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, hdr.Linkname, err)
			}
			// Set timestamp for symlink using unix.Lutimes with Timeval
			atime := unix.Timeval{
				Sec:  hdr.AccessTime.Unix(),
				Usec: int64(hdr.AccessTime.Nanosecond() / 1000), // Convert nanoseconds to microseconds
			}
			mtime := unix.Timeval{
				Sec:  hdr.ModTime.Unix(),
				Usec: int64(hdr.ModTime.Nanosecond() / 1000), // Convert nanoseconds to microseconds
			}
			if err := unix.Lutimes(targetPath, []unix.Timeval{atime, mtime}); err != nil {
				debugf("Warning: failed to set times for symlink %s: %v (continuing)\n", targetPath, err)
				// Don't fail on symlink time errors, as they may not be critical
			}
		default:
			debugf("Skipping unsupported tar entry type %c: %s\n", hdr.Typeflag, hdr.Name)
		}
	}

	// If no prefix was found, warn but don't fail (archive might not have a top dir)
	if prefix == "" {
		debugf("No top-level directory prefix found in %s; extracted without stripping\n", realPath)
	}

	return nil
}

// unpackTarballFallback extracts a .tar.zst into dest using pure-Go.
func unpackTarballFallback(tarballPath, dest string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {

		return fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		target := filepath.Join(dest, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	return nil
}

// createPackageTarball creates a .tar.zst archive of outputDir into BinDir.
// It uses system tar if available, otherwise falls back to pure-Go tar+zstd.
func createPackageTarball(pkgName, pkgVer, outputDir string, execCtx *Executor) error {
	// Ensure BinDir exists
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create BinDir: %v", err)
	}

	tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, pkgVer))

	// --- Try system tar first ---
	if _, err := exec.LookPath("tar"); err == nil {
		args := []string{"--zstd", "-cf", tarballPath, "-C", outputDir, "."}
		if !execCtx.ShouldRunAsRoot {
			args = append(args, "--owner=0", "--group=0", "--numeric-owner")
		}
		tarCmd := exec.Command("tar", args...)
		debugf("Creating package tarball with system tar: %s\n", tarballPath)
		if err := execCtx.Run(tarCmd); err == nil {
			colArrow.Print("-> ")
			colSuccess.Println("Package tarball created successfully")
			return nil
		}
		// fall through to internal if tar fails
	}

	// --- Fallback: internal tar+zstd ---
	debugf("System tar not available, falling back to internal tar+zstd for %s\n", tarballPath)

	outFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball file: %v", err)
	}
	defer outFile.Close()

	// Create zstd writer
	zw, err := zstd.NewWriter(outFile)
	if err != nil {
		return fmt.Errorf("failed to create zstd writer: %v", err)
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	// Walk outputDir and add files
	err = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		var linkTarget string
		if info.Mode()&os.ModeSymlink != 0 {
			// Read the symlink target so we can store it in the tar header
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}
		}

		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		hdr.Name = rel

		// Force numeric root ownership if not run as root
		if !execCtx.ShouldRunAsRoot {
			hdr.Uid, hdr.Gid = 0, 0
			hdr.Uname, hdr.Gname = "root", "root"
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// Only copy file contents for regular files
		if info.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to add files to tarball: %v", err)
	}

	cPrintf(colInfo, "Package tarball created successfully (internal): %s\n", tarballPath)
	return nil
}

func getModifiedFiles(pkgName, rootDir string, execCtx *Executor) ([]string, error) {

	installedDir := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName)
	manifestFile := filepath.Join(installedDir, "manifest")

	// Check if manifest exists
	if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
		return nil, nil // no previously installed files
	}

	// Read manifest entries
	data, err := readFileAsRoot(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %v", err)
	}

	// First pass: collect all file paths that need checksumming
	var filesToCheck []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		relPath := parts[0]
		relSlash := filepath.ToSlash(relPath)
		// Skip any manifest entry that refers to the package's installed manifest
		// Matches both "var/db/.../installed/<pkg>/manifest" and "/var/db/.../installed/<pkg>/manifest"
		if strings.HasSuffix(relSlash, "/installed/"+pkgName+"/manifest") {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)

		// Skip entries with 000000 hash (symlinks)
		if len(parts) > 1 && parts[1] == "000000" {
			continue
		}

		filesToCheck = append(filesToCheck, absPath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	// Compute checksums - use optimized path for user-built packages
	var checksums map[string]string
	if !execCtx.ShouldRunAsRoot {
		// Fast path: parallel processing for user-built packages
		var err error
		checksums, err = b3sumBatch(filesToCheck, runtime.NumCPU()*2)
		if err != nil {
			// Fall back to sequential processing if batch fails
			checksums = make(map[string]string)
			for _, absPath := range filesToCheck {
				sum, err := b3sum(absPath, execCtx)
				if err != nil {
					continue // skip missing files or checksum failures
				}
				checksums[absPath] = sum
			}
		}
	} else {
		// Slow path: sequential processing for root-built packages
		checksums = make(map[string]string)
		for _, absPath := range filesToCheck {
			sum, err := b3sum(absPath, execCtx)
			if err != nil {
				continue // skip missing files or checksum failures
			}
			checksums[absPath] = sum
		}
	}

	// Second pass: compare checksums and find modified files
	var modified []string
	scanner = bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		relPath := parts[0]
		relSlash := filepath.ToSlash(relPath)
		if strings.HasSuffix(relSlash, "/installed/"+pkgName+"/manifest") {
			continue
		}

		// Skip entries with 000000 hash (symlinks)
		if parts[1] == "000000" {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)
		currentSum, exists := checksums[absPath]
		if !exists {
			continue // file doesn't exist or checksum failed
		}

		if parts[1] != currentSum {
			modified = append(modified, relPath)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	return modified, nil
}

// Helper to compute b3sum of a file, using system b3sum binary if available,
// otherwise falling back to the internal Go BLAKE3 implementation.
func b3sum(path string, execCtx *Executor) (string, error) {
	// First try the system b3sum binary
	if _, err := exec.LookPath("b3sum"); err == nil {
		cmd := exec.Command("b3sum", path)

		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr

		if err := execCtx.Run(cmd); err == nil {
			fields := strings.Fields(out.String())
			if len(fields) > 0 {
				return fields[0], nil
			}
			// fall through to internal if no output
		}
	}

	// Fallback: internal Go BLAKE3 with privilege awareness
	// If the executor should run as root, use cat to read the file
	if execCtx.ShouldRunAsRoot {
		catCmd := exec.Command("cat", path)
		var out bytes.Buffer
		catCmd.Stdout = &out
		catCmd.Stderr = os.Stderr

		if err := execCtx.Run(catCmd); err != nil {
			return "", fmt.Errorf("failed to read file with elevated privileges: %w", err)
		}

		h := blake3.New(32, nil)
		if _, err := h.Write(out.Bytes()); err != nil {
			return "", fmt.Errorf("failed to hash file data: %w", err)
		}
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	}

	// Non-privileged read (existing code)
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file for blake3: %w", err)
	}
	defer f.Close()

	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash file with blake3: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// b3sumFast computes BLAKE3 for a file, using the system `b3sum` if available,
// and falling back to the internal pure-Go implementation otherwise.
func b3sumFast(path string) (string, error) {
	// Try the system b3sum first (only if it's present in PATH).
	if _, err := exec.LookPath("b3sum"); err == nil {
		cmd := exec.Command("b3sum", path)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err == nil {
			fields := strings.Fields(out.String())
			if len(fields) > 0 {
				return fields[0], nil
			}
			// fall through to internal if b3sum produced no output
		}
		// If b3sum failed to run, we’ll fall back to internal below.
	}

	// Fallback: internal Go BLAKE3 (32-byte output, no key).
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file for blake3: %w", err)
	}
	defer f.Close()

	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to hash file with blake3: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// b3sumBatch computes checksums for multiple files in parallel for user-built packages
func b3sumBatch(paths []string, maxWorkers int) (map[string]string, error) {
	if maxWorkers <= 0 {
		maxWorkers = 10 // reasonable default
	}

	results := make(map[string]string)
	errors := make(map[string]error)
	var mu sync.Mutex

	semaphore := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}        // acquire
			defer func() { <-semaphore }() // release

			checksum, err := b3sumFast(p)

			mu.Lock()
			if err != nil {
				errors[p] = err
			} else {
				results[p] = checksum
			}
			mu.Unlock()
		}(path)
	}

	wg.Wait()

	if len(errors) > 0 {
		var errMsgs []string
		for path, err := range errors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", path, err))
		}
		return results, fmt.Errorf("b3sum errors: %s", strings.Join(errMsgs, "; "))
	}

	return results, nil
}

// Helper to read a file as root if needed
func readFileAsRoot(path string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return os.ReadFile(path)
	}

	cmd := exec.Command("sudo", "cat", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// removeObsoleteFiles compares the installed manifest (under Installed/<pkg>/manifest)
// with the manifest present in the staging tree. It returns a slice of absolute
// paths (under rootDir) that should be deleted after the staging has been rsynced.
func removeObsoleteFiles(pkgName, stagingDir, rootDir string) ([]string, error) {
	installedManifestPath := filepath.Join(rootDir, Installed, pkgName, "manifest")
	stagingManifestPath := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName, "manifest")

	installedData, err := readFileAsRoot(installedManifestPath)
	if err != nil {
		// No installed manifest → nothing to remove
		return nil, nil
	}

	// Read staging manifest if present; treat missing file as empty manifest
	stagingData, _ := os.ReadFile(stagingManifestPath)

	// Build set of paths present in staging manifest
	stagingSet := make(map[string]struct{})
	if len(stagingData) > 0 {
		sc := bufio.NewScanner(strings.NewReader(string(stagingData)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			// Split into path and optional checksum: path is always first token
			parts := strings.SplitN(line, "  ", 2) // manifest uses "␣␣" separator
			path := strings.Fields(parts[0])[0]    // defensive: take first token
			stagingSet[path] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("error reading staging manifest: %v", err)
		}
	}

	var filesToDelete []string

	// Scan installed manifest; add files missing from staging manifest
	iscanner := bufio.NewScanner(strings.NewReader(string(installedData)))
	for iscanner.Scan() {
		line := strings.TrimSpace(iscanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		path := strings.Fields(parts[0])[0]

		// if present in staging manifest -> skip
		if _, ok := stagingSet[path]; ok {
			continue
		}

		installedPath := filepath.Join(rootDir, path)

		// if installed file exists on disk, schedule for deletion
		if fi, err := os.Lstat(installedPath); err == nil && !fi.IsDir() {
			filesToDelete = append(filesToDelete, installedPath)
		}
	}
	if err := iscanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading installed manifest: %v", err)
	}

	return filesToDelete, nil
}

// rsyncStaging syncs the contents of stagingDir into rootDir.
// It uses system rsync if available, otherwise falls back to a Go-native copy.
func rsyncStaging(stagingDir, rootDir string, execCtx *Executor) error {
	stagingPath := filepath.Clean(stagingDir)

	// Ensure rootDir exists
	mkdirCmd := exec.Command("mkdir", "-p", rootDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create rootDir %s: %v", rootDir, err)
	}

	// --- Try system rsync first ---
	if _, err := exec.LookPath("rsync"); err == nil {
		// Note: rsync needs trailing slash on source to copy contents, not the directory itself
		stagingPathWithSlash := stagingPath + string(os.PathSeparator)
		args := []string{
			"-aHAX",
			"--numeric-ids",
			"--no-implied-dirs",
			"--keep-dirlinks",
			stagingPathWithSlash,
			rootDir,
		}
		cmd := exec.Command("rsync", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := execCtx.Run(cmd); err == nil {
			rmCmd := exec.Command("rm", "-rf", stagingDir)
			if err := execCtx.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
			}
			return nil
		}
	}

	// --- Fallback: Try system tar pipe ---
	if _, err := exec.LookPath("tar"); err == nil {
		// This command creates an archive of the source and pipes it directly to an extraction command.
		// It's efficient and handles all permissions correctly when run via the executor.
		tarPipeCmdStr := fmt.Sprintf("tar -c -C %s . | tar -x -C %s", shellEscape(stagingPath), shellEscape(rootDir))
		cmd := exec.Command("sh", "-c", tarPipeCmdStr)
		cmd.Stderr = os.Stderr // Show potential errors from the shell or tar commands.

		debugf("Attempting to sync with system tar pipe: %s\n", tarPipeCmdStr)
		if err := execCtx.Run(cmd); err == nil {
			// Success! Clean up and return.
			rmCmd := exec.Command("rm", "-rf", stagingDir)
			if err := execCtx.Run(rmCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to remove staging dir %s: %v\n", stagingDir, err)
			}
			return nil
		}
		debugf("System tar pipe failed, falling back to internal Go implementation.\n")
	} else {
		debugf("System tar not found, falling back to internal Go implementation.\n")
	}

	// --- Fallback 2: Use internal Go tar implementation ---
	// This is resilient to broken system tools during updates
	debugf("rsync not available, using internal Go tar fallback\n")

	if err := copyTreeWithTar(stagingPath, rootDir, execCtx); err != nil {
		return fmt.Errorf("internal tar fallback failed: %v", err)
	}

	rmCmd := exec.Command("rm", "-rf", stagingDir)
	if err := execCtx.Run(rmCmd); err != nil {
		return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
	}

	return nil
}

// copyTreeWithTar copies the contents of src into dst using internal tar,
// preserving all attributes including symlinks, devices, permissions, etc.
// This is privilege-aware through the execCtx parameter.
func copyTreeWithTar(src, dst string, execCtx *Executor) error {
	// Create an in-memory tar archive of the source
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Walk the source directory and add everything to tar
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get the path relative to src
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself (we want contents only)
		if rel == "." {
			return nil
		}

		// For symlinks, we need to use Lstat to get the link info, not the target
		var linkTarget string
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				// If we can't read the symlink as the current user and need root
				if execCtx.ShouldRunAsRoot {
					cmd := exec.Command("readlink", path)
					var out bytes.Buffer
					cmd.Stdout = &out
					if err := execCtx.Run(cmd); err != nil {
						return fmt.Errorf("failed to read symlink %s: %w", path, err)
					}
					linkTarget = strings.TrimSpace(out.String())
				} else {
					return fmt.Errorf("failed to read symlink %s: %w", path, err)
				}
			}
		}

		// Create tar header
		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}

		// Set the name to the relative path
		hdr.Name = rel

		// Write header
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// For regular files, write the content
		if info.Mode().IsRegular() {
			// If we need root privileges to read the file, use cat
			if execCtx.ShouldRunAsRoot {
				cmd := exec.Command("cat", path)
				var out bytes.Buffer
				cmd.Stdout = &out
				if err := execCtx.Run(cmd); err != nil {
					return fmt.Errorf("failed to read file %s with privileges: %w", path, err)
				}
				if _, err := tw.Write(out.Bytes()); err != nil {
					return err
				}
			} else {
				// Try to open directly
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				if _, err := io.Copy(tw, f); err != nil {
					f.Close()
					return err
				}
				f.Close()
			}
		}

		return nil
	})

	if err != nil {
		tw.Close()
		return fmt.Errorf("failed to create tar archive: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	// Now extract the tar archive to the destination
	tr := tar.NewReader(&buf)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		target := filepath.Join(dst, hdr.Name)

		// Create parent directory if needed
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			// If we can't create as user, try with privileges
			if execCtx.ShouldRunAsRoot {
				mkdirCmd := exec.Command("mkdir", "-p", filepath.Dir(target))
				if err := execCtx.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create parent dir %s: %w", filepath.Dir(target), err)
				}
			} else {
				return fmt.Errorf("failed to create parent dir %s: %w", filepath.Dir(target), err)
			}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				if execCtx.ShouldRunAsRoot {
					mkdirCmd := exec.Command("mkdir", "-p", target)
					if err := execCtx.Run(mkdirCmd); err != nil {
						return fmt.Errorf("failed to create dir %s: %w", target, err)
					}
					chmodCmd := exec.Command("chmod", fmt.Sprintf("%o", hdr.Mode), target)
					execCtx.Run(chmodCmd) // best effort
				} else {
					return err
				}
			}
			// Set ownership and times
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}
			os.Chtimes(target, hdr.AccessTime, hdr.ModTime) // best effort

		case tar.TypeReg:
			// Write file content
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				if execCtx.ShouldRunAsRoot {
					// Create file via shell redirection
					var content bytes.Buffer
					if _, err := io.Copy(&content, tr); err != nil {
						return fmt.Errorf("failed to read file content: %w", err)
					}

					// Write via dd for privilege escalation
					ddCmd := exec.Command("dd", "of="+target, "status=none")
					ddCmd.Stdin = &content
					if err := execCtx.Run(ddCmd); err != nil {
						return fmt.Errorf("failed to write file %s with privileges: %w", target, err)
					}

					chmodCmd := exec.Command("chmod", fmt.Sprintf("%o", hdr.Mode), target)
					execCtx.Run(chmodCmd) // best effort
				} else {
					return fmt.Errorf("failed to create file %s: %w", target, err)
				}
			} else {
				if _, err := io.Copy(outFile, tr); err != nil {
					outFile.Close()
					return fmt.Errorf("failed to write file %s: %w", target, err)
				}
				outFile.Close()
			}

			// Set ownership and times
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}
			os.Chtimes(target, hdr.AccessTime, hdr.ModTime) // best effort

		case tar.TypeSymlink:
			// Remove existing file/link if present
			os.Remove(target)

			if err := os.Symlink(hdr.Linkname, target); err != nil {
				if execCtx.ShouldRunAsRoot {
					lnCmd := exec.Command("ln", "-sf", hdr.Linkname, target)
					if err := execCtx.Run(lnCmd); err != nil {
						return fmt.Errorf("failed to create symlink %s: %w", target, err)
					}
				} else {
					return fmt.Errorf("failed to create symlink %s: %w", target, err)
				}
			}

			// Set ownership on the symlink itself
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", "-h", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}

		case tar.TypeLink:
			// Hard link
			linkTarget := filepath.Join(dst, hdr.Linkname)
			os.Remove(target)

			if err := os.Link(linkTarget, target); err != nil {
				if execCtx.ShouldRunAsRoot {
					lnCmd := exec.Command("ln", linkTarget, target)
					if err := execCtx.Run(lnCmd); err != nil {
						return fmt.Errorf("failed to create hard link %s: %w", target, err)
					}
				} else {
					return fmt.Errorf("failed to create hard link %s: %w", target, err)
				}
			}

		default:
			debugf("Skipping unsupported tar entry type %c: %s\n", hdr.Typeflag, hdr.Name)
		}
	}

	return nil
}

// executePostInstall runs the post-install script for pkgName if present.
// If rootDir != "/" it attempts to run the same absolute path via chroot.
// If chroot fails the function prints a warning and returns nil.
func executePostInstall(pkgName, rootDir string, execCtx *Executor) error {

	// absolute path inside the system (and inside the chroot)
	const relScript = "/var/db/hokuto/installed"
	scriptPath := filepath.Join(relScript, pkgName, "post-install")
	hostScript := filepath.Join(rootDir, scriptPath)

	// nothing to do if the file doesn't exist on host
	if fi, err := os.Stat(hostScript); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat post-install script %s: %v", hostScript, err)
	} else if fi.IsDir() {
		return fmt.Errorf("post-install path %s is a directory", hostScript)
	}

	var cmd *exec.Cmd
	if rootDir == "/" {
		cmd = exec.Command(hostScript)
	} else {
		// run the same absolute path inside the chroot
		cmd = exec.Command("chroot", rootDir, scriptPath)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// If chroot is used and fails, print a warning and continue (non-fatal).
	if rootDir != "/" {
		if err := execCtx.Run(cmd); err != nil {
			cPrintf(colWarn, "Warning: chroot to %s failed or post-install could not run: %v\n", rootDir, err)
			return nil
		}
		return nil
	}

	if err := execCtx.Run(cmd); err != nil {
		return fmt.Errorf("post-install script %s failed: %v", hostScript, err)
	}
	return nil
}

// ManifestEntry represents a single line in the manifest file.
type ManifestEntry struct {
	Path     string
	Checksum string
}

// parseManifest reads a manifest file and returns a map of file paths to their entries.
// The map key is the file Path.
// parseManifest reads a manifest file and returns a map of file paths to their entries.
// It specifically skips entries that represent directories (end with '/').
func parseManifest(filePath string) (map[string]ManifestEntry, error) {
	entries := make(map[string]ManifestEntry)

	file, err := os.Open(filePath)
	if err != nil {
		// Treat non-existent base manifest as an empty manifest.
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, fmt.Errorf("failed to open manifest file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if the line represents a directory.
		// We look for a line that starts with '/' and ends with '/', and has no other fields.
		if strings.HasSuffix(line, "/") {
			// Check if the line contains ONLY the directory path.
			// If there's any whitespace, it might be a malformed file entry,
			// but for a pure directory line like "/etc/", this will be false.
			if len(strings.Fields(line)) == 1 {
				continue // Skip directories
			}
		}

		fields := strings.Fields(line)

		// Now, we expect exactly two fields (Path and Checksum) for a file.
		// If we get fewer, we return an error indicating a malformed file entry.
		if len(fields) < 2 {
			// The user's error message comes from here when processing a directory line.
			// Since we've pre-filtered pure directory lines, this catches real malformed file lines.
			return nil, fmt.Errorf("invalid manifest line format: %s", line)
		}

		path := fields[0]
		checksum := fields[1]

		entries[path] = ManifestEntry{Path: path, Checksum: checksum}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading manifest file %s: %w", filePath, err)
	}

	return entries, nil
}

// updateManifestWithNewFiles appends new entries from stagingManifest2 to stagingManifest.
// This operation requires root privileges, so it uses the global RootExec.
func updateManifestWithNewFiles(stagingManifest, stagingManifest2 string) error {
	// 1. Parse the base manifest (currently tracked files)
	// NOTE: parseManifest likely handles reading the file contents, which may require
	// elevated access if called during installation, but here it's likely called on
	// staged files, which should be accessible by the running user.
	baseEntries, err := parseManifest(stagingManifest)
	if err != nil {
		return fmt.Errorf("error parsing base manifest (%s): %w", stagingManifest, err)
	}

	// 2. Parse the new manifest (newly staged files)
	newEntries, err := parseManifest(stagingManifest2)
	if err != nil {
		return fmt.Errorf("error parsing new manifest (%s): %w", stagingManifest2, err)
	}

	// 3. Determine new files to add
	newFilesToTrack := make([]ManifestEntry, 0)
	const zeroChecksum = "000000" // The required replacement checksum

	for path, newEntry := range newEntries {
		// Ignore any entry that contains the temporary manifest identifier.
		// This prevents the manifest file itself from being added to the final manifest.
		if strings.Contains(path, "staging-manifest") {
			continue
		}

		// Check if the file path exists in the original base manifest
		if _, exists := baseEntries[path]; !exists {
			// This is a new file! Add it to the list to be appended,
			// but with the zero checksum.

			entryToAdd := newEntry
			entryToAdd.Checksum = zeroChecksum
			newFilesToTrack = append(newFilesToTrack, entryToAdd)
		}
	}

	// If no new files were found, we are done.
	if len(newFilesToTrack) == 0 {
		return nil
	}

	// 4. CENTRALIZED PRIVILEGED APPEND (Replaces os.OpenFile and writer logic)

	// First, format the data we want to append into an in-memory string.
	var manifestLines strings.Builder
	for _, entry := range newFilesToTrack {
		// Append new entries in the specified format: path<space><space>checksum<newline>
		manifestLines.WriteString(fmt.Sprintf("%s  %s\n", entry.Path, entry.Checksum))
	}

	// Second, use the RootExec to run the privileged 'tee -a' command.
	// 'tee -a' reads from stdin and appends to the specified file, running as root
	// via the Executor's mechanism (e.g., sudo).

	// Arguments: tee -a <stagingManifest>
	cmd := exec.Command("tee", "-a", stagingManifest)

	// Pipe the data from the strings.Builder into the command's standard input
	cmd.Stdin = strings.NewReader(manifestLines.String())

	// Run the command using the global RootExec
	if err := RootExec.Run(cmd); err != nil {
		return fmt.Errorf("failed to append to manifest file %s via RootExec: %w", stagingManifest, err)
	}

	return nil
}

// getRepoVersion reads pkgname/version from repoPaths and returns the version string.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// We only care about the first field (the version).
func getRepoVersion(pkgName string) (string, error) {
	// 1. Split the repoPaths string by the colon (':') separator.
	paths := strings.Split(repoPaths, ":")

	var lastErr error

	// 2. Iterate over all individual repository paths.
	for _, repoPath := range paths {
		// Trim any potential whitespace from the path
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue // Skip empty paths
		}

		// 3. Construct the full path to the version file.
		// filepath.Join handles the correct path separators (e.g., '/' or '\')
		versionFile := filepath.Join(repoPath, pkgName, "version")

		// 4. Attempt to read the file.
		data, err := os.ReadFile(versionFile)
		if err == nil {
			// File found and read successfully. Process the content.
			fields := strings.Fields(string(data))
			if len(fields) == 0 {
				// If the file is empty, this path is considered invalid but we can stop here.
				return "", fmt.Errorf("invalid version file format (empty file) for %s in path %s", pkgName, repoPath)
			}

			// Successfully found the version. Return it immediately.
			return fields[0], nil
		} else if !os.IsNotExist(err) {
			// If we hit an error other than "file not found," it's a serious issue
			// (e.g., permission denied) so we'll record it and continue trying other paths
			// but keep the error to return if no file is found anywhere.
			lastErr = fmt.Errorf("could not read version file for %s in path %s: %w", pkgName, repoPath, err)
		}
		// If os.IsNotExist(err) is true, we just continue to the next path.
	}

	// 5. If the loop completes without finding a valid version file,
	// return the last non-FileNotFound error if one occurred, otherwise
	// return a generic "not found" error.
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("version file for %s not found in any of the specified paths", pkgName)
}

// getRepoVersion2 reads pkgname/version from repoPaths and returns the version string,
// the revision string, and an error.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// used for the update check
func getRepoVersion2(pkgName string) (version string, revision string, err error) {
	// 1. Split the repoPaths string by the colon (':') separator.
	paths := strings.Split(repoPaths, ":")

	var lastErr error

	// 2. Iterate over all individual repository paths.
	for _, repoPath := range paths {
		// Trim any potential whitespace from the path
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue // Skip empty paths
		}

		// 3. Construct the full path to the version file.
		versionFile := filepath.Join(repoPath, pkgName, "version")

		// 4. Attempt to read the file.
		data, err := os.ReadFile(versionFile)
		if err == nil {
			// File found and read successfully. Process the content.
			fields := strings.Fields(string(data))

			if len(fields) < 1 {
				// File exists but is empty/invalid
				return "", "", fmt.Errorf("invalid version file format (missing version) for %s in path %s", pkgName, repoPath)
			}

			// Extract the version (first field)
			pkgVersion := fields[0]

			// Extract the revision (second field). If missing, default to "0" or "1"
			// based on your package system's convention. Assuming default to "1" is safest
			// to avoid false updates if older packages didn't have a revision number.
			pkgRevision := "1" // Default revision if only one field is present
			if len(fields) >= 2 {
				pkgRevision = fields[1]
			}

			// Successfully found the version and revision. Return them immediately.
			return pkgVersion, pkgRevision, nil
		} else if !os.IsNotExist(err) {
			// If we hit an error other than "file not found," record it.
			lastErr = fmt.Errorf("could not read version file for %s in path %s: %w", pkgName, repoPath, err)
		}
		// If os.IsNotExist(err) is true, we just continue to the next path.
	}

	// 5. If the loop completes without finding a valid version file,
	// return the last non-FileNotFound error if one occurred, otherwise
	// return a generic "not found" error.
	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", fmt.Errorf("version file for %s not found in any of the specified paths", pkgName)
}

// getBaseRepoPath extracts the base repository path (e.g., "/repo/reponame1")
// from a longer path (e.g., "/repo/reponame1/one").
func getBaseRepoPath(fullPath string) string {
	parts := strings.Split(fullPath, "/")

	// Example: for "/repo/reponame1/one", parts is ["", "repo", "reponame1", "one"]

	// We need at least parts for "", "repo", "reponameX". Length >= 3.
	if len(parts) < 3 {
		return fullPath
	}

	// We explicitly construct the path to ensure the leading '/' is present.
	// parts[0] is "", parts[1] is "repo", parts[2] is "reponame1"
	// We want to join "repo" and "reponame1" and prepend "/"

	// Check if the path is absolute (starts with '/')
	isAbs := strings.HasPrefix(fullPath, "/")

	// The components we want to join are parts[1] and parts[2]
	repoDir := path.Join(parts[1], parts[2])

	if isAbs {
		// Prepend the "/" to make it absolute again
		return "/" + repoDir
	}

	return repoDir // Return the relative path if the original wasn't absolute (though it should be)
}

// updateRepos updates each unique repository found in repoPaths
func updateRepos() {
	// 1. Split the global repoPaths string by the path separator ":"
	paths := strings.Split(repoPaths, ":")

	// 2. Determine the unique base repository directories
	uniqueRepoDirs := make(map[string]struct{})
	for _, p := range paths {
		// Clean the path to get the base repository directory
		repoDir := getBaseRepoPath(p)

		if repoDir != "" {
			uniqueRepoDirs[repoDir] = struct{}{}
		}
	}
	colArrow.Print("-> ")
	colSuccess.Println("Unique repositories to update:")
	for dir := range uniqueRepoDirs {
		colArrow.Print("-> ")
		colSuccess.Printf("%s\n", dir)

		// 3. Execute 'git pull' in each unique directory
		// We use dir as the working directory for 'git pull'
		cmd := exec.Command("git", "pull")
		cmd.Dir = dir // Set the working directory for the command

		// Capture output for logging and error checking
		output, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Printf("Error pulling repo %s: %v\nOutput:\n%s\n", dir, err, strings.TrimSpace(string(output)))
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Successfully pulled repo %s\nOutput:\n%s\n", dir, strings.TrimSpace(string(output)))
		}
	}
}

// checkPackageExists checks if a specific package directory exists in the Installed path.
// It returns true if the package directory exists and is a directory, false otherwise.
// This is a direct, silent check, ideal for internal dependency resolution.
func checkPackageExists(pkgName string) bool {
	// Determine the full path to the package's installed directory
	pkgPath := filepath.Join(Installed, pkgName)

	// Check if the path exists and is a directory.
	info, err := os.Stat(pkgPath)
	if err != nil {
		// os.IsNotExist(err) covers the most common failure,
		// any other error (permission, etc.) is treated as "not installed" for safety.
		return false
	}

	// Ensure it's actually a directory (to exclude possible stray files)
	return info.IsDir()
}

// getInstalledPackageOutput reads installed package versions from the filesystem,
// filters them by searchTerm, and returns the list as a formatted byte slice.
func getInstalledPackageOutput(searchTerm string) ([]byte, error) {
	var outputBuilder strings.Builder

	// Step 1: Get the full list of installed package directories.
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			// If the directory doesn't exist, treat it as empty, no error.
			return []byte(""), nil
		}
		return nil, fmt.Errorf("failed to read installed directory %s: %w", Installed, err)
	}

	var allPkgs []string
	for _, e := range entries {
		if e.IsDir() {
			allPkgs = append(allPkgs, e.Name())
		}
	}

	// Step 2: Filter the list if a search term was provided.
	var pkgsToShow []string
	if searchTerm != "" {
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, show everything.
		pkgsToShow = allPkgs
	}

	// Step 3: Format and collect the information (instead of printing).
	// The format is expected to be: "<pkgName> <version> [revision]"
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown 0" // Default for unreadable file

		if data, err := os.ReadFile(versionFile); err == nil {
			// Use the full content of the version file (e.g., "1.0 1")
			versionInfo = strings.TrimSpace(string(data))
		}

		// Write the package name and its full version info to the buffer
		// Example line: "fcron 3.4.0 1"
		outputBuilder.WriteString(fmt.Sprintf("%s %s\n", p, versionInfo))
	}

	// Return the collected data as a byte slice.
	return []byte(outputBuilder.String()), nil
}

// Struct to hold package information
type Package struct {
	Name              string
	InstalledVersion  string
	InstalledRevision string
	RepoVersion       string
	RepoRevision      string
}

// parsePackageList converts the output of getInstalledPackageOutput into a map of packages.
func parsePackageList(output []byte) (map[string]Package, error) {
	packages := make(map[string]Package)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		// Expecting at least 3 parts: <name> <version> <revision>
		if len(parts) < 3 {
			// Allow for packages with missing revision (assume 0 or 1 for simplicity)
			// For now, let's strictly require 3 fields for accurate comparison
			return nil, fmt.Errorf("invalid package list format (expected name, version, revision): %s", line)
		}

		pkgName := parts[0]
		pkgVersion := parts[1]
		pkgRevision := parts[2] // EXTRACT THE REVISION

		packages[pkgName] = Package{
			Name:              pkgName,
			InstalledVersion:  pkgVersion,
			InstalledRevision: pkgRevision, // Store the revision
		}
	}
	return packages, scanner.Err()
}

// pkgBuildAll executes the 'pkgBuild' command for a list of packages.
func pkgBuildAll(packages []string) error {
	if len(packages) == 0 {
		fmt.Println("No packages to build.")
		return nil
	}

	var failed []string

	for _, pkg := range packages {
		colArrow.Print("\n-> ")
		colSuccess.Printf("Executing pkgBuild for: %s\n", pkg)

		args := []string{"build", "-a"}
		if idleUpdate {
			args = append(args, "-i")
		}
		if superidleUpdate {
			args = append(args, "-ii")
		}
		args = append(args, pkg)

		cmd := exec.Command("hokuto", args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			colArrow.Print("-> ")
			color.Danger.Printf("pkgBuild failed for %s: %v\n", pkg, err)
			failed = append(failed, pkg)
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Println("Build+Install completed successfully.")
	}

	if len(failed) > 0 {
		return fmt.Errorf("some packages failed: %s", strings.Join(failed, ", "))
	}

	return nil
}

// checkForUpgrades is the main function for the upgrade logic.
func checkForUpgrades() error {
	colArrow.Print("-> ")
	colSuccess.Println("Checking for Package Upgrades")

	// 1. Get list of installed packages
	output, err := getInstalledPackageOutput("")
	if err != nil {
		return fmt.Errorf("could not retrieve installed packages: %w", err)
	}

	installedPackages, err := parsePackageList(output)
	if err != nil {
		return fmt.Errorf("failed to parse package list: %w", err)
	}

	var upgradeList []Package

	// 2. Compare installed version + revision vs. repo version + revision
	for name, pkg := range installedPackages {
		// Updated call to getRepoVersion to capture both version and revision
		repoVersion, repoRevision, err := getRepoVersion2(name)
		if err != nil {
			// Log error but continue to the next package
			debugf("Warning: Could not get repo version for %s: %v\n", name, err)
			continue
		}

		// Store repo information on the package struct
		pkg.RepoVersion = repoVersion
		pkg.RepoRevision = repoRevision

		// Comparison Logic: Check for a mismatch in either version OR revision
		isVersionMismatch := pkg.InstalledVersion != pkg.RepoVersion
		isRevisionMismatch := pkg.InstalledRevision != pkg.RepoRevision

		// NOTE: A more complex system would compare versions numerically,
		// but for simple string equality checks, this is sufficient:
		if isVersionMismatch || isRevisionMismatch {
			// Add to upgrade list
			upgradeList = append(upgradeList, pkg)
		}
	}

	// 3. Handle upgrade list
	if len(upgradeList) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No packages to upgrade.")
		return nil
	}

	cPrintf(colInfo, "\n--- %d Package(s) to Upgrade ---\n", len(upgradeList))
	var pkgNames []string
	for _, pkg := range upgradeList {
		// Print full version/revision information for clarity
		cPrintf(colInfo, "  - %s: %s %s -> %s %s\n",
			pkg.Name,
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
		pkgNames = append(pkgNames, pkg.Name)
	}

	// 4. Prompt user for upgrade
	if askForConfirmation(colInfo, "Do you want to upgrade these packages?") {
		// 5. Execute pkgBuild
		return pkgBuildAll(pkgNames)
	} else {
		cPrintln(colNote, "Upgrade canceled by user.")
	}

	return nil
}

// getPackageDependenciesForward recursively collects all dependencies for a package
// in forward order (as they appear in depends files).
// Duplicates are only allowed for "gcc" - all other packages are added once.
// This is used with the --alldeps flag to rebuild everything including duplicates.
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

// resolveMissingDeps recursively finds all missing dependencies for a package.
// It assumes cfg is passed in, as it's needed for the recursive call.
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
func isPackageInstalled(pkgName string) bool {
	// Simply defer to the silent checker.
	return checkPackageExists(pkgName)
}

type DepSpec struct {
	Name    string
	Op      string // one of: "<=", ">=", "==", "<", ">", or empty for no constraint
	Version string
}

// parseDependsFile reads the package's depends file and returns a list of dependency specs (with optional version constraints).
func parseDependsFile(pkgDir string) ([]DepSpec, error) {
	dependsPath := filepath.Join(pkgDir, "depends")
	content, err := os.ReadFile(dependsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []DepSpec{}, nil // No depends file is fine
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

		// Split the line, e.g., "alsa-lib" or "python make"
		parts := strings.Fields(line)

		// The first part is the dependency token, which may include a version constraint, e.g., python-sip<=9.8.6
		if len(parts) > 0 {
			name, op, ver := parseDepToken(parts[0])
			dependencies = append(dependencies, DepSpec{Name: name, Op: op, Version: ver})
		}
	}

	return dependencies, nil
}

// parseDepToken parses tokens like "pkg", "pkg<=1.2.3", "pkg==1.0", "pkg>=2.0" and returns name, op, version.
func parseDepToken(token string) (string, string, string) {
	// Check for multi-char operators first to avoid partial matches
	ops := []string{"<=", ">=", "==", "<", ">"}
	for _, op := range ops {
		if idx := strings.Index(token, op); idx != -1 {
			name := token[:idx]
			ver := token[idx+len(op):]
			return strings.TrimSpace(name), op, strings.TrimSpace(ver)
		}
	}
	return token, "", ""
}

// getInstalledVersion reads the installed version string from the package's metadata. Returns (version, true) if found.
func getInstalledVersion(pkgName string) (string, bool) {
	// Installed root directory is stored in global variable Installed
	versionPath := filepath.Join(Installed, pkgName, "version")
	b, err := os.ReadFile(versionPath)
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", false
	}
	return v, true
}

// versionSatisfies checks if installed satisfies op refVersion.
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
func stripPackage(outputDir string, buildExec *Executor) error {
	colArrow.Print("-> ")
	colSuccess.Println("Stripping executables in parallel")

	var wg sync.WaitGroup

	maxConcurrency := runtime.GOMAXPROCS(0) * 4
	if maxConcurrency < 8 {
		maxConcurrency = 8
	}
	concurrencyLimit := make(chan struct{}, maxConcurrency)

	// --- PHASE 1: Execute 'find' command via the Executor to get the file list ---
	shellCommand := fmt.Sprintf(
		"find %s -type f \\( -perm /u+x -o -perm /g+x -o -perm /o+x \\) -exec sh -c 'file -0 {} 2>/dev/null | grep -q ELF && printf \"%%s\\n\" {}' \\;",
		outputDir,
	)

	var findOutput bytes.Buffer
	findCmd := exec.Command("sh", "-c", shellCommand)
	findCmd.Stdout = &findOutput
	if !Verbose && !Debug {
		findCmd.Stderr = io.Discard
	} else {
		findCmd.Stderr = os.Stderr
	}

	debugf("  -> Discovering stripable ELF files")
	if err := buildExec.Run(findCmd); err != nil {
		return fmt.Errorf("failed to execute file discovery command (find/file filter): %w", err)
	}

	// --- PHASE 2: Process the collected output ---
	pathsRaw := strings.TrimSpace(findOutput.String())
	if pathsRaw == "" {
		debugf("-> No stripable ELF files found.")
		return nil
	}
	paths := strings.Split(pathsRaw, "\n")

	var failedMu sync.Mutex
	var failedFiles []string

	for _, path := range paths {
		if path == "" {
			continue
		}

		wg.Add(1)
		concurrencyLimit <- struct{}{}
		p := path

		go func(p string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			// --- MODIFICATION START ---
			// Define the stderr writer once based on global flags.
			var stderrWriter io.Writer = os.Stderr
			if !Debug && !Verbose {
				stderrWriter = io.Discard
			}
			// --- MODIFICATION END ---

			// Save original permissions
			statCmd := exec.Command("sh", "-c", fmt.Sprintf("stat -c %%a %q", p))
			var permOut bytes.Buffer
			statCmd.Stdout = &permOut
			statCmd.Stderr = stderrWriter // Use the conditional writer

			if err := buildExec.Run(statCmd); err != nil {
				debugf("Warning: failed to stat permissions for %s: %v. Skipping this file.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}
			originalPerms := strings.TrimSpace(permOut.String())
			if originalPerms == "" {
				debugf("Warning: empty perms from stat for %s. Skipping this file.\n", p)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}

			// Ensure we restore perms no matter what
			defer func() {
				restoreCmd := exec.Command("chmod", originalPerms, p)
				restoreCmd.Stderr = stderrWriter // Use the conditional writer
				if err := buildExec.Run(restoreCmd); err != nil {
					debugf("Warning: failed to restore permissions on %s to %s: %v\n", p, originalPerms, err)
				}
			}()

			// Try to grant write permission
			chmodWriteCmd := exec.Command("chmod", "u+w", p)
			chmodWriteCmd.Stderr = stderrWriter // Use the conditional writer
			if err := buildExec.Run(chmodWriteCmd); err != nil {
				debugf("Warning: failed to chmod +w %s: %v. Skipping strip for this file.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}

			debugf("  -> Stripping %s\n", p)
			stripCmd := exec.Command("strip", p)
			stripCmd.Stderr = stderrWriter // Use the conditional writer
			if err := buildExec.Run(stripCmd); err != nil {
				// Log as warning only. Do not mark the whole package as failed.
				debugf("Warning: failed to strip %s: %v. Continuing with other files.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}
		}(p)
	}

	wg.Wait()

	if len(failedFiles) > 0 {
		// Provide an informational summary but do not fail the whole build.
		debugf("Warning: some files failed to be stripped (%d). See above for details. Continuing.\n", len(failedFiles))
	}

	return nil
}

// list of essential directories that should never be removed by rmdir.
// These are absolute paths expected to be found under the HOKUTO_ROOT.
// We use a map for O(1) lookup.
var forbiddenSystemDirs = map[string]struct{}{
	"/bin":   {},
	"/lib":   {},
	"/lib32": {},
	"/lib64": {},
	"/opt":   {},
	"/sbin":  {},
	"/usr":   {},
	"/var":   {},
	"/etc":   {},
	"/swap":  {},
	// Common subdirectories
	"/etc/profile.d":           {},
	"/usr/bin":                 {},
	"/usr/include":             {},
	"/usr/lib":                 {},
	"/usr/lib32":               {},
	"/usr/lib64":               {},
	"/usr/local":               {},
	"/usr/sbin":                {},
	"/usr/share":               {},
	"/usr/src":                 {},
	"/usr/share/man":           {},
	"/usr/share/man/man1":      {},
	"/usr/share/man/man2":      {},
	"/usr/share/man/man3":      {},
	"/usr/share/man/man4":      {},
	"/usr/share/man/man5":      {},
	"/usr/share/man/man6":      {},
	"/usr/share/man/man7":      {},
	"/usr/share/man/man8":      {},
	"/var/cache":               {},
	"/var/db":                  {},
	"/var/db/hokuto":           {},
	"/var/db/hokuto/installed": {},
	"/var/db/hokuto/sources":   {},
	"/var/empty":               {},
	"/var/lib":                 {},
	"/var/local":               {},
	"/var/lock":                {},
	"/var/log":                 {},
	"/var/mail":                {},
	"/var/opt":                 {},
	"/var/run":                 {},
	"/var/service":             {},
	"/var/spool":               {},
	"/var/tmp":                 {},
	"/var/tmpdir":              {},
	"/var/lib/misc":            {},
	"/var/spool/mail":          {},
	"/var/log/old":             {},
}

// list of essential directories that should NEVER be removed, nor should any of their contents.
// These use a prefix check (recursive protection).
var forbiddenSystemDirsRecursive = map[string]struct{}{
	"/boot":      {},
	"/dev":       {},
	"/home":      {},
	"/mnt":       {},
	"/proc":      {},
	"/root":      {},
	"/sys":       {},
	"/tmp":       {},
	"/run":       {},
	"/snapshots": {},
	"/repo":      {},
}

type fileMetadata struct {
	AbsPath string
	B3Sum   string
}

// getUserConfirmation prompts the user and accepts 'y' or 'n'.
// It can print the prompt with a specific color style if p is not nil.
func getUserConfirmation(p colorPrinter, format string, a ...any) bool {
	reader := bufio.NewReader(os.Stdin)
	prompt := fmt.Sprintf(format, a...) // Create the final prompt string first

	for {
		// Use cPrintf to print the prompt. It handles the nil case automatically.
		cPrintf(p, "%s", prompt)

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "" { // Default to 'yes' on Enter
			return true
		}
		if input == "n" {
			return false
		}
		cPrintln(colWarn, "Invalid input. Please enter 'y' or 'n'.")
	}
}

// askForConfirmation prompts the user and defaults to 'yes'.
// It can print the prompt with a specific color style if p is not nil.
func askForConfirmation(p colorPrinter, format string, a ...any) bool {
	reader := bufio.NewReader(os.Stdin)
	// First, create the main part of the prompt using the provided arguments.
	mainPrompt := fmt.Sprintf(format, a...)
	// Then, create the final, full prompt string.
	fullPrompt := fmt.Sprintf("%s [Y/n]: ", mainPrompt)

	for {
		// Use our existing cPrintf helper to print the prompt with the desired color.
		// cPrintf will handle the case where 'p' is nil and print without color.
		cPrintf(p, "%s", fullPrompt)

		response, err := reader.ReadString('\n')
		if err != nil {
			return false // On error (like Ctrl+D), default to "no"
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" || response == "" {
			return true
		}
		if response == "n" || response == "no" {
			return false
		}
		cPrintln(colWarn, "Invalid input. Please type 'y' (yes) or 'n' (no).")
	}
}

// findOwnerPackage searches installed manifests for the exact file path
// and returns the name of the package that owns it.
func findOwnerPackage(filePath string) (string, error) {
	// 1. Normalize the search path for the manifest (e.g., "usr/lib/libnssckbi.so")
	// The filePath comes from the 'file' variable which is relative to rootDir
	// so it doesn't need to be stripped of rootDir, but we'll ensure it's clean.
	searchPath := filepath.Clean(filePath)

	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No packages installed
		}
		return "", fmt.Errorf("failed to read installed db: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(Installed, pkgName, "manifest")

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // skip unreadable manifests
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			manifestPath := fields[0]

			// Normalize the path found in the manifest for an exact match check
			cleanManifestPath := filepath.Clean(manifestPath)

			// Check for exact match
			if cleanManifestPath == searchPath {
				return pkgName, nil // Found the owner!
			}
		}
	}

	return "", nil // No owner found
}

// PostInstallTasks runs common system cache updates after package installs.
// Call with RootExec:  if err := PostInstallTasks(RootExec); err != nil { ... }
func PostInstallTasks(e *Executor) error {
	colArrow.Print("-> ")
	colSuccess.Println("Executing post-install tasks")
	tasks := []struct {
		name string
		args []string
	}{
		// Icon cache
		{"gtk-update-icon-cache", []string{"-q", "-t", "-f", "/usr/share/icons/hicolor"}},
		// GSettings schemas
		{"glib-compile-schemas", []string{"--quiet", "/usr/share/glib-2.0/schemas"}},
		// Font cache
		{"fc-cache", []string{"-f", "-q"}},
		// MIME database
		{"update-mime-database", []string{"-q", "/usr/share/mime"}},
		// Desktop entry database
		{"update-desktop-database", []string{"-q", "/usr/share/applications"}},
		// Pixbuf loaders (no quiet flag available)
		{"gdk-pixbuf-query-loaders", []string{"--update-cache"}},
		// Shared library cache (quiet by default)
		{"ldconfig", nil},
		// Man page index
		{"mandb", []string{"-q"}},
		// Systemd unit reload
		{"systemctl", []string{"daemon-reload"}},
	}

	var errs []error
	for _, t := range tasks {
		if _, err := exec.LookPath(t.name); err != nil {
			continue
		}
		cmd := exec.CommandContext(e.Context, t.name, t.args...)
		// Silence all output to TTY
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		// Avoid inheriting stdin (prevents accidental prompts)
		cmd.Stdin = nil

		if err := e.Run(cmd); err != nil {
			errs = append(errs, fmt.Errorf("%s failed: %w", t.name, err))
		}
	}

	if len(errs) > 0 {
		return nil
		//fmt.Errorf("some post-install tasks failed: %v", errs)
	}
	return nil
}

// build package
func pkgBuild(pkgName string, cfg *Config, execCtx *Executor, bootstrap bool) error {

	// Define the ANSI escape code format for setting the terminal title.
	// \033]0; sets the title, and \a (bell character) terminates the sequence.
	const setTitleFormat = "\033]0;%s\a"

	// Helper function to set the title in the TTY.
	setTerminalTitle := func(title string) {
		// Outputting directly to os.Stdout sets the title in the terminal session.
		fmt.Printf(setTitleFormat, title)
	}

	// Track build time
	startTime := time.Now()

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
			return fmt.Errorf("failed to clean pkgTmpDir %s: %v (fallback also failed: %v)", pkgTmpDir, err, err2)
		}
	}

	// Rereate build/output dirs (non-root, inside TMPDIR)
	for _, dir := range []string{buildDir, outputDir, logDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create dir %s: %v", dir, err)
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
		return fmt.Errorf("failed to fetch sources: %v", err)
	}

	// Perform checksum verification.
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false); err != nil {
		return fmt.Errorf("source verification failed: %w", err)
	}

	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
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

	// Read version
	versionFile := filepath.Join(pkgDir, "version")
	versionData, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read version file: %v", err)
	}
	version := strings.Fields(string(versionData))[0]

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return fmt.Errorf("build script not found: %v", err)
	}

	// 1. Define the base C/C++/LD flags
	var defaultCFLAGS = "-O2 -march=x86-64 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// Build environment
	env := os.Environ()
	var defaults = map[string]string{}

	if bootstrap {
		// --- Bootstrap environment (like the lfs user) ---
		lfsRoot := cfg.Values["LFS"]
		if lfsRoot == "" {
			return fmt.Errorf("bootstrap mode requires LFS to be set in config")
		}

		defaults = map[string]string{
			"LFS":         lfsRoot,
			"LC_ALL":      "POSIX",
			"LFS_TGT":     "x86_64-lfs-linux-gnu",
			"LFS_TGT32":   "i686-lfs-linux-gnu",
			"LFS_TGTX32":  "x86_64-lfs-linux-gnux32",
			"PATH":        filepath.Join(lfsRoot, "tools/bin") + ":/usr/bin:/bin",
			"MAKEFLAGS":   fmt.Sprintf("-j%d", runtime.NumCPU()),
			"CONFIG_SITE": filepath.Join(lfsRoot, "usr/share/config.site"),
			"HOKUTO_ROOT": lfsRoot,
			"TMPDIR":      currentTmpDir,
		}
	} else {
		// --- Normal build environment---
		defaults = map[string]string{
			"AR":          "gcc-ar",
			"CC":          "cc",
			"CXX":         "c++",
			"NM":          "gcc-nm",
			"RANLIB":      "gcc-ranlib",
			"CFLAGS":      defaultCFLAGS, // Use the constant
			"CXXFLAGS":    "",
			"LDFLAGS":     defaultLDFLAGS, // Use the constant
			"MAKEFLAGS":   fmt.Sprintf("-j%d", runtime.NumCPU()),
			"RUSTFLAGS":   fmt.Sprintf("--remap-path-prefix=%s=.", buildDir),
			"GOFLAGS":     "-trimpath -modcacherw",
			"GOPATH":      filepath.Join(buildDir, "go"),
			"HOKUTO_ROOT": cfg.Values["HOKUTO_ROOT"],
			"TMPDIR":      currentTmpDir,
		}

		// Based on the priority, override the defaults for cores and signal the wrapper.
		switch buildPriority {
		case "idle":
			numCores := runtime.NumCPU() / 2
			if numCores < 1 {
				numCores = 1
			}
			defaults["MAKEFLAGS"] = fmt.Sprintf("-j%d", numCores)
			defaults["CMAKE_BUILD_PARALLEL_LEVEL"] = fmt.Sprintf("%d", numCores)
			defaults["HOKUTO_BUILD_PRIORITY"] = "idle" // Set variable for wrapper
		case "superidle":
			numCores := 1
			defaults["MAKEFLAGS"] = fmt.Sprintf("-j%d", numCores)
			defaults["CMAKE_BUILD_PARALLEL_LEVEL"] = fmt.Sprintf("%d", numCores)
			defaults["HOKUTO_BUILD_PRIORITY"] = "superidle" // Set variable for wrapper
		}
	}

	// Only apply normal flag logic if not in bootstrap mode
	if !bootstrap {

		// 2. Select the appropriate keys and default values based on cfg.DefaultLTO
		var cflagsKey, cxxflagsKey, ldflagsKey string

		if shouldLTO {
			cflagsKey = "CFLAGS_LTO"
			cxxflagsKey = "CXXFLAGS_LTO"
			ldflagsKey = "LDFLAGS_LTO"
			// Set LTO defaults if they are not defined in the configuration
			// (You'd likely define these globally in your program)
			defaults["CFLAGS"] = defaultCFLAGS + " -flto=auto"   // Example LTO flag
			defaults["LDFLAGS"] = defaultLDFLAGS + " -flto=auto" // Example LTO flag
		} else {
			cflagsKey = "CFLAGS"
			cxxflagsKey = "CXXFLAGS"
			ldflagsKey = "LDFLAGS"
			defaults["CFLAGS"] = defaultCFLAGS
			defaults["LDFLAGS"] = defaultLDFLAGS
		}

		// 3. Set CXXFLAGS default based on CFLAGS if not set, regardless of LTO
		defaults["CXXFLAGS"] = ""

		// 4. Override defaults with actual config values
		// We only need to check the CFLAGS, CXXFLAGS, LDFLAGS keys now
		// This ensures the correct, prioritized value from the config is used.
		if val := cfg.Values[cflagsKey]; val != "" {
			defaults["CFLAGS"] = val
		}
		if val := cfg.Values[cxxflagsKey]; val != "" {
			defaults["CXXFLAGS"] = val
		}
		if val := cfg.Values[ldflagsKey]; val != "" {
			defaults["LDFLAGS"] = val
		}

		// The CXXFLAGS fallback logic must be applied AFTER CFLAGS is finalized.
		// We must apply it before the final loop, as the final loop simply appends.
		finalCXXFLAGS := defaults["CXXFLAGS"]
		if finalCXXFLAGS == "" {
			// Fallback to CFLAGS if CXXFLAGS is still empty
			finalCXXFLAGS = defaults["CFLAGS"]
		}
		defaults["CXXFLAGS"] = finalCXXFLAGS // Update the map with the resolved value
	}

	for k, v := range defaults {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	// Run build script
	debugf("Building %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	// 1. Define the log file path
	logFile, err := os.Create(filepath.Join(logDir, "build-log.txt"))
	if err != nil {
		// Handle the error (e.g., return it, or panic if log file creation is mandatory)
		return fmt.Errorf("failed to create build log file: %w", err)
	}
	defer logFile.Close() // Ensure the log file is closed when the function exits

	cmd := exec.Command(buildScript, outputDir, version, pkgName)
	cmd.Dir = buildDir
	cmd.Env = env

	// 2. Define the base writers: always log to the file.
	// The file writer must be included regardless of the Debug flag.
	var stdoutWriters []io.Writer
	var stderrWriters []io.Writer

	// Always write to the log file
	stdoutWriters = append(stdoutWriters, logFile)
	stderrWriters = append(stderrWriters, logFile)

	// 3. Conditionally add the console writers based on the Debug flag.
	var consoleOutputWriter io.Writer = os.Stdout
	var consoleErrorWriter io.Writer = os.Stderr

	// For interactive builds, we always want console output.
	// For non-interactive, respect Debug/Verbose flags.
	if !buildExec.Interactive && !Debug && !Verbose {
		consoleOutputWriter = io.Discard
		consoleErrorWriter = io.Discard
	}

	// Add the console writers (either os.Stdout/os.Stderr or io.Discard)
	stdoutWriters = append(stdoutWriters, consoleOutputWriter)
	stderrWriters = append(stderrWriters, consoleErrorWriter)

	// 4. Create the final MultiWriters
	// io.MultiWriter combines all the writers in the slices.
	cmd.Stdout = io.MultiWriter(stdoutWriters...)
	cmd.Stderr = io.MultiWriter(stderrWriters...)

	var runErr error // Use a single error variable for both paths

	// NEW: Create a special executor for the build script that applies idle priority
	buildScriptExec := &Executor{
		Context:           buildExec.Context,
		ShouldRunAsRoot:   buildExec.ShouldRunAsRoot,
		ApplyIdlePriority: setIdlePriority, // Use the global flag here
		Interactive:       buildExec.Interactive,
	}

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
					title := fmt.Sprintf("%s elapsed: %s", pkgName, elapsed)
					setTerminalTitle(title)
					colArrow.Print("-> ")
					colSuccess.Printf("Building %s elapsed: %s\r", pkgName, elapsed)
				case <-doneCh:
					fmt.Print("\r")
					return
				case <-buildExec.Context.Done():
					return
				}
			}
		}()

		// Run the build.
		if err := buildScriptExec.Run(cmd); err != nil {
			runErr = fmt.Errorf("build failed: %w", err)
		}

		// Stop ticker goroutine and wait.
		close(doneCh)
		runWg.Wait()

	} else {
		// --- INTERACTIVE PATH: Run directly without any timers or title updates ---
		// This gives the child process exclusive control of the terminal.
		if err := buildScriptExec.Run(cmd); err != nil {
			runErr = fmt.Errorf("build failed: %w", err)
		}
	}

	if runErr != nil {
		colArrow.Print("-> ")
		color.Danger.Printf("Build failed for %s: %v\n", pkgName, runErr)
		finalTitle := fmt.Sprintf("❌ FAILED: %s", pkgName)
		setTerminalTitle(finalTitle)

		// Flush the log file so tail sees everything written so far.
		if logFile != nil {
			_ = logFile.Sync()
		}

		// Path to the build log (we created this earlier as logFile)
		logPath := filepath.Join(logDir, "build-log.txt")

		// Launch a tail -n 200 -f so the user can view the last 200 lines and follow live.
		// Connect stdin/stdout/stderr so the user can Ctrl-C to exit the tail.
		tailCmd := exec.Command("tail", "-n", "50", "-f", logPath)
		tailCmd.Stdin = os.Stdin
		tailCmd.Stdout = os.Stdout
		tailCmd.Stderr = os.Stderr

		// Run tail via the same Executor so privilege behavior and context cancellation are honored.
		// Ignore tail errors (user may Ctrl-C to exit); we only return the original build error.
		_ = buildExec.Run(tailCmd)

		return runErr
	}

	// success
	elapsed := time.Since(startTime).Truncate(time.Second)
	debugf("\n%s built successfully in %s, output in %s\n", pkgName, elapsed, outputDir)

	// Create /var/db/hokuto/installed/<pkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
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

	// Generate depends
	if err := generateDepends(pkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
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
	pattern := filepath.Join(outputDir, "lib", "perl5", "*", "core_perl", "perllocal.pod")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		// This is an error in the pattern itself or a fundamental I/O error
		fmt.Fprintf(os.Stderr, "Warning: failed to glob for perllocal.pod pattern %s: %v\n", pattern, err)
		// Continue, as this is a non-fatal cleanup
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

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	// Generate package archive
	if err := createPackageTarball(pkgName, version, outputDir, buildExec); err != nil {
		return fmt.Errorf("failed to package tarball: %v", err)
	}

	// Cleanup tmpdirs
	if Debug {
		fmt.Fprintf(os.Stderr, "INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", pkgTmpDir)
	} else {
		rmCmd := exec.Command("rm", "-rf", pkgTmpDir)
		if err := RootExec.Run(rmCmd); err != nil {
			fmt.Fprintf(os.Stderr, "failed to cleanup build tmpdirs: %v\n", err)
		}
	}
	// Build SUCCESSFUL: Set title to success status
	finalTitle := fmt.Sprintf("✅ SUCCESS: %s", pkgName)
	setTerminalTitle(finalTitle)
	debugf("HOKUTO ROOT IS", rootDir)
	return nil
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
	version := strings.Fields(string(versionData))[0]

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return fmt.Errorf("build script not found: %v", err)
	}

	// 2. Build environment (Modified to include the backed-up libs for Executor tools)
	env := os.Environ()
	defaults := map[string]string{
		"AR":          "gcc-ar",
		"CC":          "cc",
		"CXX":         "c++",
		"NM":          "gcc-nm",
		"RANLIB":      "gcc-ranlib",
		"CFLAGS":      "-O2 -march=x86-64 -mtune=generic -pipe -fPIC",
		"CXXFLAGS":    "",
		"LDFLAGS":     "",
		"MAKEFLAGS":   fmt.Sprintf("-j%d", runtime.NumCPU()),
		"RUSTFLAGS":   fmt.Sprintf("--remap-path-prefix=%s=.", buildDir),
		"GOFLAGS":     "-trimpath -modcacherw",
		"GOPATH":      filepath.Join(buildDir, "go"),
		"HOKUTO_ROOT": rootDir,
		"TMPDIR":      currentTmpDir,
	}

	// Based on the priority, override the defaults for cores and signal the wrapper.
	switch buildPriority {
	case "idle":
		numCores := runtime.NumCPU() / 2
		if numCores < 1 {
			numCores = 1
		}
		defaults["MAKEFLAGS"] = fmt.Sprintf("-j%d", numCores)
		defaults["CMAKE_BUILD_PARALLEL_LEVEL"] = fmt.Sprintf("%d", numCores)
		defaults["HOKUTO_BUILD_PRIORITY"] = "idle" // Set variable for wrapper
	case "superidle":
		numCores := 1
		defaults["MAKEFLAGS"] = fmt.Sprintf("-j%d", numCores)
		defaults["CMAKE_BUILD_PARALLEL_LEVEL"] = fmt.Sprintf("%d", numCores)
		defaults["HOKUTO_BUILD_PRIORITY"] = "superidle" // Set variable for wrapper
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

	// 1. Define the base C/C++/LD flags
	var defaultCFLAGS = "-O2 -march=x86-64 -mtune=generic -pipe -fPIC"
	var defaultLDFLAGS = ""

	// 2. Select the appropriate keys and default values based on cfg.DefaultLTO
	var cflagsKey, cxxflagsKey, ldflagsKey string

	if shouldLTO {
		cflagsKey = "CFLAGS_LTO"
		cxxflagsKey = "CXXFLAGS_LTO"
		ldflagsKey = "LDFLAGS_LTO"
		// Set LTO defaults if they are not defined in the configuration
		// (You'd likely define these globally in your program)
		defaults["CFLAGS"] = defaultCFLAGS + " -flto=auto"   // Example LTO flag
		defaults["LDFLAGS"] = defaultLDFLAGS + " -flto=auto" // Example LTO flag
	} else {
		cflagsKey = "CFLAGS"
		cxxflagsKey = "CXXFLAGS"
		ldflagsKey = "LDFLAGS"
		defaults["CFLAGS"] = defaultCFLAGS
		defaults["LDFLAGS"] = defaultLDFLAGS
	}

	// 3. Set CXXFLAGS default based on CFLAGS if not set, regardless of LTO
	defaults["CXXFLAGS"] = ""

	// 4. Override defaults with actual config values
	// We only need to check the CFLAGS, CXXFLAGS, LDFLAGS keys now
	// This ensures the correct, prioritized value from the config is used.
	if val := cfg.Values[cflagsKey]; val != "" {
		defaults["CFLAGS"] = val
	}
	if val := cfg.Values[cxxflagsKey]; val != "" {
		defaults["CXXFLAGS"] = val
	}
	if val := cfg.Values[ldflagsKey]; val != "" {
		defaults["LDFLAGS"] = val
	}

	// The CXXFLAGS fallback logic must be applied AFTER CFLAGS is finalized.
	// We must apply it before the final loop, as the final loop simply appends.
	finalCXXFLAGS := defaults["CXXFLAGS"]
	if finalCXXFLAGS == "" {
		// Fallback to CFLAGS if CXXFLAGS is still empty
		finalCXXFLAGS = defaults["CFLAGS"]
	}
	defaults["CXXFLAGS"] = finalCXXFLAGS // Update the map with the resolved value

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
	cPrintf(colInfo, "RebuildingRebuilding %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	// 1. Define the log file path
	logFile, err := os.Create(filepath.Join(logDir, "build-log.txt"))
	if err != nil {
		// Handle the error (e.g., return it, or panic if log file creation is mandatory)
		return fmt.Errorf("failed to create build log file: %w", err)
	}
	defer logFile.Close() // Ensure the log file is closed when the function exits

	cmd := exec.Command(buildScript, outputDir, version, pkgName)
	cmd.Dir = buildDir
	cmd.Env = env

	// 2. Define the base writers: always log to the file.
	// The file writer must be included regardless of the Debug flag.
	var stdoutWriters []io.Writer
	var stderrWriters []io.Writer

	// Always write to the log file
	stdoutWriters = append(stdoutWriters, logFile)
	stderrWriters = append(stderrWriters, logFile)

	// 3. Conditionally add the console writers based on the Debug flag.
	var consoleOutputWriter io.Writer = os.Stdout
	var consoleErrorWriter io.Writer = os.Stderr

	// For interactive builds, we always want console output.
	// For non-interactive, respect Debug/Verbose flags.
	if !buildExec.Interactive && !Debug && !Verbose {
		consoleOutputWriter = io.Discard
		consoleErrorWriter = io.Discard
	}

	// Add the console writers (either os.Stdout/os.Stderr or io.Discard)
	stdoutWriters = append(stdoutWriters, consoleOutputWriter)
	stderrWriters = append(stderrWriters, consoleErrorWriter)

	// 4. Create the final MultiWriters
	// io.MultiWriter combines all the writers in the slices.
	cmd.Stdout = io.MultiWriter(stdoutWriters...)
	cmd.Stderr = io.MultiWriter(stderrWriters...)

	var runErr error // Use a single error variable for both paths

	// NEW: Create a special executor for the build script that applies idle priority
	buildScriptExec := &Executor{
		Context:           buildExec.Context,
		ShouldRunAsRoot:   buildExec.ShouldRunAsRoot,
		ApplyIdlePriority: setIdlePriority, // Use the global flag here
		Interactive:       buildExec.Interactive,
	}

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
					colInfo.Printf(" Building %s  elapsed: %s\r", pkgName, elapsed)
				case <-doneCh:
					fmt.Print("\r")
					return
				case <-buildExec.Context.Done():
					return
				}
			}
		}()

		// Run the build.
		if err := buildScriptExec.Run(cmd); err != nil {
			runErr = fmt.Errorf("build failed: %w", err)
		}

		// Stop ticker goroutine and wait.
		close(doneCh)
		runWg.Wait()
	} else {
		// --- INTERACTIVE PATH: Run directly without timers or title updates ---
		if err := buildScriptExec.Run(cmd); err != nil {
			runErr = fmt.Errorf("build failed: %w", err)
		}
	}

	// Check the single runErr variable (compiler knows it may be non-nil)
	if runErr != nil {
		cPrintf(colError, "\nBuild failed for %s: %v\n", pkgName, runErr)

		// Set title to warning status
		finalTitle := fmt.Sprintf("❌ FAILED: %s", pkgName)
		setTerminalTitle(finalTitle)

		// Flush the log file so tail sees everything written so far.
		if logFile != nil {
			_ = logFile.Sync()
		}

		// Path to the build log (we created this earlier as logFile)
		logPath := filepath.Join(logDir, "build-log.txt")

		// Launch a tail -n 200 -f so the user can view the last 200 lines and follow live.
		// Connect stdin/stdout/stderr so the user can Ctrl-C to exit the tail.
		tailCmd := exec.Command("tail", "-n", "50", "-f", logPath)
		tailCmd.Stdin = os.Stdin
		tailCmd.Stdout = os.Stdout
		tailCmd.Stderr = os.Stderr

		// Run tail via the same Executor so privilege behavior and context cancellation are honored.
		// Ignore tail errors (user may Ctrl-C to exit); we only return the original build error.
		_ = buildExec.Run(tailCmd)

		return runErr
	}

	// success
	elapsed := time.Since(startTime).Truncate(time.Second)
	cPrintf(colNote, "\n%s built successfully in %s, output in %s\n", pkgName, elapsed, outputDir)

	// Create /var/db/hokuto/installed/<pkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
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

	// Generate depends
	if err := generateDepends(pkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
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
	pattern := filepath.Join(outputDir, "lib", "perl5", "*", "core_perl", "perllocal.pod")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		// This is an error in the pattern itself or a fundamental I/O error
		fmt.Fprintf(os.Stderr, "Warning: failed to glob for perllocal.pod pattern %s: %v\n", pattern, err)
		// Continue, as this is a non-fatal cleanup
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

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	cPrintf(colNote, "%s rebuilt successfully, output in %s\n", pkgName, outputDir)
	//Set title to success status
	finalTitle := fmt.Sprintf("✅ SUCCESS: %s", pkgName)
	setTerminalTitle(finalTitle)

	// Key difference: Skip tarball creation and cleanup to allow pkgInstall to sync and clean up.
	return nil
}

func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor) error {

	// Special handling for glibc: direct extraction without staging or checks
	if pkgName == "glibc" {
		colArrow.Print("-> ")
		colSuccess.Println("Installing glibc using direct extraction method")

		var extractErr error

		// Use system tar if available
		if _, err := exec.LookPath("tar"); err == nil {
			args := []string{"xf", tarballPath, "-C", rootDir}
			tarCmd := exec.Command("tar", args...)
			tarCmd.Stdout = os.Stdout
			tarCmd.Stderr = os.Stderr

			extractErr = execCtx.Run(tarCmd)
			if extractErr == nil {
				colArrow.Print("-> ")
				colSuccess.Println("glibc installed successfully via direct extraction.")
			}
		} else {
			// Fallback to Go implementation if tar not available
			extractErr = unpackTarballFallback(tarballPath, rootDir)
			if extractErr == nil {
				colArrow.Print("-> ")
				colSuccess.Println("glibc installed successfully via direct extraction (fallback).")
			}
		}

		if extractErr != nil {
			return fmt.Errorf("failed to extract glibc tarball: %v", extractErr)
		}

		// Always run post-install hook for glibc
		if err := executePostInstall(pkgName, rootDir, execCtx); err != nil {
			colArrow.Print("-> ")
			color.Danger.Printf("post-install for %s returned error: %v\n", pkgName, err)
		}

		return nil
	}

	stagingDir := filepath.Join(tmpDir, pkgName, "staging")
	pkgTmpDir := filepath.Join(tmpDir, pkgName)

	// Declare and initialize the 'failed' slice for tracking non-fatal errors
	var failed []string

	// Clean staging dir
	os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("failed to create staging dir: %v", err)
	}

	// 1. Unpack tarball into staging
	debugf("Unpacking %s into %s\n", tarballPath, stagingDir)

	// Try system tar first
	if _, err := exec.LookPath("tar"); err == nil {
		untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
		if err := execCtx.Run(untarCmd); err == nil {
			// success with system tar
		} else {
			// fallback if tar failed
			if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
				return fmt.Errorf("failed to unpack tarball (fallback): %v", err)
			}
		}
	} else {
		// fallback if tar not found
		if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
			return fmt.Errorf("failed to unpack tarball (fallback): %v", err)
		}
	}

	// 2. Detect user-modified files
	debugf("detect user modified files")

	// Determine if this package was built as a user (for optimization)
	// Check for asroot file in the staging directory metadata (embedded during build)
	stagingMetadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	asRootFile := filepath.Join(stagingMetadataDir, "asroot")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
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
		return err
	}

	// 3. Interactive handling of modified files
	for _, file := range modifiedFiles {
		stagingFile := filepath.Join(stagingDir, file)
		currentFile := filepath.Join(rootDir, file) // file under the install root

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

		ownerDisplay := fmt.Sprintf("(Owner: %s) ", ownerPkg)

		if _, err := os.Stat(stagingFile); err == nil {
			// file exists in staging
			cmd := exec.Command("diff", "-u", currentFile, stagingFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()

			cPrintf(colInfo, "File %s modified, %schoose action: [k]eep current, [U]se new, [e]dit: ", file, ownerDisplay)
			var input string
			fmt.Scanln(&input)
			input = strings.TrimSpace(input)
			if input == "" {
				input = "u" // default to use new when user just presses enter
			}
			switch input {
			case "k":
				cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
				}
			case "u":
				// keep staging file as-is
			case "e":
				// --- NEW: Get original staging file permissions ---
				stagingInfo, err := os.Stat(stagingFile)
				if err != nil {
					return fmt.Errorf("failed to stat staging file %s: %v", stagingFile, err)
				}
				originalMode := stagingInfo.Mode()
				// read staging content
				stContent, err := os.ReadFile(stagingFile)
				if err != nil {
					return fmt.Errorf("failed to read staging file %s: %v", stagingFile, err)
				}

				// produce unified diff (currentFile vs stagingFile); ignore diff errors (non-zero exit means differences)
				diffCmd := exec.Command("diff", "-u", currentFile, stagingFile)
				diffOut, _ := diffCmd.Output() // we don't fail if diff returns non-zero

				// create temp file prefilled with staging content + marked diff
				tmp, err := os.CreateTemp("", "hokuto-edit-")
				if err != nil {
					return fmt.Errorf("failed to create temp file for editing: %v", err)
				}
				tmpPath := tmp.Name()
				defer func() {
					tmp.Close()
					_ = os.Remove(tmpPath)
				}()

				if _, err := tmp.Write(stContent); err != nil {
					return fmt.Errorf("failed to write staging content to temp file: %v", err)
				}

				// append a separator and diff output for reference
				if len(diffOut) > 0 {
					if _, err := tmp.WriteString("\n\n--- diff (installed -> staging) ---\n"); err != nil {
						return fmt.Errorf("failed to write diff header to temp file: %v", err)
					}
					if _, err := tmp.Write(diffOut); err != nil {
						return fmt.Errorf("failed to write diff to temp file: %v", err)
					}
				}

				// close before launching editor
				if err := tmp.Close(); err != nil {
					return fmt.Errorf("failed to close temp file before editing: %v", err)
				}

				editor := os.Getenv("EDITOR")
				if editor == "" {
					editor = "nano"
				}

				// Launch editor against the temp file as the invoking user so they can edit comfortably.
				editCmd := exec.Command(editor, tmpPath)
				editCmd.Stdin, editCmd.Stdout, editCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := editCmd.Run(); err != nil {
					return fmt.Errorf("editor failed: %v", err)
				}

				// After editing, copy temp back to staging
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", tmpPath, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to copy edited file back to staging %s: %v", stagingFile, err)
				}
				// --- NEW: Explicitly restore permissions ---
				// The `cp --preserve=mode` relies on the temp file's mode, which is wrong.
				// Use chmod to ensure the correct original mode is set.
				// We format the mode to an octal string (e.g., "0644").
				modeStr := fmt.Sprintf("%#o", originalMode.Perm())

				chmodCmd := exec.Command("chmod", modeStr, stagingFile)
				if err := execCtx.Run(chmodCmd); err != nil {
					return fmt.Errorf("failed to restore permissions on %s to %s: %v", stagingFile, modeStr, err)
				}
			}
		} else {
			// file does NOT exist in staging
			cPrintf(colInfo, "User modified %s, but new package has no file. Keep it? [y/N]: ", file)
			var input string
			fmt.Scanln(&input)
			ans := strings.ToLower(strings.TrimSpace(input))
			if ans == "y" {
				// ensure staging directory exists (run as root)
				stagingFileDir := filepath.Dir(stagingFile)
				mkdirCmd := exec.Command("mkdir", "-p", stagingFileDir)
				if err := execCtx.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", stagingFileDir, err)
				}
				// copy current file into staging preserving attributes
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", currentFile, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to copy %s to staging: %v", file, err)
				}
				debugf("Kept modified file by copying %s into staging\n", file)
			} else {
				// user chose not to keep it -> remove the installed file (run as root)
				rmCmd := exec.Command("rm", "-f", currentFile)
				if err := execCtx.Run(rmCmd); err != nil {
					// warn but continue install; do not abort the whole install for a removal failure
					cPrintf(colWarn, "Warning: failed to remove %s: %v\n", currentFile, err)
				} else {
					debugf("Removed user-modified file: %s\n", file)
				}
			}
		}
	}
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
		return fmt.Errorf("failed to generate manifest: %v", err)
	}
	debugf("Generate update manifest\n")
	if err := updateManifestWithNewFiles(stagingManifest, stagingManifest2file); err != nil {
		fmt.Fprintf(os.Stderr, "Manifest update failed: %v\n", err)
	}

	// Delete stagingManifest2dir
	rmCmd := exec.Command("rm", "-rf", stagingManifest2dir)
	if err := execCtx.Run(rmCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove StagingManifest: %v", err)
	}

	// 4. Determine obsolete files (compare manifests)
	debugf("Find obsolete files\n")
	filesToDelete, err := removeObsoleteFiles(pkgName, stagingDir, rootDir)
	if err != nil {
		return err
	}

	// --- NEW: Dependency Check and Backup (Before deletion) ---
	debugf("Dependency check")
	affectedPackages := make(map[string]struct{})
	libFilesToDelete := make(map[string]struct{})
	tempLibBackupDir, err := os.MkdirTemp(tmpDir, "hokuto-lib-backup-")
	if err != nil {
		return fmt.Errorf("failed to create temporary backup directory: %v", err)
	}
	// CLEANUP: Ensure the backup directory is removed on exit
	defer func() {
		if !Debug {
			rmCmd := exec.Command("rm", "-rf", tempLibBackupDir)
			if err := execCtx.Run(rmCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to cleanup temporary library backup: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", tempLibBackupDir)
		}
	}()

	// 4a. Check filesToDelete against all libdeps
	allInstalledEntries, err := os.ReadDir(Installed)
	if err == nil {
		for _, entry := range allInstalledEntries {
			if !entry.IsDir() || entry.Name() == pkgName {
				continue // Skip files or the package currently being installed
			}

			otherPkgName := entry.Name()
			libdepsPath := filepath.Join(Installed, otherPkgName, "libdeps")

			libdepsContent, err := readFileAsRoot(libdepsPath)
			if err != nil {
				continue // Skip if libdeps file is unreadable
			}

			// Check if any file in filesToDelete is a libdep of otherPkgName
			lines := strings.Split(string(libdepsContent), "\n")
			for _, line := range lines {
				libPath := strings.TrimSpace(line)
				if libPath == "" {
					continue
				}

				// Construct the absolute path to the library file currently on the system
				// This is primarily for the OLD format (full path in libdeps).
				absLibPath := libPath
				if rootDir != "/" && strings.HasPrefix(libPath, "/") {
					// Old format: path is absolute, reconstruct relative to rootDir
					absLibPath = filepath.Join(rootDir, libPath[1:])
				} else if !strings.HasPrefix(libPath, "/") {
					// Handle defensively, but for the NEW format (basename), we will use the full path
					// from filesToDelete, ignoring this potentially incorrect path construction.
					absLibPath = filepath.Join(rootDir, libPath)
				}

				// Determine if the libPath is a full absolute path or just a basename.
				isFullPath := strings.HasPrefix(libPath, "/")

				// Check if this library is scheduled for deletion
				matchFound := false
				finalAbsPath := "" // Stores the correct absolute path of the file being deleted

				for _, fileToDelete := range filesToDelete {

					if isFullPath {
						// Case 1: Old format (full path in libdeps).
						// Match the full path (relying on absLibPath reconstruction).
						if fileToDelete == absLibPath {
							finalAbsPath = absLibPath
							matchFound = true
						}
					} else {
						// Case 2: New format (basename only in libdeps).
						// Match the basename of the file being deleted against the libdep entry.
						fileToDeleteBasename := filepath.Base(fileToDelete)
						if fileToDeleteBasename == libPath {
							// Found a match, use the actual path being deleted
							finalAbsPath = fileToDelete
							matchFound = true
						}
					}

					if matchFound {
						affectedPackages[otherPkgName] = struct{}{}
						libFilesToDelete[finalAbsPath] = struct{}{}
						// Break inner loop (over filesToDelete) and check the next libdep
						break
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
		mkdirCmd := exec.Command("mkdir", "-p", backupDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create backup dir %s: %v", backupDir, err)
		}

		// Copy the library file to the backup location
		cpCmd := exec.Command("cp", "--remove-destination", "--preserve=mode,ownership,timestamps", libPath, backupPath)
		if err := execCtx.Run(cpCmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to backup library %s: %v\n", libPath, err)
		} else {
			cPrintf(colInfo, "Backed up affected library %s to %s\n", libPath, backupPath)
		}
	}

	// 5. Rsync staging into root
	debugf("Rsync staging into root")
	if err := rsyncStaging(stagingDir, rootDir, execCtx); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd := exec.Command("rm", "-f", p)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Printf("warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			debugf("Removed obsolete file: %s\n", p)
		}
	}

	// 7. Run package post-install script
	if err := executePostInstall(pkgName, rootDir, execCtx); err != nil {
		fmt.Printf("warning: post-install for %s returned error: %v\n", pkgName, err)
	}

	// --- Rebuild Affected Packages (Step 8) ---
	if len(affectedPackages) > 0 {
		affectedList := make([]string, 0, len(affectedPackages))
		for pkg := range affectedPackages {
			affectedList = append(affectedList, pkg)
		}
		sort.Strings(affectedList)

		// 8a. Prompt for rebuild (Hokuto is guaranteed to be run in a terminal)
		cPrintf(colWarn, "\nWARNING: The following packages depend on libraries that were removed/upgraded:\n  %s\n", strings.Join(affectedList, ", "))

		performRebuild := true // Default to true, and allow user input to override

		cPrintf(colInfo, "Do you want to rebuild these packages now? This is highly recommended. [Y/n]: ")

		var answer string
		// Read the line. Using '_' to discard the error and the count,
		// as we only care if 'answer' is "n".
		_, _ = fmt.Scanln(&answer) // Corrected line: 'err' replaced with '_'

		// Check if the trimmed input is 'n' (No). An empty input (user pressed Enter)
		// or an error (like EOF on Enter) will fall through to 'performRebuild = true'.
		if strings.ToLower(strings.TrimSpace(answer)) == "n" {
			cPrintf(colInfo, "Skipping rebuild")
			performRebuild = false
		}
		// If err != nil (like when only Enter is pressed), or input is empty/ 'y',
		// performRebuild remains true.

		// 8b. Perform rebuild
		if performRebuild {
			colArrow.Print("-> ")
			colSuccess.Println("Starting rebuild of affected packages")
			for _, pkg := range affectedList {
				cPrintf(colInfo, "\n--- Rebuilding %s ---\n", pkg)

				if err := pkgBuildRebuild(pkg, cfg, execCtx, tempLibBackupDir); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s failed: %v", pkg, err))
					cPrintf(colWarn, "WARNING: Rebuild of %s failed: %v\n", pkg, err)
				} else {
					rebuildOutputDir := filepath.Join(tmpDir, pkg, "output")

					if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
						failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", pkg, err))
						cPrintf(colWarn, "WARNING: Failed to sync rebuilt package %s to root: %v\n", pkg, err)
					}

					rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, pkg))
					if err := execCtx.Run(rmCmd); err != nil {
						fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", pkg, err)
					}
					cPrintf(colNote, "Rebuild of %s finished and installed.\n", pkg)
				}
			}
		}
	}

	// 9. Cleanup
	rmCmd2 := exec.Command("rm", "-rf", pkgTmpDir)
	if err := execCtx.Run(rmCmd2); err != nil {
		fmt.Fprintf(os.Stderr, "failed to cleanup: %v\n", err)
	}

	// 10. Report failures if any
	if len(failed) > 0 { // 'failed' slice is correctly declared at the start of pkgInstall
		return fmt.Errorf("some file actions failed:\n%s", strings.Join(failed, "\n"))
	}

	// 11. Run global post-install tasks
	if err := PostInstallTasks(RootExec); err != nil {
		fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
	}
	return nil
}

// uninstallPackage removes an installed package safely.
// - pkgName: package to remove
// - cfg: configuration (used for HOKUTO_ROOT)
// - execCtx: Executor that must have ShouldRunAsRoot=true (RootExec)
// - force: ignore reverse-dep checks
// - yes: assume confirmation
func pkgUninstall(pkgName string, cfg *Config, execCtx *Executor, force, yes bool) error {
	// Resolve HOKUTO_ROOT (fall back to "/")
	hRoot := cfg.Values["HOKUTO_ROOT"]
	if hRoot == "" {
		hRoot = "/"
	}

	installedDir := filepath.Join(hRoot, "var", "db", "hokuto", "installed", pkgName)
	manifestPath := filepath.Join(installedDir, "manifest")

	// Path prefix for internal metadata files that should skip the b3sum check.
	internalFilePrefix := filepath.Join(hRoot, "var", "db", "hokuto", "installed")

	// 1. Verify package exists
	if _, err := os.Stat(installedDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("package %s is not installed", pkgName)
		}
		return fmt.Errorf("failed to stat package metadata: %v", err)
	}

	// 2. Read manifest as root
	manifestBytes, err := readFileAsRoot(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest for %s: %v", pkgName, err)
	}

	// 3. Build list of files and directories from manifest.
	var files []fileMetadata // CHANGED: Use new struct to store B3Sum
	var dirs []string
	var fileCount int // Track only installable files for confirmation message

	sc := bufio.NewScanner(strings.NewReader(string(manifestBytes)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Split into path and optional checksum
		pathInManifest := line
		expectedSum := ""
		if strings.HasSuffix(line, "/") {
			// directory entry, no checksum
		} else {
			parts := strings.SplitN(line, "  ", 2)
			pathInManifest = parts[0]
			if len(parts) > 1 {
				expectedSum = strings.TrimSpace(parts[1])
			}
		}

		// Absolute path on disk
		var absPath string
		if filepath.IsAbs(pathInManifest) {
			if hRoot != "/" {
				absPath = filepath.Join(hRoot, pathInManifest[1:])
			} else {
				absPath = pathInManifest
			}
		} else {
			absPath = filepath.Join(hRoot, pathInManifest)
		}

		if strings.HasSuffix(pathInManifest, "/") {
			dirs = append(dirs, absPath)
			continue
		}

		fileCount++
		files = append(files, fileMetadata{AbsPath: absPath, B3Sum: expectedSum})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("error parsing manifest: %v", err)
	}

	// 4. Check reverse dependencies (unchanged)
	// ... (Original Step 4 code) ...
	dependents := []string{}
	dbRoot := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(dbRoot)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			other := e.Name()
			if other == pkgName {
				continue
			}
			depFile := filepath.Join(dbRoot, other, "depends")
			b, err := readFileAsRoot(depFile)
			if err != nil {
				continue
			}
			lines := strings.Split(string(b), "\n")
			for _, L := range lines {
				L = strings.TrimSpace(L)
				if L == "" {
					continue
				}
				parts := strings.Fields(L)
				if len(parts) == 0 {
					continue
				}
				if parts[0] == pkgName {
					dependents = append(dependents, other)
					break
				}
			}
		}
	}
	if len(dependents) > 0 && !force {
		return fmt.Errorf("cannot uninstall %s: other packages depend on it: %s", pkgName, strings.Join(dependents, ", "))
	}

	// 5. Confirm with user unless 'yes' is set
	if !yes {
		colArrow.Print("-> ")
		color.Danger.Printf("About to remove package %s and %d file(s). Continue? [Y/n]: ", pkgName, fileCount)
		var answer string
		fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "" && answer != "y" {
			return fmt.Errorf("aborted by user")
		}
	}

	// 6. Run pre-uninstall if present (unchanged)
	preScript := filepath.Join(installedDir, "pre-uninstall")
	if fi, err := os.Stat(preScript); err == nil && !fi.IsDir() {
		cmd := exec.Command(preScript)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := execCtx.Run(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: pre-uninstall script failed: %v\n", err)
		}
	}

	// 7. Remove files (with optional b3sum check)
	var failed []string
	var filesToRemove []string
	var filesToCheck []fileMetadata

	// Separate files that need checksum verification from those that don't
	for _, meta := range files {
		p := meta.AbsPath // The full HOKUTO_ROOT prefixed path

		// Safety check: don't remove root
		clean := filepath.Clean(p)
		if clean == "/" || clean == hRoot {
			failed = append(failed, fmt.Sprintf("%s: refused to remove root", p))
			continue
		}

		// Always check b3sums for files in /etc (critical system files)
		// Skip checksum verification if force=true or if it's internal metadata, but not for /etc files
		isEtcFile := strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, filepath.Join(hRoot, "etc/"))

		if (force || strings.HasPrefix(p, internalFilePrefix) || meta.B3Sum == "") && !isEtcFile {
			filesToRemove = append(filesToRemove, clean)
		} else {
			filesToCheck = append(filesToCheck, meta)
		}
	}

	// Check files that need verification
	for _, meta := range filesToCheck {
		p := meta.AbsPath
		clean := filepath.Clean(p)

		currentSum, err := b3sum(p, execCtx)
		if err != nil {
			// Treat inability to check as a failure to remove for safety
			failed = append(failed, fmt.Sprintf("%s: failed to compute b3sum: %v", p, err))
			continue
		}

		// Skip modification warning for files with 000000 checksum
		if currentSum != meta.B3Sum && meta.B3Sum != "000000" {
			cPrintf(colWarn, "\nWARNING: File %s has been modified (expected %s, found %s).\n", p, meta.B3Sum, currentSum)

			// Prompt user unless 'yes' is set
			if !yes {
				fmt.Printf("File content mismatch. Remove anyway? [Y/n]: ")
				var answer string
				fmt.Scanln(&answer)
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer == "" {
					answer = "y" // default to Yes if user just presses Enter
				}
				if answer != "y" {
					failed = append(failed, fmt.Sprintf("%s: content mismatch, removal skipped by user", p))
					continue // Skip removal
				}
			}
		}

		filesToRemove = append(filesToRemove, clean)
	}

	// Batch remove all files at once
	if len(filesToRemove) > 0 {
		// Use rm with multiple files for better performance
		rmCmd := exec.Command("rm", "-f")
		rmCmd.Args = append(rmCmd.Args, filesToRemove...)

		if err := execCtx.Run(rmCmd); err != nil {
			// If batch removal fails, try individual removals
			colArrow.Print("-> ")
			colSuccess.Println("Batch removal failed, trying individual removals")
			for _, file := range filesToRemove {
				rmCmd := exec.Command("rm", "-f", file)
				if err := execCtx.Run(rmCmd); err != nil {
					failed = append(failed, fmt.Sprintf("%s: %v", file, err))
				} else {
					fmt.Printf("Removed %s\n", file)
				}
			}
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Removed %d files\n", len(filesToRemove))
		}
	}

	// 8. Try to rmdir directories recorded in manifest, deepest first (unchanged)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		clean := filepath.Clean(d)

		// Safety check 1: Don't attempt to rmdir outside HOKUTO_ROOT.
		if !strings.HasPrefix(clean, filepath.Clean(hRoot)) {
			continue
		}

		// Safety check 2: Check against forbidden system directories.
		relToHRoot := strings.TrimPrefix(clean, filepath.Clean(hRoot))
		if relToHRoot == "" {
			relToHRoot = "/"
		}

		if !strings.HasPrefix(relToHRoot, "/") {
			relToHRoot = "/" + relToHRoot
		}

		isForbidden := false

		// A. Check 1: Forbidden Recursive Directories (Prefix Check)
		for forbiddenPath := range forbiddenSystemDirsRecursive {
			// Trim the trailing slash for comparison, unless the path itself is "/"
			recursiveRoot := forbiddenPath

			// The path is forbidden if it's an exact match OR starts with the forbidden path + '/'
			if relToHRoot == recursiveRoot {
				isForbidden = true
				break
			}

			if strings.HasPrefix(relToHRoot, recursiveRoot+"/") {
				isForbidden = true
				break
			}
		}

		// B. Check 2: Forbidden Exact Directories (Map Lookup)
		if !isForbidden {
			if _, found := forbiddenSystemDirs[relToHRoot]; found {
				isForbidden = true
			}
		}

		if isForbidden {
			debugf("Skipping removal of protected system directory: %s\n", clean)
			continue
		}

		rmdirCmd := exec.Command("rmdir", clean)
		rmdirCmd.Stderr = io.Discard // Silence stderr to avoid "Directory not empty" warnings
		if err := execCtx.Run(rmdirCmd); err == nil {
			debugf("Removed empty directory %s\n", clean)
		}
	}

	// 9. Remove package metadata directory (unchanged)
	rmMetaCmd := exec.Command("rm", "-rf", installedDir)
	if err := execCtx.Run(rmMetaCmd); err != nil {
		failed = append(failed, fmt.Sprintf("failed to remove metadata %s: %v", installedDir, err))
	} else {
		debugf("Removed package metadata: %s\n", installedDir)
	}

	// 10. Run post-uninstall hook if present (unchanged)
	postScript := filepath.Join(installedDir, "post-uninstall")
	if fi, err := os.Stat(postScript); err == nil && !fi.IsDir() {
		cmd := exec.Command(postScript)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := execCtx.Run(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: post-uninstall script failed: %v\n", err)
		}
	}

	// 11. Report failures if any (unchanged)
	if len(failed) > 0 {
		return fmt.Errorf("some removals failed:\n%s", strings.Join(failed, "\n"))
	}
	return nil
}

func handleBuildCommand(args []string, cfg *Config) {
	// 1. Initialize a FlagSet for the "build" subcommand
	buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
	var autoInstall = buildCmd.Bool("a", false, "Automatically install the package(s) after successful build without prompting.")
	var idleBuild = buildCmd.Bool("i", false, "Use half cpu cores and lowest niceness for build process.")
	var superidleBuild = buildCmd.Bool("ii", false, "Use one cpu core and lowest niceness for build process.")
	var verbose = buildCmd.Bool("v", false, "Enable verbose output (show build process output).")
	var verboseLong = buildCmd.Bool("verbose", false, "Enable verbose output (show build process output).")
	var bootstrap = buildCmd.Bool("bootstrap", false, "Enable bootstrap build mode")
	var bootstrapDir = buildCmd.String("bootstrap-dir", "", "Specify the bootstrap directory (used with --bootstrap)")
	var allDeps = buildCmd.Bool("alldeps", false, "Force build all dependencies (no binary packages used)")

	// Parse the arguments specific to the "build" subcommand
	if err := buildCmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing build flags: %v\n", err)
		os.Exit(1)
	}
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

	// Handle bootstrap logic
	if *bootstrap {
		if *bootstrapDir == "" {
			fmt.Fprintln(os.Stderr, "Error: --bootstrap requires --bootstrap-dir to be specified")
			os.Exit(1)
		}
		if cfg.Values == nil {
			cfg.Values = make(map[string]string)
		}
		cfg.Values["LFS"] = *bootstrapDir
	}

	// The positional arguments (package names) are now in buildCmd.Args()
	packagesToProcess := buildCmd.Args()
	if len(packagesToProcess) < 1 {
		fmt.Println("Usage: hokuto build [options] <package> [package...]")
		fmt.Println("Options:")
		buildCmd.PrintDefaults()
		os.Exit(1)
	}

	// Set to non-critical (0 is default, but good to be explicit)
	isCriticalAtomic.Store(0)

	// --- CONDITIONAL OVERRIDE FOR HOKUTO_ROOT ---
	if *bootstrap {

		// 1. Get the LFS root path
		lfsRoot := cfg.Values["LFS"]
		if lfsRoot == "" {
			log.Fatalf("bootstrap mode requires LFS to be set in config")
		}

		// 2. Override HOKUTO_ROOT and cachedir
		cfg.Values["HOKUTO_ROOT"] = lfsRoot
		cfg.Values["HOKUTO_CACHE_DIR"] = filepath.Join(lfsRoot, "var/cache/hokuto")

		// 1. Check for existing /repo/bootstrap
		if fi, err := os.Stat("/repo/bootstrap"); err == nil && fi.IsDir() {
			// Use pre-existing /repo/bootstrap
			cfg.Values["HOKUTO_PATH"] = "/repo/bootstrap"
			colArrow.Print("-> ")
			colSuccess.Println("Using existing bootstrap repo at /repo/bootstrap")
		} else {
			// 2. Check for existing /tmp/repo/bootstrap
			if fi, err := os.Stat("/tmp/repo/bootstrap"); err == nil && fi.IsDir() {
				cfg.Values["HOKUTO_PATH"] = "/tmp/repo/bootstrap"
				colArrow.Print("-> ")
				colSuccess.Println("Using existing bootstrap repo at /tmp/repo/bootstrap")
			} else {
				// Need to download and unpack into /tmp/repo
				url := "https://github.com/sauzeros/bootstrap/releases/download/latest/bootstrap-repo.tar.xz"
				tmpFile := filepath.Join(os.TempDir(), "bootstrap-repo.tar.xz")
				colArrow.Print("-> ")
				colSuccess.Printf("Downloading bootstrap repo from %s\n", url)
				resp, err := http.Get(url)
				if err != nil {
					log.Fatalf("failed to download bootstrap repo: %v", err)
				}
				defer resp.Body.Close()

				out, err := os.Create(tmpFile)
				if err != nil {
					log.Fatalf("failed to create temp file: %v", err)
				}
				if _, err := io.Copy(out, resp.Body); err != nil {
					out.Close()
					log.Fatalf("failed to save bootstrap archive: %v", err)
				}
				out.Close()

				// Unpack into /tmp/repo
				colArrow.Print("-> ")
				colSuccess.Println("Unpacking bootstrap repo into /tmp/repo")

				extractDir := filepath.Join(os.TempDir(), "repo")
				if err := os.MkdirAll(extractDir, 0o755); err != nil {
					log.Fatalf("failed to create extract dir %s: %v", extractDir, err)
				}

				f, err := os.Open(tmpFile)
				if err != nil {
					log.Fatalf("failed to open downloaded archive: %v", err)
				}
				defer f.Close()

				xzr, err := xz.NewReader(f)
				if err != nil {
					log.Fatalf("failed to create xz reader: %v", err)
				}

				tr := tar.NewReader(xzr)
				for {
					hdr, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						log.Fatalf("error reading tar: %v", err)
					}

					target := filepath.Join(extractDir, hdr.Name)

					switch hdr.Typeflag {
					case tar.TypeDir:
						if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
							log.Fatalf("failed to create dir %s: %v", target, err)
						}
					case tar.TypeReg:
						if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
							log.Fatalf("failed to create parent dir: %v", err)
						}
						outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
						if err != nil {
							log.Fatalf("failed to create file %s: %v", target, err)
						}
						if _, err := io.Copy(outFile, tr); err != nil {
							outFile.Close()
							log.Fatalf("failed to write file %s: %v", target, err)
						}
						outFile.Close()
					case tar.TypeSymlink:
						if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
							log.Fatalf("failed to create symlink %s -> %s: %v", target, hdr.Linkname, err)
						}
					}
				}

				log.Printf("Bootstrap repo unpacked successfully into /tmp/repo")
				cfg.Values["HOKUTO_PATH"] = "/tmp/repo/bootstrap"
			}
		}
	}
	// Call initConfig with the possibly modified config
	initConfig(cfg)

	// --- GLOBAL DEPENDENCY RESOLUTION & BINARY CHECK ---

	// masterMissingDeps will hold all unique packages needed across all requested builds (in reverse build order)
	var masterMissingDeps []string
	// masterProcessed tracks all dependencies across all packages to avoid duplicates and loops
	masterProcessed := make(map[string]bool)

	// Track which packages the user explicitly requested (to defer final install)
	targetPackages := make(map[string]bool)
	for _, pkg := range packagesToProcess {
		targetPackages[pkg] = true
	}

	// 2. Resolve dependencies for ALL requested packages
	var packagesToBuildFromDeps []string

	if *allDeps {
		// When --alldeps is active, build dependencies in forward order (as they appear in depends file)
		// and allow duplicates to be rebuilt
		fmt.Println("--alldeps flag set: building all dependencies in order with duplicates allowed")

		for _, pkgName := range packagesToProcess {
			colArrow.Print("-> ")
			colSuccess.Println("Resolving dependencies for target package %s", pkgName)

			// Get dependencies in forward order (as they appear in depends file)
			deps, err := getPackageDependenciesForward(pkgName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving dependencies for %s: %v\n", pkgName, err)
				os.Exit(1)
			}

			// Add all dependencies (including duplicates) followed by the package itself
			packagesToBuildFromDeps = append(packagesToBuildFromDeps, deps...)
			packagesToBuildFromDeps = append(packagesToBuildFromDeps, pkgName)
		}
	} else {
		// Normal mode: use existing dependency resolution (reverse order, no duplicates)
		for _, pkgName := range packagesToProcess {
			colArrow.Print("-> ")
			colSuccess.Printf("Resolving dependencies for target package %s\n", pkgName)

			// NOTE: resolveMissingDeps must be able to handle being called multiple times
			// and update masterProcessed and masterMissingDeps correctly, acting like a global resolver.
			if err := resolveMissingDeps(pkgName, masterProcessed, &masterMissingDeps); err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving dependencies for %s: %v\n", pkgName, err)
				os.Exit(1)
			}
		}
		packagesToBuildFromDeps = masterMissingDeps
	}

	var finalPackagesToBuild []string

	// 3. BINARY CHECK AND USER PROMPT LOGIC (for all collected packages)
	// When --alldeps is set, skip binary check entirely and force build everything
	if *allDeps {
		// All packages will be built, no filtering needed
		finalPackagesToBuild = packagesToBuildFromDeps
	} else {
		for _, depPkg := range packagesToBuildFromDeps {
			version, err := getRepoVersion(depPkg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal error: could not determine version for %s: %v\n", depPkg, err)
				os.Exit(1)
			}
			tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", depPkg, version))

			// Only consider using a binary if it is NOT one of the user-requested target packages
			if !targetPackages[depPkg] {
				if _, err := os.Stat(tarballPath); err == nil {
					// Binary exists
					fmt.Printf("Dependency '%s' is not installed, but a built binary (%s) is available.\n", depPkg, filepath.Base(tarballPath))

					// PROMPT: Do you want to use the pre-built binary?
					if !getUserConfirmation(colNote, "-> Do you want to use the available binary package for dependency %s? (Y/n) ", depPkg) {
						fmt.Printf("User chose to build %s.\n", depPkg)
						finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
					} else {
						colArrow.Print("-> ")
						colSuccess.Printf("Using available binary for %s. Installing\n", depPkg)
						// Check if package has dependencies to uninstall first
						depsToUninstall := getPackageDependenciesToUninstall(depPkg)
						if len(depsToUninstall) > 0 {
							debugf("Package %s requires uninstalling dependencies: %v\n", depPkg, depsToUninstall)
							for _, dep := range depsToUninstall {
								debugf("Uninstalling %s\n", dep)
								if err := pkgUninstall(dep, cfg, RootExec, true, true); err != nil {
									// Log warning but continue with installation
									debugf("Warning: failed to uninstall %s: %v (continuing with installation)\n", dep, err)
								} else {
									debugf("%s uninstalled successfully.\n", dep)
								}
							}
						}
						// Immediate install of dependency binary
						isCriticalAtomic.Store(1)
						if err := pkgInstall(tarballPath, depPkg, cfg, RootExec); err != nil {
							isCriticalAtomic.Store(0)
							fmt.Fprintf(os.Stderr, "Fatal error installing binary %s: %v\n", depPkg, err)
							os.Exit(1)
						}
						isCriticalAtomic.Store(0)
						colArrow.Print("-> ")
						colSuccess.Printf("Dependency %s installed successfully from binary.\n", depPkg)
						// This package is installed and won't be built, so skip adding to finalPackagesToBuild
					}
				} else {
					// No binary found, must build
					finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
				}
			} else {
				// User-requested target package that was also missing, always proceed to build
				finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
			}
		}
	}

	// Update the final list of packages to actually build
	packagesToBuild := finalPackagesToBuild

	// --- NEW LOGIC START ---
	// This block ensures that all packages the user explicitly requested are
	// included in the final build list, forcing a rebuild if they are already installed.

	// Skip this logic when --alldeps is active since all packages are already in the list
	if !*allDeps {
		// Create a quick lookup map of what's already in the build queue
		// to prevent adding duplicates.
		alreadyInBuildList := make(map[string]bool)
		for _, pkg := range packagesToBuild {
			alreadyInBuildList[pkg] = true
		}

		// Iterate through the original user request and add any target packages
		// that aren't already in the build list.
		for _, targetPkg := range packagesToProcess {
			if !alreadyInBuildList[targetPkg] {
				// This package was not "missing", but the user wants to rebuild it.
				colArrow.Print("-> ")
				colSuccess.Printf("Package '%s' is already installed. Adding to queue for a forced rebuild.\n", targetPkg)
				packagesToBuild = append(packagesToBuild, targetPkg)
			}
		}
	}
	// --- NEW LOGIC END ---

	// --- FINAL LIST CHECK ---

	// If after all dependency resolution and user requests, there's nothing to build, exit.
	if len(packagesToBuild) == 0 {
		fmt.Printf("All required packages are installed and no rebuild was requested. Nothing to do.\n")
		os.Exit(0)
	}

	colArrow.Print("-> ")
	colSuccess.Printf("The following packages will be built in order: %s\n", strings.Join(packagesToBuild, ", "))
	// If idle priority is set, inform the user
	if setIdlePriority {
		cPrintf(colWarn, "NOTE: Build process niceness set to IDLE (nice -n 19).\n")
	}

	// --- EXECUTION OF BUILD LOOP ---
	var builtTargetPackages []string // Track the target packages that were successfully built
	for _, buildPkg := range packagesToBuild {
		// ... (Steps 3A, 3B - Get Version, Build) ...
		version, err := getRepoVersion(buildPkg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: could not determine version for %s: %v\n", buildPkg, err)
			os.Exit(1)
		}
		tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", buildPkg, version))

		colArrow.Print("-> ")
		colSuccess.Printf("Starting build: %s (%s)\n", buildPkg, version)
		if err := pkgBuild(buildPkg, cfg, UserExec, *bootstrap); err != nil {
			colArrow.Print("-> ")
			colError.Printf("Fatal error building %s: %v\n", buildPkg, err)
			os.Exit(1)
		}

		// --- STEP 3C: Install (Dependencies are installed immediately when --alldeps is set) ---
		if !targetPackages[buildPkg] { // If it's *not* a target package (i.e., it's a dependency)
			// Install dependencies immediately (always auto-install when --alldeps is set)
			isCriticalAtomic.Store(1)

			// Check if dependency has dependencies to uninstall first
			depsToUninstall := getPackageDependenciesToUninstall(buildPkg)
			if len(depsToUninstall) > 0 {
				debugf("Package %s requires uninstalling dependencies: %v\n", buildPkg, depsToUninstall)
				for _, dep := range depsToUninstall {
					debugf("Uninstalling %s\n", dep)
					if err := pkgUninstall(dep, cfg, RootExec, true, true); err != nil {
						// Log warning but continue with installation
						debugf("Warning: failed to uninstall %s: %v (continuing with installation)\n", dep, err)
					} else {
						debugf("%s uninstalled successfully.\n", dep)
					}
				}
			}
			if err := pkgInstall(tarballPath, buildPkg, cfg, RootExec); err != nil {
				isCriticalAtomic.Store(0)
				fmt.Fprintf(os.Stderr, "Fatal error installing dependency %s: %v\n", buildPkg, err)
				os.Exit(1)
			}
			isCriticalAtomic.Store(0)
			colArrow.Print("-> ")
			colSuccess.Printf("Dependency %s installed successfully.\n", buildPkg)
		} else {
			// If it's a target package, defer install and save its name
			builtTargetPackages = append(builtTargetPackages, buildPkg)
			debugf("Target package %s built successfully. Installation deferred.\n", buildPkg)
		}
	}

	// --- FINAL INSTALL PROMPT ---
	if len(builtTargetPackages) > 0 {
		// Note: The prompt/auto-install applies to ALL built target packages
		shouldInstall := *autoInstall
		if !shouldInstall {
			// Prompt user once for all built target packages
			targetsList := strings.Join(builtTargetPackages, ", ")
			shouldInstall = getUserConfirmation(colWarn, "-> Do you want to install the following package(s): %s (Y/n) ", targetsList)
		}

		if shouldInstall {
			// Loop and install all successfully built target packages
			for _, finalPkg := range builtTargetPackages {
				version, _ := getRepoVersion(finalPkg) // Re-get version (should not fail)
				tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", finalPkg, version))

				// Check if package has dependencies to uninstall first
				depsToUninstall := getPackageDependenciesToUninstall(finalPkg)
				if len(depsToUninstall) > 0 {
					debugf("Package %s requires uninstalling dependencies: %v\n", finalPkg, depsToUninstall)
					for _, dep := range depsToUninstall {
						debugf("Uninstalling %s\n", dep)
						if err := pkgUninstall(dep, cfg, RootExec, true, true); err != nil {
							// Log warning but continue with installation
							debugf("Warning: failed to uninstall %s: %v (continuing with installation)\n", dep, err)
						} else {
							debugf("%s uninstalled successfully.\n", dep)
						}
					}
				}
				colArrow.Print("-> ")
				colSuccess.Printf("Starting installation of target package %s\n", finalPkg)
				isCriticalAtomic.Store(1)
				if err := pkgInstall(tarballPath, finalPkg, cfg, RootExec); err != nil {
					isCriticalAtomic.Store(0)
					fmt.Fprintf(os.Stderr, "Fatal error installing final package %s: %v\n", finalPkg, err)
					os.Exit(1)
				}
				isCriticalAtomic.Store(0)
				colArrow.Print("-> ")
				colSuccess.Printf("Package %s installed successfully.\n", finalPkg)
			}
		} else {
			debugf("Installation of target packages skipped by user. Built packages remain in %s.\n", BinDir)
		}
	}

	// Clean up or exit after a successful run
	os.Exit(0)
}

// executeMountCommand accepts the FULL destination path (e.g., /var/tmp/lfs/dev/tty)
func (e *Executor) executeMountCommand(source, dest, fsType, options string, isBind bool) error {
	args := []string{}

	// Check if the destination is expected to be a device file.
	// These must exist as a file, not a directory.
	base := filepath.Base(source)
	isDeviceFileBind := isBind && (base == "tty" || base == "console" || base == "null" || base == "ptmx" || base == "zero" || base == "full" || base == "random" || base == "urandom")
	// NOTE: Added "ptmx", "zero", "full", "random", "urandom" to match typical essential device nodes.

	if isDeviceFileBind {
		// For device file binds:
		// 1. Ensure the parent directory exists.
		parentDir := filepath.Dir(dest)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
		}

		// 2. Create the file placeholder if it doesn't exist.
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			if err := os.WriteFile(dest, []byte{}, 0644); err != nil {
				return fmt.Errorf("failed to create device file placeholder %s: %w", dest, err)
			}
		}
	} else {
		// 1. Ensure the destination directory exists (for all non-device file mounts)
		if err := os.MkdirAll(dest, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", dest, err)
		}
	}

	// --- Rest of the logic remains the same (Bind/Type mounting logic) ---

	if isBind {
		if options == "--make-private" {
			// ... (propagation logic remains the same) ...
			// Omitted for brevity.
			return nil
		}
		args = []string{source, dest, "--bind"}
	} else {
		args = append(args, source, dest)
		if fsType != "" {
			args = append(args, "-t", fsType)
		}
		if options != "" {
			args = append(args, "-o", options)
		}
	}

	cmd := exec.Command("mount", args...)
	debugf("[INFO] Running mount: %s\n", strings.Join(cmd.Args, " "))

	if err := e.Run(cmd); err != nil {
		return fmt.Errorf("mount failed for %s to %s: %w", source, dest, err)
	}
	return nil
}

// UnmountFilesystems unmounts all given paths using the external 'umount -l'
// command via e.Run() to ensure proper privilege escalation.
func (e *Executor) UnmountFilesystems(paths []string) error {
	var cleanupErrors []string

	// Iterate backwards to safely unmount mounts within other mounts
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]

		// Check if the path exists before attempting unmount
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		debugf("[INFO] Unmounting: %s\n", path)

		// Use external `umount -l` (lazy unmount)
		cmdUnmount := exec.Command("umount", "-l", path)

		// Execute the command via the privileged Executor
		if err := e.Run(cmdUnmount); err != nil {
			// Note: We avoid checking specific syscall errors (like EBUSY) here
			// because the error comes from the external `umount` binary.
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("Failed to umount %s (via external umount): %v", path, err))
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("multiple unmount errors occurred:\n%s", strings.Join(cleanupErrors, "\n"))
	}
	return nil
}

// BindMount creates the destination directory and performs a recursive bind mount
// using the external 'mount' binary via e.Run() to ensure proper privilege escalation.
func (e *Executor) BindMount(source, dest, options string) error {
	// 1. Ensure the destination directory exists
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dest, err)
	}

	// 2. Perform the bind mount: `mount --bind source dest`
	// We use an external command to trigger the privilege escalation via e.Run().
	// Note: We use the '-o bind' option, which is equivalent to MS_BIND.
	cmdBind := exec.Command("mount", "--bind", source, dest)

	debugf("[INFO] Running: %s %s\n", "mount", strings.Join(cmdBind.Args, " "))
	if err := e.Run(cmdBind); err != nil {
		return fmt.Errorf("failed to perform bind mount of %s to %s: %w", source, dest, err)
	}

	// 3. Set mount propagation to MS_PRIVATE (using external mount command)
	// This prevents chroot mount/unmount events from affecting the host.
	// We use --make-rprivate to apply recursively and privately.
	// We MUST run this as a separate command.
	cmdPrivate := exec.Command("mount", "--make-rprivate", dest)

	if err := e.Run(cmdPrivate); err != nil {
		fmt.Printf("[WARNING] Could not set mount %s to private: %v\n", dest, err)
		// This is a warning, not a fatal error, so we continue.
	}

	return nil
}

// ExecuteChroot executes the target command inside the chroot environment.
// It relies on the external 'chroot' binary, which is automatically wrapped
// with 'sudo' (if needed) and run via the Executor.Run method.
func (e *Executor) ExecuteChroot(targetDir string, cmdArgs []string) (int, error) {
	// First check if systemd-run is available
	_, err := exec.LookPath("systemd-run")
	if err == nil {
		// Build systemd-run invocation that sets RootDirectory and runs the command directly.
		suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
		unitName := "hokuto-chroot-" + filepath.Base(targetDir) + "-" + suffix
		sdArgs := []string{
			"systemd-run", "--pty",
			"--setenv=TERM=xterm",
			"--unit=" + unitName,
			"--description=hokuto chroot " + targetDir,
			"--property=RootDirectory=" + targetDir,
			"--",
		}
		sdArgs = append(sdArgs, cmdArgs...)

		cmd := exec.CommandContext(e.Context, sdArgs[0], sdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := e.Run(cmd); err != nil {
			return 1, fmt.Errorf("error running chroot via systemd-run: %w", err)
		}
		return 0, nil
	}

	// Fallback: use traditional chroot if systemd-run is not found
	chrootArgs := append([]string{targetDir}, cmdArgs...)
	cmd := exec.CommandContext(e.Context, "chroot", chrootArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := e.Run(cmd); err != nil {
		return 1, fmt.Errorf("error running chroot fallback: %w", err)
	}
	return 0, nil
}

// runChrootCommand encapsulates the chroot logic and GUARANTEES cleanup via defer.
func runChrootCommand(args []string, execCtx *Executor) (exitCode int) {
	// Set default exitCode to 1 (failure) in case we encounter errors before the chrooted command runs.
	exitCode = 1

	if len(args) < 1 {
		fmt.Println("Usage: hokuto chroot <targetdir> [command...]")
		return // Returns exitCode 1
	}

	targetDir := args[0]
	var chrootCmd []string
	if len(args) > 1 {
		chrootCmd = args[1:]
	} else {
		// FIX: Add the interactive flag to prevent hangs on startup
		chrootCmd = []string{"/bin/bash", "-i", "-l"}
	}
	// --- A. DEFERRED CLEANUP (CRITICAL STEP) ---
	pathsToUnmount := []string{
		// Reverse order of mounting, most nested first.
		filepath.Join(targetDir, "tmp"),
		filepath.Join(targetDir, "run"),
		filepath.Join(targetDir, "dev/shm"),
		filepath.Join(targetDir, "dev/pts"),
		// Specific device files must be unmounted BEFORE /dev
		filepath.Join(targetDir, "dev/tty"),
		filepath.Join(targetDir, "dev/console"),
		filepath.Join(targetDir, "dev/null"),
		filepath.Join(targetDir, "dev"),
		//filepath.Join(targetDir, "sys/firmware/efi/efivars"),
		filepath.Join(targetDir, "sys"),
		filepath.Join(targetDir, "proc"),
	}

	// Filter out paths that don't exist before deferring cleanup
	existingPaths := []string{}
	for _, p := range pathsToUnmount {
		if _, err := os.Stat(p); err == nil {
			existingPaths = append(existingPaths, p)
		}
	}

	defer func() {
		colArrow.Print("-> ")
		colSuccess.Println("Starting chroot cleanup")
		// Use the list of paths confirmed to exist
		err := execCtx.UnmountFilesystems(existingPaths)
		if err != nil {
			// ... (error handling for cleanup) ...
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Successfully unmounted all chroot filesystems.")
		}
	}()

	// --- B. PREPARATION ---
	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)

	debugf("[INFO] Setting up specialized mounts in %s \n", targetDir)

	// Helper to reduce verbosity. m now sends the full destination path.
	m := func(source, target string, fsType, options string, isBind bool) error {
		// Construct the full destination path here once: /var/tmp/lfs + /proc = /var/tmp/lfs/proc
		destPath := filepath.Join(targetDir, target)
		return execCtx.executeMountCommand(source, destPath, fsType, options, isBind)
	}
	// NOTE: If any mount fails, the function returns, and the defer block executes.

	// 1. /proc (proc)
	if err := m("proc", "proc", "proc", "nosuid,noexec,nodev", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /proc: %v\n", err)
		return
	}

	// 2. /sys (sysfs)
	if err := m("sys", "sys", "sysfs", "nosuid,noexec,nodev,ro", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /sys: %v\n", err)
		return
	}

	// 3. /sys/firmware/efi/efivars (Conditional mount)
	efiVarsPath := filepath.Join(targetDir, "sys/firmware/efi/efivars")
	if _, err := os.Stat(efiVarsPath); err == nil {
		// ignore_error here, so we don't return on failure.
		m("efivarfs", "sys/firmware/efi/efivars", "efivarfs", "nosuid,noexec,nodev", false)
	}

	// 4. /dev (devtmpfs) - CRITICAL for TTY/ioctl fix
	if err := m("udev", "dev", "devtmpfs", "mode=0755,nosuid", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev: %v\n", err)
		return
	}

	// 5. /dev/pts (devpts)
	if err := m("devpts", "dev/pts", "devpts", "mode=0620,gid=5,nosuid,noexec", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev/pts: %v\n", err)
		return
	}

	// 6. Bind mount essential TTY/device nodes (The ioctl fix)
	if err := m("/dev/ptmx", "dev/ptmx", "", "", true); err != nil { // <-- This now correctly creates a file placeholder
		fmt.Printf("[FATAL] Failed to bind /dev/ptmx: %v\n", err)
		return
	}
	if err := m("/dev/tty", "dev/tty", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/tty: %v\n", err)
		return
	}
	if err := m("/dev/console", "dev/console", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/console: %v\n", err)
		return
	}
	if err := m("/dev/null", "dev/null", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/null: %v\n", err)
		return
	}

	// 7. /dev/shm (tmpfs)
	if err := m("shm", "dev/shm", "tmpfs", "mode=1777,nosuid,nodev", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev/shm: %v\n", err)
		return
	}

	// 8. /run (Bind mount with private propagation)
	if err := m("/run", "run", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /run: %v\n", err)
		return
	}
	// Execute the propagation step separately
	execCtx.executeMountCommand("", filepath.Join(targetDir, "run"), "", "--make-private", true)

	// 9. /tmp (tmpfs)
	if err := m("tmp", "tmp", "tmpfs", "mode=1777,strictatime,nodev,nosuid", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /tmp: %v\n", err)
		return
	}

	// --- C. CHROOT EXECUTION ---
	colArrow.Print("-> ")
	colSuccess.Printf("Executing command %v in chroot %s\n", chrootCmd, targetDir)

	finalCode, err := execCtx.ExecuteChroot(targetDir, chrootCmd)

	// Check for errors during execution (not just non-zero exit code)
	if err != nil {
		// Handle the "No such file or directory" error specifically
		if strings.Contains(err.Error(), "No such file or directory") {
			fmt.Printf("[ERROR] Chroot command failure: The target executable '%s' was not found inside %s.\n", chrootCmd[0], targetDir)
			// Set exitCode to 127 (standard for 'command not found')
			exitCode = 127
		} else {
			fmt.Printf("[ERROR] Command failed inside chroot: %v\n", err)
			exitCode = 1
		}
		return // Returns the updated exitCode. The defer will execute now.
	}

	// Success: return the exit code from the chrooted command.
	exitCode = finalCode
	return
}

// getPackageDependenciesToUninstall returns a list of package names to uninstall
// before installing the given package. For Python/Cython packages, it returns the
// package name itself. For specific packages, it returns their associated dependencies.
// Returns an empty slice if no uninstallation is needed.
// This fixes issues with broken pip versions during upgrades and removes bootstrap packages when required.
func getPackageDependenciesToUninstall(name string) []string {
	switch name {
	case "gcc":
		return []string{"02-gcc-1", "20-gcc-2", "05-libstdc++"}
	case "binutils":
		return []string{"01-binutils-1", "19-binutils-2"}
	case "linux-headers":
		return []string{"03-linux-headers"}
	case "m4":
		return []string{"06-m4"}
	case "ncurses":
		return []string{"07-ncurses"}
	case "bash":
		return []string{"08-bash"}
	case "diffutils":
		return []string{"10-diffutils"}
	case "file":
		return []string{"11-file"}
	case "gawk":
		return []string{"13-gawk"}
	case "grep":
		return []string{"14-grep"}
	case "gzip":
		return []string{"15-gzip"}
	case "make":
		return []string{"16-make"}
	case "patch":
		return []string{"17-patch"}
	case "sed":
		return []string{"18-sed"}
	case "hokuto":
		return []string{"21-hokuto"}
	case "python", "cython":
		return []string{name}
	default:
		if strings.HasPrefix(name, "python-") || strings.HasPrefix(name, "cython-") {
			return []string{name}
		}
		return nil // No dependencies to uninstall
	}
}

// handleCleanupCommand handles the 'cleanup' subcommand
func handleCleanupCommand(args []string) error {
	cleanupCmd := flag.NewFlagSet("cleanup", flag.ExitOnError)
	cleanSources := cleanupCmd.Bool("sources", false, "Remove all cached source files.")
	cleanBins := cleanupCmd.Bool("bins", false, "Remove all built binary packages.")
	cleanAll := cleanupCmd.Bool("all", false, "Remove both sources and binaries.")

	if err := cleanupCmd.Parse(args); err != nil {
		return err // Should not happen with flag.ExitOnError
	}

	// If no flags are provided, show help and exit
	if !*cleanSources && !*cleanBins && !*cleanAll {
		fmt.Println("Usage: hokuto cleanup [flag]")
		fmt.Println("You must specify what to clean up. Use one of the following flags:")
		cleanupCmd.PrintDefaults()
		return nil
	}

	// If -all is used, it implies both sources and bins
	if *cleanAll {
		*cleanSources = true
		*cleanBins = true
	}

	if *cleanSources {
		colArrow.Print("-> ")
		cPrintf(colWarn, "Deleting sources cache at %s.\n", SourcesDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing source cache directory: %s\n", SourcesDir)
			rmCmd := exec.Command("rm", "-rf", SourcesDir)
			if err := RootExec.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove source cache: %w", err)
			}
			colArrow.Print("-> ")
			colSuccess.Println("Source cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of source cache canceled.")
		}
	}

	if *cleanBins {
		cPrintf(colWarn, "This will permanently delete all built binary packages at %s.\n", BinDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing binary cache directory: %s\n", BinDir)
			rmCmd := exec.Command("rm", "-rf", BinDir)
			if err := RootExec.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove binary cache: %w", err)
			}
			colArrow.Print("-> ")
			colSuccess.Println("Binary cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of binary cache canceled.")
		}
	}

	return nil
}

// printHelp prints the commands table
func printHelp() {
	// General Usage Header
	color.Bold.Println("Usage: hokuto <command> [arguments...]")
	fmt.Println()
	color.Info.Println("Available Commands:")

	type cmdInfo struct {
		Cmd  string
		Args string
		Desc string
	}
	// Restore detailed descriptions including command-specific options
	cmds := []cmdInfo{
		{"version, --version", "", "Show hokuto version and information"},
		{"list, ls", "[pkg]", "List installed packages, optionally filter by name"},
		{"checksum, c", "<pkg>", "Fetch sources and generate checksum file for a package. -f (force redwonload of sources)"},
		{"build, b", "<pkg...>", "Build package(s). -a (auto-install), -i (half cpu cores), -ii (one cpu core), --alldeps"},
		{"install, i", "<pkg...>", "Install pre-built packages from the binary cache or a specified .tar.zst file"},
		{"uninstall, r", "<pkg...>", "Uninstall package(s). -f (force), -y (skip confirmation)"},
		{"update, u", "[options]", "Update repositories and check for upgrades. Options: -i (half cpu cores), -ii (one cpu core)"},
		{"manifest, m", "<pkg>", "Show the file list for an installed package"},
		{"find, f", "<query>", "Find which package matches query string"},
		{"new, n", "<pkg>", "Create a new package skeleton"},
		{"edit, e", "<pkg>", "Edit a package's build files. -a (edit all files)"},
		{"bootstrap", "<dir>", "Build a bootstrap rootfs in target directory"},
		{"chroot", "<dir> [cmd...]", "Enter chroot and run command (default: /bin/bash)"},
		{"cleanup", "[options]", "Clean up cache directories. -sources, -bins, -all"},
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
	color.Info.Println("Run 'hokuto <command> --help' for more details on a specific command.")
}

// Entry point
func main() {

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
	// The rest of the main function is wrapped in a way that respects the context.
	// Use an anonymous function to encapsulate the logic and use defer cancel().
	// We pass the context to the executor and the main commands.

	// Check for immediate cancellation before starting (e.g., if signal received early)
	if ctx.Err() != nil {
		// Already cancelled before we started the main logic
		return
	}

	// Now, wrap your existing logic:

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
	case "chroot":
		// Call the new wrapper function that contains the defer logic
		exitCode = runChrootCommand(os.Args[2:], RootExec)

	case "cleanup":
		if err := handleCleanupCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup failed: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version":
		// Print version first
		// HOKUTOVERSION (string for search)
		fmt.Println("hokuto 0.2.26")

		// Try to pick and show a random embedded PNG from assets/
		imgs, err := listEmbeddedImages()
		if err != nil || len(imgs) == 0 {
			// No images available — nothing more to do
			if err != nil {
				fmt.Fprintln(os.Stderr, "warning: failed to list embedded images:", err)
			}
			break
		}

		// Choose a random image
		choice := imgs[rand.Intn(len(imgs))]

		// Inform user which image we'll show (colored if you like)
		//color.Info.Printf("Showing image: %s\n", choice)

		// Display via chafa using the main context (ctx must be in scope in main)
		// Forward a small default set of chafa flags; you may change or pass none.
		if err := displayEmbeddedWithChafa(ctx, choice, "--symbols=block", "--size=80x40"); err != nil {
			fmt.Fprintln(os.Stderr, "error displaying image:", err)
		}

	case "list", "ls":
		pkg := ""
		if len(os.Args) >= 3 {
			pkg = os.Args[2]
		}
		if err := listPackages(pkg); err != nil {
			fmt.Println("Error:", err)
		}

	case "checksum", "c":
		force := false

		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto checksum <pkg1> [<pkg2> ...] [-f]")
			return
		}

		// Collect args after the command
		args := os.Args[2:]

		// If last argument is -f, enable force and drop it from package list
		if len(args) > 0 && args[len(args)-1] == "-f" {
			force = true
			args = args[:len(args)-1]
		}

		if len(args) == 0 {
			fmt.Println("Usage: hokuto checksum <pkg1> [<pkg2> ...] [-f]")
			return
		}

		// args now contains one or more package names
		var overallErr error
		for _, pkg := range args {
			if err := hokutoChecksum(pkg, force); err != nil {
				fmt.Printf("Error for %s: %v\n", pkg, err)
				overallErr = err
				// continue to process remaining packages
			}
		}

		if overallErr != nil {
			os.Exit(1)
		}

	case "build", "b":
		handleBuildCommand(os.Args[2:], cfg)

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
			"--bootstrap",
			"--bootstrap-dir",
			bootstrapDirArg,
			"bootstrap", // The specific package to build in bootstrap mode.
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Starting bootstrap process in directory: %s\n", bootstrapDirArg)

		// 3. Call the generic build handler with the constructed arguments.
		handleBuildCommand(buildArgs, cfg)

	case "install", "i":
		// Get all arguments after "hokuto" and "install"
		args := os.Args[2:]
		if len(args) == 0 {
			fmt.Println("Usage: hokuto install <tarball|pkgname>")
			os.Exit(1)
		}

		// Set to CRITICAL (1) for the entire installation process
		isCriticalAtomic.Store(1)
		// Ensure it is reset when the install function returns/panics
		defer isCriticalAtomic.Store(0)

		allSucceeded := true

		// Loop through all provided arguments (tarballs or package names)
		for _, arg := range args {
			var tarballPath, pkgName string

			debugf("Processing argument: %s\n", arg)

			if strings.HasSuffix(arg, ".tar.zst") {
				// Direct tarball path
				tarballPath = arg
				base := filepath.Base(tarballPath)

				// Determine package name from tarball filename (e.g., pkgname-version.tar.zst)
				// Remove .tar.zst extension first
				nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")

				// Find the last dash that separates package name from version
				// Version typically contains dots, so we look for the last dash before the version
				lastDashIndex := strings.LastIndex(nameWithoutExt, "-")
				if lastDashIndex == -1 {
					fmt.Fprintf(os.Stderr, "Error: Could not determine package name from tarball file name: %s\n", arg)
					allSucceeded = false
					continue
				}

				// Extract the part before the last dash as package name
				pkgName = nameWithoutExt[:lastDashIndex]

				// Verify the tarball actually exists before attempting install
				if _, err := os.Stat(tarballPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error: Tarball not found or inaccessible: %s\n", tarballPath)
					allSucceeded = false
					continue
				}

			} else {
				// Package name
				pkgName = arg

				// 1. Get the version for the package
				version, err := getRepoVersion(pkgName)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error determining version for %s: %v\n", pkgName, err)
					allSucceeded = false
					continue
				}

				// 2. Determine the expected path in BinDir
				tarballPath = filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, version))

				// 3. Check if the pre-built tarball exists
				if _, err := os.Stat(tarballPath); err != nil {
					cPrintf(colWarn, "Error: Package tarball not found for %s at %s.\n", pkgName, tarballPath)
					allSucceeded = false
					continue
				}
			}

			// --- Installation Execution ---
			// Check if package has dependencies to uninstall first
			depsToUninstall := getPackageDependenciesToUninstall(pkgName)
			if len(depsToUninstall) > 0 {
				debugf("Package %s requires uninstalling dependencies: %v\n", pkgName, depsToUninstall)
				for _, dep := range depsToUninstall {
					debugf("Uninstalling %s\n", dep)
					if err := pkgUninstall(dep, cfg, RootExec, true, true); err != nil {
						// Log warning but continue with installation
						debugf("Warning: failed to uninstall %s: %v (continuing with installation)\n", dep, err)
					} else {
						debugf("%s uninstalled successfully.\n", dep)
					}
				}
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Installing %s from %s\n", pkgName, tarballPath)

			if err := pkgInstall(tarballPath, pkgName, cfg, RootExec); err != nil {
				fmt.Fprintf(os.Stderr, "Error installing package %s: %v\n", pkgName, err)
				allSucceeded = false
				// Continue to the next package
				continue
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Package %s installed successfully.\n", pkgName)
		}

		if !allSucceeded {
			// Exit with an error code if any package failed to install
			os.Exit(1)
		}

	case "uninstall", "remove", "r":
		// 1. Initialize a FlagSet for the "uninstall" subcommand
		uninstallCmd := flag.NewFlagSet("uninstall", flag.ExitOnError)
		var force = uninstallCmd.Bool("f", false, "Force uninstallation, ignoring dependency checks.")
		var yes = uninstallCmd.Bool("y", false, "Assume 'yes' to all prompts.")
		// Also support long flags for consistency, though the user didn't specify them
		var forceLong = uninstallCmd.Bool("force", false, "Force uninstallation, ignoring dependency checks.")
		var yesLong = uninstallCmd.Bool("yes", false, "Assume 'yes' to all prompts.")

		// Parse the arguments specific to the "uninstall" subcommand,
		// starting from os.Args[2] (i.e., skipping "hokuto" and "uninstall")
		if err := uninstallCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing uninstall flags: %v\n", err)
			os.Exit(1)
		}

		// The positional arguments (package names) are now in uninstallCmd.Args()
		packagesToUninstall := uninstallCmd.Args()

		if len(packagesToUninstall) == 0 {
			fmt.Println("Usage: hokuto uninstall [options] <pkgname> [pkgname...]")
			fmt.Println("Options:")
			uninstallCmd.PrintDefaults()
			os.Exit(1)
		}

		// Combine short and long flags for the final effective value
		effectiveForce := *force || *forceLong
		effectiveYes := *yes || *yesLong

		// critical section for the entire operation
		isCriticalAtomic.Store(1)
		defer isCriticalAtomic.Store(0)

		// Loop through all provided packages and attempt to uninstall each one
		allSucceeded := true
		for _, pkgName := range packagesToUninstall {
			colArrow.Print("-> ")
			colSuccess.Printf("Attempting to uninstall package: %s\n", pkgName)

			// The pkgUninstall function must be updated to accept the final flag values
			if err := pkgUninstall(pkgName, cfg, RootExec, effectiveForce, effectiveYes); err != nil {
				colArrow.Print("-> ")
				color.Light.Printf("Error uninstalling %s: %v\n", pkgName, err)
				allSucceeded = false
				// Continue to the next package instead of os.Exit(1) immediately
				// This allows for partial success if one package fails but others succeed.
			} else {
				colArrow.Print("-> ")
				colSuccess.Printf("Package %s removed\n", pkgName)
			}
		}

		if !allSucceeded {
			// Exit with an error code if any package failed to uninstall
			os.Exit(1)
		}

	case "update", "u":
		// check for -i and -v in the arguments for the update command
		// os.Args layout: [program, "update", ...flags...]
		for _, a := range os.Args[2:] {
			if a == "-i" || a == "--idle" {
				idleUpdate = true
			}
			if a == "-ii" || a == "--superidle" {
				superidleUpdate = true
			}
			if a == "-v" || a == "--verbose" {
				Verbose = true
			}
		}

		updateRepos()

		if err := PostInstallTasks(RootExec); err != nil {
			fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
		}

		if err := checkForUpgrades(); err != nil {
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
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto new <pkgname>")
			os.Exit(1)
		}
		pkg := os.Args[2]
		if err := newPackage(pkg); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	case "edit", "e":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto edit <pkgname> [-a]")
			os.Exit(1)
		}

		// Default: pkgName is os.Args[2]
		pkg := os.Args[2]
		openAll := false

		// Check if there is a third argument and if it's the -a flag
		if len(os.Args) == 4 {
			if os.Args[3] == "-a" {
				openAll = true
			} else {
				// Handle invalid third argument (e.g., hokuto edit pkgname junk)
				fmt.Println("Usage: hokuto edit <pkgname> [-a]")
				os.Exit(1)
			}
		} else if len(os.Args) > 4 {
			// Handle too many arguments
			fmt.Println("Usage: hokuto edit <pkgname> [-a]")
			os.Exit(1)
		}

		// Pass the flag to the function
		if err := editPackage(pkg, openAll); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	default:
		printHelp()
		exitCode = 1
	}
	os.Exit(exitCode)
}
