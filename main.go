package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"
)

// --- NEW GLOBAL STATE ---
// We use a value of 1 for critical and 0 for non-critical/default.
var isCriticalAtomic atomic.Int32

var (
	rootDir    string
	CacheDir   string
	SourcesDir string
	BinDir     string
	CacheStore string
	Installed  string
	repoPaths  string
	tmpDir     string
	WantStrip  string
	ConfigFile = "/etc/hokuto.conf"
	// Global executors (declared, to be assigned in main)
	UserExec *Executor
	RootExec *Executor
)

// Config struct
type Config struct {
	Values       map[string]string
	DefaultStrip bool
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
}

func initConfig(cfg *Config) {
	rootDir = cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}

	repoPaths = cfg.Values["HOKUTO_PATH"]
	if repoPaths == "" {
		log.Fatalf("Critical error: HOKUTO_PATH is not set in the configuration.")
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

	CacheDir = "/var/cache/hokuto"
	SourcesDir = CacheDir + "/sources"
	BinDir = CacheDir + "/bin"
	CacheStore = SourcesDir + "/_cache"
	Installed = rootDir + "/var/db/hokuto/installed"

}

// Executor provides a consistent interface for executing commands,
// abstracting away the privilege escalation (sudo) logic.
type Executor struct {
	Context         context.Context // The context to use for cancellation
	ShouldRunAsRoot bool            // ShouldRunAsRoot specifies whether the command MUST be executed with root privileges.
	sudoPrimed      bool
}

// Update the constructor/factory function for Executor
func NewExecutor(ctx context.Context /* other params */) *Executor {
	// ... initialize other fields if necessary
	return &Executor{Context: ctx}
}

// ensureSudo only prompts for a password if sudo really needs one.
// 1. If we’re root or root‐mode isn’t required, do nothing.
// 2. If we've already primed, try “sudo -v” (interactive on expiry).
// 3. Otherwise, run “sudo -n -v” (noninteractive); if it succeeds, no password is needed.
// 4. If that fails, open /dev/tty, read the password, then run “sudo -S -v” to prime.
func (e *Executor) ensureSudo() error {
	// no elevation needed if we’re already root or ShouldRunAsRoot is false
	if os.Geteuid() == 0 || !e.ShouldRunAsRoot {
		return nil
	}

	// if we’ve primed before, refresh the timestamp (may re‐prompt if expired)
	if e.sudoPrimed {
		refresh := exec.CommandContext(e.Context, "sudo", "-v")
		refresh.Stdin = os.Stdin
		refresh.Stdout = os.Stdout
		refresh.Stderr = os.Stderr
		if err := refresh.Run(); err == nil {
			return nil
		}
		// expired or error: clear flag and fall through to interactive prompt
		e.sudoPrimed = false
	} else {
		// try noninteractive validation: succeeds if nopasswd or timestamp still valid
		check := exec.CommandContext(e.Context, "sudo", "-n", "-v")
		check.Stdout = io.Discard
		check.Stderr = io.Discard
		if err := check.Run(); err == nil {
			e.sudoPrimed = true
			return nil
		}
		// noninteractive check failed: sudo needs a password
	}

	// interactive password prompt via the real tty
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return fmt.Errorf("cannot open /dev/tty: %w", err)
	}
	defer tty.Close()

	fmt.Fprint(os.Stderr, "Enter sudo password: ")
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("reading sudo password: %w", err)
	}

	// prime sudo’s timestamp cache
	prime := exec.CommandContext(e.Context, "sudo", "-S", "-v")
	prime.Stdin = strings.NewReader(string(pass) + "\n")
	prime.Stdout = os.Stdout
	prime.Stderr = os.Stderr
	if err := prime.Run(); err != nil {
		return fmt.Errorf("sudo validation failed: %w", err)
	}

	e.sudoPrimed = true
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

	// --- Phase 1: maybe prime sudo ---
	if err := e.ensureSudo(); err != nil {
		return err
	}

	// --- Phase 2: build the final command ---
	var finalCmd *exec.Cmd
	if e.ShouldRunAsRoot && os.Geteuid() != 0 {
		// use -E only so sudo reads its own tty and uses our cached ticket
		args := append([]string{"-E", cmd.Path}, cmd.Args[1:]...)
		finalCmd = exec.CommandContext(e.Context, "sudo", args...)
	} else {
		finalCmd = exec.CommandContext(e.Context, cmd.Path, cmd.Args[1:]...)
	}

	// preserve or inherit the environment
	if len(cmd.Env) > 0 {
		finalCmd.Env = cmd.Env
	} else {
		finalCmd.Env = os.Environ()
	}

	// carry over working dir and stdio
	finalCmd.Dir = cmd.Dir
	finalCmd.Stdin = cmd.Stdin
	finalCmd.Stdout = cmd.Stdout
	finalCmd.Stderr = cmd.Stderr

	// --- Phase 3: isolate process group for context‐based cleanup ---
	finalCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// --- Phase 4: start and watch for cancel ---
	if err := finalCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}
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

// List installed packages with version, supporting partial matches.
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
		// This is the new logic for partial matching
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, we'll show everything
		pkgsToShow = allPkgs
	}

	// Step 3: Handle the case where no packages were found after filtering.
	if len(pkgsToShow) == 0 {
		if searchTerm != "" {
			return fmt.Errorf("no packages found matching: %s", searchTerm)
		}
		// This handles the case where there are no packages installed at all.
		fmt.Println("No packages installed.")
		return nil
	}

	// Step 4: Print the information for the final list of packages.
	// This part remains the same as your original code.
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		version := "unknown"
		if data, err := os.ReadFile(versionFile); err == nil {
			version = strings.TrimSpace(string(data))
		}
		fmt.Printf("%s %s\n", p, version)
	}

	return nil
}

// Hashing helper for cached filenames
func hashString(s string) string {
	cmd := exec.Command("b3sum")
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.Output()
	if err != nil {
		return "hashfail"
	}
	return strings.Fields(string(out))[0]
}

// downloadFile downloads a URL into the hokuto cache
func downloadFile(url, destFile string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(CacheStore, 0o755); err != nil {
		return err
	}

	// destFile is the filename only (without path)
	destFile = filepath.Base(destFile)
	fmt.Printf("Downloading %s -> %s/%s\n", url, CacheStore, destFile)

	// Try aria2c first
	cmd := exec.Command("aria2c", "-x", "4", "-s", "4", "-d", CacheStore, "-o", destFile, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("aria2c failed, falling back to curl")

		absPath := filepath.Join(CacheStore, destFile)
		cmd = exec.Command("curl", "-L", "-o", absPath, url)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return nil
}

// Fetch sources (HTTP/FTP + Git)
func fetchSources(pkgName, pkgDir string) error {
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

		// --- NEW: Split the line into source URL and potential extra parameter ---
		parts := strings.SplitN(line, " ", 2)
		sourceURL := parts[0]
		// The second part (parts[1]) is the parameter to ignore here (e.g., "mpv-old").
		// --------------------------------------------------------------------------

		// Skip local files
		if strings.HasPrefix(sourceURL, "files/") {
			continue
		}
		// Note: Patches/ are typically handled in prepareSources, not fetched.

		if strings.HasPrefix(sourceURL, "git+") {
			// Git repo handling
			gitURL := strings.TrimPrefix(sourceURL, "git+")
			ref := ""
			if strings.Contains(gitURL, "#") {
				subParts := strings.SplitN(gitURL, "#", 2)
				gitURL = subParts[0]
				ref = subParts[1]
			}
			parts := strings.Split(strings.TrimSuffix(gitURL, ".git"), "/")
			repoName := parts[len(parts)-1]
			destPath := filepath.Join(pkgLinkDir, repoName) // destPath is where the repo is cloned

			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				fmt.Printf("Cloning git repository %s into %s\n", gitURL, destPath)
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

			// Disable detached HEAD advice
			exec.Command("git", "-C", destPath, "config", "advice.detachedHead", "false").Run()

			if ref != "" {
				// Ref check logic remains the same
				checkBranch := exec.Command("git", "-C", destPath, "rev-parse", "--verify", "refs/heads/"+ref)
				if err := checkBranch.Run(); err == nil {
					// branch → checkout + pull
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
					cmd = exec.Command("git", "-C", destPath, "pull")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				} else {
					// tag/commit → checkout only
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				}
			}
			fmt.Printf("Git repository ready: %s\n", destPath)
			continue
		}

		// HTTP/FTP sources
		// Use sourceURL instead of line
		parts = strings.Split(sourceURL, "/")
		origFilename := parts[len(parts)-1]

		// The hash should only be based on the URL, not the external parameter.
		hashName := fmt.Sprintf("%s-%s", hashString(sourceURL), origFilename)
		cachePath := filepath.Join(CacheStore, hashName)

		if _, err := os.Stat(cachePath); os.IsNotExist(err) {
			if err := downloadFile(sourceURL, cachePath); err != nil {
				return fmt.Errorf("failed to download %s: %v", sourceURL, err)
			}
		} else {
			fmt.Printf("Already in cache: %s\n", cachePath)
		}

		// --- Linked file is created using the original filename from the URL ---
		linkPath := filepath.Join(pkgLinkDir, origFilename)
		if _, err := os.Lstat(linkPath); err == nil {
			os.Remove(linkPath)
		}
		if err := os.Symlink(cachePath, linkPath); err != nil {
			return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, linkPath, err)
		}
		fmt.Printf("Linked %s -> %s\n", linkPath, cachePath)
	}

	return nil
}

func verifyOrCreateChecksums(pkgName, pkgDir string) error {
	pkgSrcDir := filepath.Join(SourcesDir, pkgName)
	checksumFile := filepath.Join(pkgDir, "checksums") // repo package dir

	existing := make(map[string]string)
	if f, err := os.Open(checksumFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				existing[parts[1]] = parts[0]
			} else {
				existing["single"] = parts[0]
			}
		}
		f.Close()
	}

	files, err := os.ReadDir(pkgSrcDir)
	if err != nil {
		return fmt.Errorf("cannot read source dir: %v", err)
	}

	var summary []string
	var updatedChecksums []string

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		filePath := filepath.Join(pkgSrcDir, f.Name())

		hashValid := false
		mismatch := false
		skipped := false

		if oldSum, ok := existing[f.Name()]; ok {
			cmd := exec.Command("b3sum", "-c")
			cmd.Stdin = strings.NewReader(fmt.Sprintf("%s  %s\n", oldSum, filePath))
			if err := cmd.Run(); err == nil {
				hashValid = true
			} else {
				mismatch = true
			}
		}

		if mismatch {
			fmt.Printf("Checksum mismatch for %s. Redownload and regenerate checksum? [y/N]: ", f.Name())
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(strings.TrimSpace(response)) == "y" {
				// Redownload
				sourceLines, _ := os.ReadFile(filepath.Join(pkgDir, "sources"))
				for _, line := range strings.Split(string(sourceLines), "\n") {
					if strings.Contains(line, f.Name()) {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}

						// Compute hash filename for _cache
						hashName := fmt.Sprintf("%s-%s", hashString(line+f.Name()), f.Name())
						cachePath := filepath.Join(CacheStore, hashName)

						// Remove old cache file if exists
						if _, err := os.Stat(cachePath); err == nil {
							os.Remove(cachePath)
						}

						// Remove old symlink/file in source dir
						if _, err := os.Lstat(filePath); err == nil {
							os.Remove(filePath)
						}

						// Download into _cache
						if err := downloadFile(line, cachePath); err != nil {
							return fmt.Errorf("failed to redownload %s: %v", f.Name(), err)
						}

						// Create symlink in pkg dir
						if err := os.Symlink(cachePath, filePath); err != nil {
							return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, filePath, err)
						}

						hashValid = false // recompute checksum
					}
				}
			} else {
				fmt.Printf("Skipping update for %s\n", f.Name())
				// Remove invalid symlink
				if _, err := os.Lstat(filePath); err == nil {
					os.Remove(filePath)
				}

				// Remove cache file as well
				sourceLines, _ := os.ReadFile(filepath.Join(pkgDir, "sources"))
				for _, line := range strings.Split(string(sourceLines), "\n") {
					if strings.Contains(line, f.Name()) {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						hashName := fmt.Sprintf("%s-%s", hashString(line+f.Name()), f.Name())
						cachePath := filepath.Join(CacheStore, hashName)
						if _, err := os.Stat(cachePath); err == nil {
							os.Remove(cachePath)
						}
					}
				}

				skipped = true
				hashValid = false
			}
		}

		if !hashValid {
			if !skipped {
				fmt.Printf("Updating checksum for %s\n", f.Name())
				cmd := exec.Command("b3sum", filePath)
				out, err := cmd.Output()
				if err != nil {
					return fmt.Errorf("failed to compute checksum: %v", err)
				}
				sum := strings.Fields(string(out))[0]
				updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", sum, f.Name()))
				summary = append(summary, fmt.Sprintf("%s: updated", f.Name()))
			} else {
				// User skipped → mark as mismatch
				updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", existing[f.Name()], f.Name()))
				summary = append(summary, fmt.Sprintf("%s: mismatch (skipped)", f.Name()))
			}
		} else {
			updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", existing[f.Name()], f.Name()))
			summary = append(summary, fmt.Sprintf("%s: ok", f.Name()))
		}
	}

	// Write back to the package directory
	if err := os.WriteFile(checksumFile, []byte(strings.Join(updatedChecksums, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write checksums file: %v", err)
	}

	fmt.Printf("Checksums summary for %s:\n", pkgName)
	for _, s := range summary {
		fmt.Println(" -", s)
	}

	return nil
}

// checksum command
func hokutoChecksum(pkgName string) error {

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

	if err := fetchSources(pkgName, pkgDir); err != nil {
		return fmt.Errorf("error fetching sources: %v", err)
	}
	if err := verifyOrCreateChecksums(pkgName, pkgDir); err != nil {
		return fmt.Errorf("error verifying checksums: %v", err)
	}

	return nil
}

// prepareSources copies and extracts sources into the build directory
func prepareSources(pkgName, pkgDir, buildDir string, execCtx *Executor) error {
	// Assuming CacheDir, SourcesDir, Executor, etc. are available in scope.
	srcDir := filepath.Join(CacheDir, "sources", pkgName)

	// Clear buildDir
	// We clear the whole directory and then recreate it to ensure a clean start.
	rmCmd := exec.Command("rm", "-rf", buildDir)
	if err := execCtx.Run(rmCmd); err != nil {
		return fmt.Errorf("failed to clear build dir %s: %v", buildDir, err)
	}
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		return fmt.Errorf("failed to create build dir %s: %v", buildDir, err)
	}

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

		// 1. Split the line into source path and optional target subdirectory
		parts := strings.SplitN(line, " ", 2)
		relPath := parts[0]
		targetSubdir := ""
		if len(parts) == 2 {
			targetSubdir = parts[1]
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
		case strings.HasPrefix(relPath, "patches/"):
			// Local patches in package directory
			srcPath = filepath.Join(pkgDir, relPath)
		case isGitSource:
			// Git sources: Source path is the cloned directory in the cache (SourcesDir/pkgName/repoName)
			gitURL := strings.TrimPrefix(relPath, "git+")
			parsedURL, err := url.Parse(gitURL)
			if err != nil {
				return fmt.Errorf("invalid git URL in sources file: %w", err)
			}
			repoBase := filepath.Base(parsedURL.Path)
			if strings.HasSuffix(repoBase, ".git") {
				repoBase = strings.TrimSuffix(repoBase, ".git")
			}
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

		// Extract archives or copy file (using realPath)
		switch {
		case strings.HasSuffix(realPath, ".tar.gz"),
			strings.HasSuffix(realPath, ".tar.xz"),
			strings.HasSuffix(realPath, ".tar.bz2"),
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
			lddCmd.Stderr = os.Stderr // pipe errors to our stderr

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

	fmt.Printf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(seen))
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

// listOutputFiles generates a list of all files and directories in outputDir.
func listOutputFiles(outputDir string, execCtx *Executor) ([]string, error) {
	var entries []string

	// Use find via sudo to safely list all files and directories
	cmd := exec.Command("find", outputDir)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := execCtx.Run(cmd); err != nil {
		return nil, fmt.Errorf("failed to list output files via find: %v", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		path := scanner.Text()

		// Compute path relative to outputDir
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

		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
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

// generateManifest scans outputDir and writes a manifest file
// installedDir is the directory where the manifest file will be placed
// outputDir is the dir scanned for files
func generateManifest(outputDir, installedDir string, execCtx *Executor) error {
	manifestFile := filepath.Join(installedDir, "manifest")
	tmpManifest := filepath.Join(os.TempDir(), filepath.Base(manifestFile)+".tmp")

	// Ensure installedDir exists as root
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installedDir: %v", err)
	}

	// List all output files
	entries, err := listOutputFiles(outputDir, execCtx)
	if err != nil {
		return fmt.Errorf("failed to list output files: %v", err)
	}

	// Remove manifest from entries if present
	relManifest, err := filepath.Rel(outputDir, manifestFile)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for manifest: %v", err)
	}

	filtered := []string{}
	for _, e := range entries {
		if e != "/"+relManifest {
			filtered = append(filtered, e)
		}
	}
	filtered = append(filtered, "/"+relManifest)

	// Open temp manifest for writing
	f, err := os.OpenFile(tmpManifest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open temporary manifest file: %v", err)
	}
	defer f.Close()

	for _, entry := range filtered {
		absPath := filepath.Join(outputDir, strings.TrimPrefix(entry, "/"))
		info, err := os.Stat(absPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			cleaned := "/" + strings.Trim(strings.TrimPrefix(entry, "/"), "/") + "/"
			if _, err := fmt.Fprintf(f, "%s\n", cleaned); err != nil {
				return fmt.Errorf("failed to write manifest entry: %v", err)
			}
			continue
		}

		// Compute checksum with b3sum helper
		checksum, err := b3sum(absPath, execCtx)
		if err != nil {
			return fmt.Errorf("b3sum failed for %s: %v", absPath, err)
		}

		// The output parsing and error checking is now handled inside the b3sum function,
		// but we still check the overall function error.
		// Note: The rest of the logic remains the same, as the b3sum function now returns
		// the computed checksum string directly.

		if _, err := fmt.Fprintf(f, "%s  %s\n", entry, checksum); err != nil {
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}

	}

	f.Close() // close before moving

	// Move temp manifest into installedDir as root
	cpCmd := exec.Command("cp", "--remove-destination", tmpManifest, manifestFile)
	if err := execCtx.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy temporary manifest into place: %v", err)
	}

	// Remove temp manifest
	os.Remove(tmpManifest)

	fmt.Printf("Manifest written to %s (%d entries)\n", manifestFile, len(filtered))
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

// extractTar extracts a tarball into the destination directory
func extractTar(archive, dest string) error {
	cmd := exec.Command("tar", "xf", archive, "-C", dest, "--strip-components=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract %s: %v", archive, err)
	}
	return nil
}

func createPackageTarball(pkgName, pkgVer, outputDir string, execCtx *Executor) error {
	// Ensure BinDir exists
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create BinDir: %v", err)
	}

	tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, pkgVer))

	args := []string{"-cf", tarballPath, "-C", outputDir, "."}
	args = append([]string{"--zstd"}, args...) // always compress

	// Check if the build phase ran as an unprivileged user.
	// If ShouldRunAsRoot is FALSE, the build ran as the user, and we must override ownership inside the tarball.
	if !execCtx.ShouldRunAsRoot {
		// Force numeric root ownership for user builds
		// This ensures the files inside the tarball are always 0:0 regardless of the builder's UID.
		args = append(args, "--owner=0", "--group=0", "--numeric-owner")
	}

	// Create the final tar command
	tarCmd := exec.Command("tar", args...)

	fmt.Printf("Creating package tarball: %s\n", tarballPath)
	if err := execCtx.Run(tarCmd); err != nil {
		return fmt.Errorf("failed to create tarball: %v", err)
	}

	fmt.Printf("Package tarball created successfully: %s\n", tarballPath)
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

	var modified []string
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

		// Compute b3sum of installed file
		sum, err := b3sum(absPath, execCtx)
		if err != nil {
			continue // skip missing files or checksum failures
		}

		// Compare with recorded hash in manifest (if present)
		if len(parts) > 1 && parts[1] != sum {
			modified = append(modified, relPath)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	return modified, nil
}

// Helper to compute b3sum of a file, using system b3sum binary
func b3sum(path string, execCtx *Executor) (string, error) {
	// We remove the internal privilege check (if os.Geteuid() != 0)
	// and let the Executor handle it.

	cmd := exec.Command("b3sum", path)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr // Pipe errors to the calling process stderr

	// Use the Executor provided by the caller
	if err := execCtx.Run(cmd); err != nil {
		return "", fmt.Errorf("b3sum failed for %s: %w", path, err)
	}

	fields := strings.Fields(out.String())
	if len(fields) == 0 {
		return "", fmt.Errorf("b3sum produced no output for %s", path)
	}
	return fields[0], nil
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
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			stagingSet[fields[0]] = struct{}{}
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
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		relPath := fields[0]

		// if present in staging manifest -> skip
		if _, ok := stagingSet[relPath]; ok {
			continue
		}

		installedPath := filepath.Join(rootDir, relPath)

		// if installed file exists on disk, schedule for deletion
		if fi, err := os.Stat(installedPath); err == nil && !fi.IsDir() {
			filesToDelete = append(filesToDelete, installedPath)
		}
		// if file does not exist or is a directory, skip it
	}
	if err := iscanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading installed manifest: %v", err)
	}

	return filesToDelete, nil
}

// rsyncStaging syncs the contents of stagingDir into rootDir.
// Helper to sync staging dir into rootDir, respecting existing symlinks
func rsyncStaging(stagingDir, rootDir string, execCtx *Executor) error {
	// Ensure trailing slash on stagingDir so rsync copies contents
	stagingPath := filepath.Clean(stagingDir) + string(os.PathSeparator)

	// Ensure rootDir exists
	mkdirCmd := exec.Command("mkdir", "-p", rootDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create rootDir %s: %v", rootDir, err)
	}

	// rsync args:
	// -aHAX         : archive mode (permissions, symlinks, hardlinks, xattrs)
	// --numeric-ids : preserve numeric ownership
	// --no-implied-dirs : only create directories that exist in staging
	// --keep-dirlinks : treat symlinked directory on receiver as directory (don't replace the symlink)
	args := []string{
		"-aHAX",
		"--numeric-ids",
		"--no-implied-dirs",
		"--keep-dirlinks",
		stagingPath,
		rootDir,
	}

	cmd := exec.Command("rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := execCtx.Run(cmd); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}
	// Clean up staging directory
	rmCmd := exec.Command("rm", "-rf", stagingDir)
	if err := execCtx.Run(rmCmd); err != nil {
		return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
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
			fmt.Printf("warning: chroot to %s failed or post-install could not run: %v\n", rootDir, err)
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

	fmt.Println("Unique repositories to update:")
	for dir := range uniqueRepoDirs {
		fmt.Printf("- %s\n", dir)

		// 3. Execute 'git pull' in each unique directory
		// We use dir as the working directory for 'git pull'
		cmd := exec.Command("git", "pull")
		cmd.Dir = dir // Set the working directory for the command

		// Capture output for logging and error checking
		output, err := cmd.CombinedOutput()

		if err != nil {
			fmt.Printf("Error pulling repo %s: %v\nOutput:\n%s\n", dir, err, strings.TrimSpace(string(output)))
		} else {
			fmt.Printf("Successfully pulled repo %s\nOutput:\n%s\n", dir, strings.TrimSpace(string(output)))
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

	args := append([]string{"build"}, packages...)

	fmt.Printf("\n--> Executing pkgBuild for: %s\n", strings.Join(packages, ", "))

	cmd := exec.Command("hokuto", args...)

	// Inherit Stdin, Stdout, Stderr for interactive build process
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pkgBuild failed: %w", err)
	}

	fmt.Println("pkgBuild completed successfully.")
	return nil
}

// checkForUpgrades is the main function for the upgrade logic.
func checkForUpgrades() error {
	fmt.Println("--- Checking for Package Upgrades ---")

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
			fmt.Printf("Warning: Could not get repo version for %s: %v\n", name, err)
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
		fmt.Println("All installed packages are up to date.")
		return nil
	}

	fmt.Printf("\n--- %d Package(s) to Upgrade ---\n", len(upgradeList))
	var pkgNames []string
	for _, pkg := range upgradeList {
		// Print full version/revision information for clarity
		fmt.Printf("  - %s: %s %s -> %s %s\n",
			pkg.Name,
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
		pkgNames = append(pkgNames, pkg.Name)
	}

	// 4. Prompt user for upgrade
	if askForConfirmation("Do you want to upgrade these packages?") {
		// 5. Execute pkgBuild
		return pkgBuildAll(pkgNames)
	} else {
		fmt.Println("Upgrade canceled by user.")
	}

	return nil
}

// resolveMissingDeps recursively finds all missing dependencies for a package.
// It assumes cfg is passed in, as it's needed for the recursive call.
func resolveMissingDeps(pkgName string, processed map[string]bool, missing *[]string) error {

	// 1. Mark this package as processed to prevent infinite recursion
	if processed[pkgName] {
		return nil
	}
	processed[pkgName] = true

	// 2. Check if the package is already installed
	if isPackageInstalled(pkgName) {
		return nil
	}

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
	for _, depName := range dependencies {
		// Safety check: a package cannot depend on itself.
		if depName == pkgName {
			continue
		}

		// Ensure cfg is passed for the recursive call!
		if err := resolveMissingDeps(depName, processed, missing); err != nil {
			// Propagate the error up
			return err
		}
	}

	// --- 6. Add the missing package to the list ---
	// Add the package to the list *after* its dependencies have been processed.
	*missing = append(*missing, pkgName)

	return nil
}

// isPackageInstalled checks if a package is currently installed.
// This is the function called by the dependency resolver (resolveMissingDeps).
func isPackageInstalled(pkgName string) bool {
	// Simply defer to the silent checker.
	return checkPackageExists(pkgName)
}

// parseDependsFile reads the package's depends file and returns a list of package names.
func parseDependsFile(pkgDir string) ([]string, error) {
	dependsPath := filepath.Join(pkgDir, "depends")
	content, err := os.ReadFile(dependsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // No depends file is fine
		}
		return nil, fmt.Errorf("failed to read depends file: %w", err)
	}

	var dependencies []string
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split the line, e.g., "alsa-lib" or "python make"
		parts := strings.Fields(line)

		// The first part is always the dependency name.
		if len(parts) > 0 {
			dependencies = append(dependencies, parts[0])
		}
	}

	return dependencies, nil
}

// stripPackage recursively walks outputDir and runs the 'strip' command on every executable file found,
// executing the stripping concurrently to maximize speed.
func stripPackage(outputDir string, buildExec *Executor) error {
	fmt.Printf("Stripping executables in parallel in: %s\n", outputDir)

	var wg sync.WaitGroup
	var firstError error
	var errOnce sync.Once

	maxConcurrency := runtime.GOMAXPROCS(0) * 4
	if maxConcurrency < 8 {
		maxConcurrency = 8
	}
	concurrencyLimit := make(chan struct{}, maxConcurrency)

	isStripable := func(path string, info os.FileInfo) bool {
		// Must be a regular file (not a symlink) and have any execute bit set.
		if !info.Mode().IsRegular() {
			return false
		}
		if (info.Mode() & 0o111) == 0 {
			return false
		}

		// Quick magic check: read first 4 bytes and verify ELF magic.
		f, err := os.Open(path)
		if err != nil {
			return false
		}
		defer f.Close()

		var hdr [4]byte
		n, err := io.ReadFull(f, hdr[:])
		if err != nil || n != 4 {
			return false
		}

		// ELF magic: 0x7f 'E' 'L' 'F'
		if hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' {
			return true
		}

		// Not an ELF executable; skip.
		return false
	}

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if isStripable(path, info) {
			wg.Add(1)
			concurrencyLimit <- struct{}{}

			// capture local copy of path for goroutine
			p := path

			go func(p string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()

				fmt.Printf("  -> Stripping %s\n", p)

				cmd := exec.Command("strip", p)
				if err := buildExec.Run(cmd); err != nil {
					errOnce.Do(func() {
						firstError = fmt.Errorf("failed to strip %s: %w", p, err)
					})
					fmt.Fprintf(os.Stderr, "Warning: failed to strip %s: %v. Continuing.\n", p, err)
				}
			}(p)
		}

		return nil
	}

	if err := filepath.Walk(outputDir, walkFn); err != nil {
		return fmt.Errorf("error walking output directory: %w", err)
	}

	wg.Wait()

	if firstError != nil {
		return fmt.Errorf("build failed during stripping phase for %s: %w", outputDir, firstError)
	}

	return nil
}

// list of essential directories that should never be removed by rmdir.
// These are absolute paths expected to be found under the HOKUTO_ROOT.
// We use a map for O(1) lookup.
var forbiddenSystemDirs = map[string]struct{}{
	"/bin":   {},
	"/dev":   {},
	"/home":  {},
	"/lib":   {},
	"/lib32": {},
	"/lib64": {},
	"/mnt":   {},
	"/opt":   {},
	"/proc":  {},
	"/root":  {},
	"/sbin":  {},
	"/sys":   {},
	"/usr":   {},
	"/var":   {},
	"/etc":   {},
	"/tmp":   {},
	"/boot":  {},
	"/run":   {},
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
	// Custom/provided paths
	"/repo": {}, // If 'repo' is a top-level system directory
}

type fileMetadata struct {
	AbsPath string
	B3Sum   string
}

// userprompt for install after build
func getUserConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "" {
			return true
		}
		if input == "n" {
			return false
		}
		fmt.Println("Invalid input. Please enter 'y' or 'n'.")
	}
}

func askForConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s [y/N]: ", prompt)
		response, err := reader.ReadString('\n')
		if err != nil {
			return false
		}

		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" {
			return true
		}
		if response == "n" || response == "no" || response == "" {
			return false
		}
		fmt.Println("Invalid input. Please type 'y' (yes) or 'n' (no).")
	}
}

// build package
func pkgBuild(pkgName string, cfg *Config, execCtx *Executor) error {
	// set tmpdir
	pkgTmpDir := filepath.Join(tmpDir, pkgName)
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")

	// Create build/output dirs (non-root, inside TMPDIR)
	for _, dir := range []string{buildDir, outputDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

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
	// 1. Determine the Execution Context for THIS PACKAGE.
	// This check MUST stay here as it is package-specific.
	asRootFile := filepath.Join(pkgDir, "asroot")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}
	// 2. CLONE AND SELECT EXECUTOR
	// Create a new Executor instance for the build phase.
	buildExec := &Executor{
		Context:         execCtx.Context, // Inherit the main cancellation context
		ShouldRunAsRoot: needsRootBuild,  // Set the privilege based on 'asroot' file
	}
	// Download sources if required
	if err := hokutoChecksum(pkgName); err != nil {
		return fmt.Errorf("failed to fetch sources: %v", err)
	}
	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	noStripFile := filepath.Join(pkgDir, "nostrip")
	if _, err := os.Stat(noStripFile); err == nil {
		fmt.Printf("Local 'nostrip' file found in %s. Disabling stripping.\n", pkgDir)
		shouldStrip = false // Override the global setting for this package only
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

	// Build environment
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
		"HOKUTO_ROOT": cfg.Values["HOKUTO_ROOT"],
		"TMPDIR":      tmpDir,
	}

	for k, def := range defaults {
		val := cfg.Values[k]
		if val == "" {
			val = def
		}
		if k == "CXXFLAGS" && val == "" {
			val = cfg.Values["CFLAGS"]
			if val == "" {
				val = defaults["CFLAGS"]
			}
		}
		env = append(env, fmt.Sprintf("%s=%s", k, val))
	}

	// Run build script
	fmt.Printf("Building %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	cmd := exec.Command(buildScript, outputDir, version)
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	// 3. CENTRALIZED EXECUTION: Use the selected Executor regardless of privilege.
	// This replaces the entire conditional if/else block.
	if err := buildExec.Run(cmd); err != nil {
		return fmt.Errorf("build failed: %v", err)
	}

	// Create /var/db/hokuto/installed/<pkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	fmt.Printf("Creating metadata directory: %s\n", installedDir)
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := buildExec.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installed dir: %v", err)
	}

	// Generate libdeps
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if err := generateLibDeps(outputDir, libdepsFile, buildExec); err != nil {
		fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
	} else {
		fmt.Printf("Library dependencies written to %s\n", libdepsFile)
	}

	// Generate depends
	if err := generateDepends(pkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate depends: %v", err)
	}
	fmt.Printf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	fmt.Printf("%s built successfully, output in %s\n", pkgName, outputDir)

	// Strip the package
	if shouldStrip {
		// NOTE: stripPackage uses buildExec (UserExec) to run the external 'strip' command
		if err := stripPackage(outputDir, buildExec); err != nil {
			// Treat strip failure as a build failure (or a warning, depending on policy)
			return fmt.Errorf("build failed during stripping phase for %s: %w", pkgName, err)
		}
	} else {
		fmt.Printf("Skipping binary stripping for %s (NoStrip is true).\n", pkgName)
	}

	// Copy version file from pkgDir
	versionSrc := filepath.Join(pkgDir, "version")
	versionDst := filepath.Join(installedDir, "version")
	cpCmd := exec.Command("cp", "--remove-destination", versionSrc, versionDst)
	if err := buildExec.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy version file: %v", err)
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

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	// Generate package archive
	if err := createPackageTarball(pkgName, version, outputDir, buildExec); err != nil {
		return fmt.Errorf("failed to package tarball: %v", err)
	}

	// Cleanup tmpdirs
	if os.Getenv("HOKUTO_DEBUG") == "1" {
		fmt.Fprintf(os.Stderr, "INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", pkgTmpDir)
	} else {
		rmCmd := exec.Command("rm", "-rf", pkgTmpDir)
		if err := buildExec.Run(rmCmd); err != nil {
			fmt.Fprintf(os.Stderr, "failed to cleanup build tmpdirs: %v\n", err)
		}
	}

	return nil
}

// pkgBuildRebuild is used after an uninstall/upgrade to rebuild dependent packages.
// It skips tarball creation, cleanup, and runs with an adjusted environment.
// oldLibsDir is the path to the temporary directory containing backed-up libraries.
func pkgBuildRebuild(pkgName string, cfg *Config, execCtx *Executor, oldLibsDir string) error {

	// --- Setup (Same as pkgBuild) ---
	pkgTmpDir := filepath.Join(tmpDir, pkgName)
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")

	// Clean and re-create build/output dirs
	if err := os.RemoveAll(pkgTmpDir); err != nil {
		return fmt.Errorf("failed to clean pkg tmp dir %s: %v", pkgTmpDir, err)
	}
	for _, dir := range []string{buildDir, outputDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

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

	// 1. Determine the Execution Context
	asRootFile := filepath.Join(pkgDir, "asroot")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}
	buildExec := &Executor{
		Context:         execCtx.Context,
		ShouldRunAsRoot: needsRootBuild,
	}

	// Download sources if required
	if err := hokutoChecksum(pkgName); err != nil {
		return fmt.Errorf("failed to fetch sources: %v", err)
	}
	// Prepare sources
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Check if strip should be disabled
	shouldStrip := cfg.DefaultStrip
	noStripFile := filepath.Join(pkgDir, "nostrip")
	if _, err := os.Stat(noStripFile); err == nil {
		fmt.Printf("Local 'nostrip' file found in %s. Disabling stripping.\n", pkgDir)
		shouldStrip = false // Override the global setting for this package only
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
		"TMPDIR":      tmpDir,
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

	for k, def := range defaults {
		val := cfg.Values[k]
		if val == "" {
			val = def
		}
		if k == "CXXFLAGS" && val == "" {
			val = cfg.Values["CFLAGS"]
			if val == "" {
				val = defaults["CFLAGS"]
			}
		}
		// Only append non-overridden environment variables
		if k != "PATH" && k != "LD_LIBRARY_PATH" {
			env = append(env, fmt.Sprintf("%s=%s", k, val))
		}
	}

	// Run build script
	fmt.Printf("Rebuilding %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, buildExec)

	cmd := exec.Command(buildScript, outputDir, version)
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if err := buildExec.Run(cmd); err != nil {
		return fmt.Errorf("rebuild failed: %v", err)
	}

	// Create /var/db/hokuto/installed/<pkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	fmt.Printf("Creating metadata directory: %s\n", installedDir)
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := buildExec.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installed dir: %v", err)
	}

	// Generate libdeps
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if err := generateLibDeps(outputDir, libdepsFile, buildExec); err != nil {
		fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
	} else {
		fmt.Printf("Library dependencies written to %s\n", libdepsFile)
	}

	// Generate depends
	if err := generateDepends(pkgName, pkgDir, outputDir, rootDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate depends: %v", err)
	}
	fmt.Printf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	fmt.Printf("%s built successfully, output in %s\n", pkgName, outputDir)

	// Strip the package
	if shouldStrip {
		// NOTE: stripPackage uses buildExec (UserExec) to run the external 'strip' command
		if err := stripPackage(outputDir, buildExec); err != nil {
			// Treat strip failure as a build failure (or a warning, depending on policy)
			return fmt.Errorf("build failed during stripping phase for %s: %w", pkgName, err)
		}
	} else {
		fmt.Printf("Skipping binary stripping for %s (NoStrip is true).\n", pkgName)
	}

	// Copy version file from pkgDir
	versionSrc := filepath.Join(pkgDir, "version")
	versionDst := filepath.Join(installedDir, "version")
	cpCmd := exec.Command("cp", "--remove-destination", versionSrc, versionDst)
	if err := buildExec.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to copy version file: %v", err)
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

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, buildExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	fmt.Printf("%s rebuilt successfully, output in %s\n", pkgName, outputDir)

	// Key difference: Skip tarball creation and cleanup to allow pkgInstall to sync and clean up.
	return nil
}

func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor) error {

	stagingDir := filepath.Join(tmpDir, "staging", pkgName)

	// Declare and initialize the 'failed' slice for tracking non-fatal errors
	var failed []string

	// Clean staging dir
	os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("failed to create staging dir: %v", err)
	}

	// 1. Unpack tarball into staging
	fmt.Printf("Unpacking %s into %s\n", tarballPath, stagingDir)
	untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
	if err := execCtx.Run(untarCmd); err != nil {
		return fmt.Errorf("failed to unpack tarball: %v", err)
	}

	// 2. Detect user-modified files
	modifiedFiles, err := getModifiedFiles(pkgName, rootDir, execCtx)
	if err != nil {
		return err
	}

	// 3. Interactive handling of modified files
	for _, file := range modifiedFiles {
		stagingFile := filepath.Join(stagingDir, file)
		currentFile := filepath.Join(rootDir, file) // file under the install root

		if _, err := os.Stat(stagingFile); err == nil {
			// file exists in staging
			cmd := exec.Command("diff", "-u", currentFile, stagingFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()

			fmt.Printf("File %s modified, choose action: [k]eep current, [u]se new, [e]dit: ", file)
			var input string
			fmt.Scanln(&input)
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
			fmt.Printf("User modified %s, but new package has no file. Keep it? [y/N]: ", file)
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
				fmt.Printf("Kept modified file by copying %s into staging\n", file)
			} else {
				// user chose not to keep it -> remove the installed file (run as root)
				rmCmd := exec.Command("rm", "-f", currentFile)
				if err := execCtx.Run(rmCmd); err != nil {
					// warn but continue install; do not abort the whole install for a removal failure
					fmt.Printf("warning: failed to remove %s: %v\n", currentFile, err)
				} else {
					fmt.Printf("Removed user-modified file: %s\n", file)
				}
			}
		}
	}
	// Generate updated manifest of staging
	stagingManifest := stagingDir + "/var/db/hokuto/installed/" + pkgName + "/manifest"
	stagingManifest2dir := "/tmp/staging-manifest-" + pkgName
	stagingManifest2file := filepath.Join(stagingManifest2dir, "/manifest")
	if err := generateManifest(stagingDir, stagingManifest2dir, execCtx); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}
	if err := updateManifestWithNewFiles(stagingManifest, stagingManifest2file); err != nil {
		fmt.Fprintf(os.Stderr, "Manifest update failed: %v\n", err)
	}
	// Delete stagingManifest2dir
	rmCmd := exec.Command("rm", "-rf", stagingManifest2dir)
	if err := execCtx.Run(rmCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove StagingManifest: %v", err)
	}

	// 4. Determine obsolete files (compare manifests)
	filesToDelete, err := removeObsoleteFiles(pkgName, stagingDir, rootDir)
	if err != nil {
		return err
	}

	// --- NEW: Dependency Check and Backup (Before deletion) ---
	affectedPackages := make(map[string]struct{})
	libFilesToDelete := make(map[string]struct{})
	tempLibBackupDir, err := os.MkdirTemp(tmpDir, "hokuto-lib-backup-")
	if err != nil {
		return fmt.Errorf("failed to create temporary backup directory: %v", err)
	}
	// CLEANUP: Ensure the backup directory is removed on exit
	defer func() {
		if os.Getenv("HOKUTO_DEBUG") != "1" {
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
				// libdeps should contain paths relative to rootDir (e.g., /usr/lib/libfoo.so)
				absLibPath := libPath
				if rootDir != "/" && strings.HasPrefix(libPath, "/") {
					absLibPath = filepath.Join(rootDir, libPath[1:])
				} else if !strings.HasPrefix(libPath, "/") {
					// This is unexpected for libdeps, but handle defensively
					absLibPath = filepath.Join(rootDir, libPath)
				}

				// Check if this library is scheduled for deletion
				for _, fileToDelete := range filesToDelete {
					if fileToDelete == absLibPath {
						affectedPackages[otherPkgName] = struct{}{}
						libFilesToDelete[absLibPath] = struct{}{}
						// Break inner loop and check the next libdep
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
			fmt.Fprintf(os.Stderr, "warning: failed to determine relative path for backup %s: %v\n", libPath, err)
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
			fmt.Printf("Backed up affected library %s to %s\n", libPath, backupPath)
		}
	}

	// 5. Rsync staging into root
	if err := rsyncStaging(stagingDir, rootDir, execCtx); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd := exec.Command("rm", "-f", p)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Printf("warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			fmt.Printf("Removed obsolete file: %s\n", p)
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
		fmt.Printf("\nWARNING: The following packages depend on libraries that were removed/upgraded:\n  %s\n", strings.Join(affectedList, ", "))

		performRebuild := true // Default to true, and allow user input to override

		fmt.Printf("Do you want to rebuild these packages now? This is highly recommended. [Y/n]: ")

		var answer string
		// Read the line. Using '_' to discard the error and the count,
		// as we only care if 'answer' is "n".
		_, _ = fmt.Scanln(&answer) // Corrected line: 'err' replaced with '_'

		// Check if the trimmed input is 'n' (No). An empty input (user pressed Enter)
		// or an error (like EOF on Enter) will fall through to 'performRebuild = true'.
		if strings.ToLower(strings.TrimSpace(answer)) == "n" {
			fmt.Println("Skipping rebuild. System stability may be compromised.")
			performRebuild = false
		}
		// If err != nil (like when only Enter is pressed), or input is empty/ 'y',
		// performRebuild remains true.

		// 8b. Perform rebuild
		if performRebuild {
			fmt.Println("Starting rebuild of affected packages...")
			for _, pkg := range affectedList {
				fmt.Printf("\n--- Rebuilding %s ---\n", pkg)

				if err := pkgBuildRebuild(pkg, cfg, execCtx, tempLibBackupDir); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s failed: %v", pkg, err))
					fmt.Printf("WARNING: Rebuild of %s failed: %v\n", pkg, err)
				} else {
					rebuildOutputDir := filepath.Join(tmpDir, pkg, "output")

					if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
						failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", pkg, err))
						fmt.Printf("WARNING: Failed to sync rebuilt package %s to root: %v\n", pkg, err)
					}

					rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, pkg))
					if err := execCtx.Run(rmCmd); err != nil {
						fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", pkg, err)
					}
					fmt.Printf("Rebuild of %s finished and installed.\n", pkg)
				}
			}
		}
	}

	// 9. Cleanup original staging dir
	os.RemoveAll(stagingDir)

	// 10. Report failures if any
	if len(failed) > 0 { // 'failed' slice is correctly declared at the start of pkgInstall
		return fmt.Errorf("some file actions failed:\n%s", strings.Join(failed, "\n"))
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
		fields := strings.Fields(line)
		if len(fields) < 1 { // Need at least the path
			continue
		}
		pathInManifest := fields[0]

		// b3sum is the second field if it exists, otherwise empty.
		expectedSum := ""
		if len(fields) > 1 {
			expectedSum = fields[1]
		}

		// Calculate the absolute path on the filesystem, relative to HOKUTO_ROOT.
		absPath := pathInManifest
		if filepath.IsAbs(pathInManifest) {
			if hRoot != "/" {
				absPath = filepath.Join(hRoot, pathInManifest[1:])
			} else {
				absPath = pathInManifest
			}
		} else {
			absPath = filepath.Join(hRoot, pathInManifest)
		}

		// directory entries end with '/'
		if strings.HasSuffix(pathInManifest, "/") {
			dirs = append(dirs, absPath)
			continue
		}

		// Only count actual files for the confirmation prompt (Step 5)
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
		// Use fileCount for the prompt
		fmt.Printf("About to remove package %s and %d file(s). Continue? [y/N]: ", pkgName, fileCount)
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
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

	// 7. Remove files (with b3sum check)
	var failed []string
	for _, meta := range files {
		p := meta.AbsPath // The full HOKUTO_ROOT prefixed path

		// Safety check: don't remove root
		clean := filepath.Clean(p)
		if clean == "/" || clean == hRoot {
			failed = append(failed, fmt.Sprintf("%s: refused to remove root", p))
			continue
		}

		// Check b3sum unless the file is internal metadata
		if !strings.HasPrefix(p, internalFilePrefix) && meta.B3Sum != "" {
			currentSum, err := b3sum(p, execCtx)
			if err != nil {
				// Treat inability to check as a failure to remove for safety
				failed = append(failed, fmt.Sprintf("%s: failed to compute b3sum: %v", p, err))
				continue
			}

			if currentSum != meta.B3Sum {
				fmt.Printf("\nWARNING: File %s has been modified (expected %s, found %s).\n", p, meta.B3Sum, currentSum)

				// Prompt user unless 'yes' is set
				if !yes {
					fmt.Printf("File content mismatch. Remove anyway? [y/N]: ")
					var answer string
					fmt.Scanln(&answer)
					if strings.ToLower(strings.TrimSpace(answer)) != "y" {
						failed = append(failed, fmt.Sprintf("%s: content mismatch, removal skipped by user", p))
						continue // Skip removal
					}
				}
			}
		}

		// Removal command
		rmCmd := exec.Command("rm", "-f", clean)
		if err := execCtx.Run(rmCmd); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		fmt.Printf("Removed %s\n", p)
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

		if _, found := forbiddenSystemDirs[relToHRoot]; found {
			fmt.Printf("Skipping removal of protected system directory: %s\n", clean)
			continue
		}

		rmdirCmd := exec.Command("rmdir", clean)
		if err := execCtx.Run(rmdirCmd); err == nil {
			fmt.Printf("Removed empty directory %s\n", clean)
		}
	}

	// 9. Remove package metadata directory (unchanged)
	rmMetaCmd := exec.Command("rm", "-rf", installedDir)
	if err := execCtx.Run(rmMetaCmd); err != nil {
		failed = append(failed, fmt.Sprintf("failed to remove metadata %s: %v", installedDir, err))
	} else {
		fmt.Printf("Removed package metadata: %s\n", installedDir)
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
					fmt.Printf("\n[WARNING] Critical operation in progress (e.g., install). Press Ctrl+C AGAIN to force exit NOW.\n")

					// Wait for a second signal or a short delay
					select {
					case <-sigs:
						fmt.Println("\n[FATAL] Forced immediate exit.")
						os.Exit(130) // Common exit code for SIGINT
					case <-time.After(5 * time.Second):
						// If no second signal, continue waiting for the loop to repeat
						continue
					case <-ctx.Done():
						return // Context cancelled from outside
					}
				} else {
					// --- NON-CRITICAL PHASE: Graceful Cancellation ---
					// This block runs ONLY when isCriticalAtomic.Load() != 1

					fmt.Printf("\n[INFO] Received %v. Cancelling process gracefully...\n", sig)
					cancel() // Cancel the context

					// NEW: Give the command a moment to die and flush its buffers
					// before proceeding to check for a second signal or exiting.
					time.Sleep(100 * time.Millisecond) // Wait 100ms

					// Wait for a second signal for immediate exit
					select {
					case <-sigs:
						fmt.Println("\n[FATAL] Second interrupt received. Forcing immediate exit.")
						os.Exit(130)
					case <-ctx.Done():
						return
					case <-time.After(500 * time.Millisecond):
						// Give the program a moment to shut down before exiting the goroutine
						return
					}
				} // <-- Correctly closed 'else' block

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
		fmt.Println("Usage: hokuto <command> [args...]")
		return
	}

	cfg, err := loadConfig(ConfigFile)
	if err != nil {
		// handle error
	}
	mergeEnvOverrides(cfg)
	initConfig(cfg)

	// This ensures both executors have the valid cancellation context (ctx).
	UserExec = &Executor{
		Context:         ctx,
		ShouldRunAsRoot: false,
	}
	RootExec = &Executor{
		Context:         ctx,
		ShouldRunAsRoot: true,
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("hokuto 0.1")
	case "list":
		pkg := ""
		if len(os.Args) >= 3 {
			pkg = os.Args[2]
		}
		if err := listPackages(pkg); err != nil {
			fmt.Println("Error:", err)
		}
	case "checksum":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto checksum <pkgname>")
			return
		}
		pkg := os.Args[2]
		if err := hokutoChecksum(pkg); err != nil {
			fmt.Println("Error:", err)
		}

	case "build":
		// 1. Initialize a FlagSet for the "build" subcommand
		buildCmd := flag.NewFlagSet("build", flag.ExitOnError)
		var autoInstall = buildCmd.Bool("a", false, "Automatically install the package(s) after successful build without prompting.")

		// Parse the arguments specific to the "build" subcommand,
		// starting from os.Args[2] (i.e., skipping "hokuto" and "build")
		if err := buildCmd.Parse(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing build flags: %v\n", err)
			os.Exit(1)
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
		for _, pkgName := range packagesToProcess {
			fmt.Printf("Resolving dependencies for target package %s...\n", pkgName)

			// NOTE: resolveMissingDeps must be able to handle being called multiple times
			// and update masterProcessed and masterMissingDeps correctly, acting like a global resolver.
			if err := resolveMissingDeps(pkgName, masterProcessed, &masterMissingDeps); err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving dependencies for %s: %v\n", pkgName, err)
				os.Exit(1)
			}
		}

		// masterMissingDeps now contains the union of all missing packages (dependencies + targets) in reverse build order.
		packagesToBuild := masterMissingDeps
		var finalPackagesToBuild []string

		// 3. BINARY CHECK AND USER PROMPT LOGIC (for all collected packages)
		for _, depPkg := range packagesToBuild {
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
					if !getUserConfirmation(fmt.Sprintf("Do you want to use the available binary package for dependency %s? (Y/n) ", depPkg)) {
						fmt.Printf("User chose to build %s.\n", depPkg)
						finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
					} else {
						fmt.Printf("Using available binary for %s. Installing...\n", depPkg)
						// Immediate install of dependency binary
						isCriticalAtomic.Store(1)
						if err := pkgInstall(tarballPath, depPkg, cfg, RootExec); err != nil {
							isCriticalAtomic.Store(0)
							fmt.Fprintf(os.Stderr, "Fatal error installing binary %s: %v\n", depPkg, err)
							os.Exit(1)
						}
						isCriticalAtomic.Store(0)
						fmt.Printf("Dependency %s installed successfully from binary.\n", depPkg)
						// This package is installed and won't be built, so skip adding to finalPackagesToBuild
					}
				} else {
					// No binary found, must build
					finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
				}
			} else {
				// User-requested target package, always proceed to build
				finalPackagesToBuild = append(finalPackagesToBuild, depPkg)
			}
		}

		// Update the final list of packages to actually build
		packagesToBuild = finalPackagesToBuild

		// --- FINAL LIST CHECK AND SORTING ---

		// Check for the rebuild-only case for packages that were originally requested
		if len(packagesToBuild) == 0 {
			if len(masterMissingDeps) == 0 {
				// If masterMissingDeps was initially empty, the user wants a rebuild of all targets
				fmt.Printf("All packages and dependencies are already installed. Rebuilding target package(s).\n")
				packagesToBuild = packagesToProcess // Set to the original requested list
			} else {
				// All required packages were installed from available binaries. Nothing left to do.
				fmt.Printf("All required packages are installed (many from available binaries). No build needed.\n")
				os.Exit(0)
			}
		}

		fmt.Printf("The following packages will be built in order: %s\n", strings.Join(packagesToBuild, ", "))

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

			fmt.Printf("--- Starting Build: %s (%s) ---\n", buildPkg, version)
			if err := pkgBuild(buildPkg, cfg, UserExec); err != nil {
				fmt.Fprintf(os.Stderr, "Fatal error building %s: %v\n", buildPkg, err)
				os.Exit(1)
			}

			// --- STEP 3C: Install (Dependencies are installed immediately) ---
			if !targetPackages[buildPkg] { // If it's *not* a target package (i.e., it's a dependency)
				// Install dependencies immediately
				isCriticalAtomic.Store(1)
				if err := pkgInstall(tarballPath, buildPkg, cfg, RootExec); err != nil {
					isCriticalAtomic.Store(0)
					fmt.Fprintf(os.Stderr, "Fatal error installing dependency %s: %v\n", buildPkg, err)
					os.Exit(1)
				}
				isCriticalAtomic.Store(0)
				fmt.Printf("Dependency %s installed successfully.\n", buildPkg)
			} else {
				// If it's a target package, defer install and save its name
				builtTargetPackages = append(builtTargetPackages, buildPkg)
				fmt.Printf("Target package %s built successfully. Installation deferred.\n", buildPkg)
			}
		}

		// --- FINAL INSTALL PROMPT ---
		if len(builtTargetPackages) > 0 {
			// Note: The prompt/auto-install applies to ALL built target packages
			shouldInstall := *autoInstall
			if !shouldInstall {
				// Prompt user once for all built target packages
				targetsList := strings.Join(builtTargetPackages, ", ")
				shouldInstall = getUserConfirmation(fmt.Sprintf("Build finished. Do you want to install the following package(s): %s? (Y/n) ", targetsList))
			}

			if shouldInstall {
				// Loop and install all successfully built target packages
				for _, finalPkg := range builtTargetPackages {
					version, _ := getRepoVersion(finalPkg) // Re-get version (should not fail)
					tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", finalPkg, version))

					fmt.Printf("Starting installation of target package %s...\n", finalPkg)
					isCriticalAtomic.Store(1)
					if err := pkgInstall(tarballPath, finalPkg, cfg, RootExec); err != nil {
						isCriticalAtomic.Store(0)
						fmt.Fprintf(os.Stderr, "Fatal error installing final package %s: %v\n", finalPkg, err)
						os.Exit(1)
					}
					isCriticalAtomic.Store(0)
					fmt.Printf("Package %s installed successfully.\n", finalPkg)
				}
			} else {
				fmt.Printf("Installation of target packages skipped by user. Built packages remain in %s.\n", BinDir)
			}
		}

		// Clean up or exit after a successful run
		os.Exit(0)

	case "install":
		// Get all arguments after "hokuto" and "install"
		args := os.Args[2:]
		if len(args) == 0 {
			fmt.Println("Usage: hokuto install <tarball|pkgname> [tarball|pkgname...]")
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

			fmt.Printf("Processing argument: %s\n", arg)

			if strings.HasSuffix(arg, ".tar.zst") {
				// Direct tarball path
				tarballPath = arg
				base := filepath.Base(tarballPath)

				// Determine package name from tarball filename (e.g., pkgname-version.tar.zst)
				parts := strings.SplitN(base, "-", 2)
				if len(parts) < 1 {
					fmt.Fprintf(os.Stderr, "Error: Could not determine package name from tarball file name: %s\n", arg)
					allSucceeded = false
					continue
				}
				pkgName = parts[0]

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
					fmt.Fprintf(os.Stderr, "Error: Built package tarball not found for %s at %s. You must 'hokuto build' it first.\n", pkgName, tarballPath)
					allSucceeded = false
					continue
				}
			}

			// --- Installation Execution ---
			fmt.Printf("Starting installation of %s from %s...\n", pkgName, tarballPath)

			if err := pkgInstall(tarballPath, pkgName, cfg, RootExec); err != nil {
				fmt.Fprintf(os.Stderr, "Error installing package %s: %v\n", pkgName, err)
				allSucceeded = false
				// Continue to the next package
				continue
			}

			fmt.Printf("Package %s installed successfully.\n", pkgName)
		}

		if !allSucceeded {
			// Exit with an error code if any package failed to install
			os.Exit(1)
		}

	case "uninstall":
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
			fmt.Printf("Attempting to uninstall package: %s\n", pkgName)

			// The pkgUninstall function must be updated to accept the final flag values
			if err := pkgUninstall(pkgName, cfg, RootExec, effectiveForce, effectiveYes); err != nil {
				fmt.Fprintf(os.Stderr, "Error uninstalling %s: %v\n", pkgName, err)
				allSucceeded = false
				// Continue to the next package instead of os.Exit(1) immediately
				// This allows for partial success if one package fails but others succeed.
			} else {
				fmt.Printf("Package %s removed\n", pkgName)
			}
		}

		if !allSucceeded {
			// Exit with an error code if any package failed to uninstall
			os.Exit(1)
		}
		// If all packages were successfully uninstalled, exit cleanly

	case "update":
		updateRepos()
		if err := checkForUpgrades(); err != nil {
			fmt.Fprintf(os.Stderr, "Upgrade process failed: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Println("Unknown command:", os.Args[1])
	}
}
