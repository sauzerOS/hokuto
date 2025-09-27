package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
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
	ConfigFile = "/etc/hokuto.conf"
	// Global executors (declared, to be assigned in main)
	UserExec *Executor
	RootExec *Executor
)

// Config struct
type Config struct {
	Values map[string]string
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

// ensureSudo prompts once and primes the sudo timestamp cache.
func (e *Executor) ensureSudo() error {
	// if we’re already root or we never need sudo, nothing to do
	if os.Geteuid() == 0 || !e.ShouldRunAsRoot {
		return nil
	}
	// if we’ve already primed, just refresh timestamp
	if e.sudoPrimed {
		cmd := exec.CommandContext(e.Context, "sudo", "-v")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// force a re-prompt next time
			e.sudoPrimed = false
			return fmt.Errorf("sudo timestamp refresh failed: %w", err)
		}
		return nil
	}

	// first-time ask on /dev/tty
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

	// prime the timestamp cache with -S (read from our pipe) and -v
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

// Run executes cmd, elevating with sudo -E if needed.
// Password is only asked/cached in ensureSudo(), never during the main exec.
func (e *Executor) Run(cmd *exec.Cmd) error {
	// Phase 0: wire up stdio
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	// Phase 1: prompt/refresh sudo timestamp
	if err := e.ensureSudo(); err != nil {
		return err
	}

	// Phase 2: build the actual invocation
	var finalCmd *exec.Cmd
	if e.ShouldRunAsRoot && os.Geteuid() != 0 {
		// use -E only—no -S, so sudo reads its own tty
		args := append([]string{"-E", cmd.Path}, cmd.Args[1:]...)
		finalCmd = exec.CommandContext(e.Context, "sudo", args...)
	} else {
		finalCmd = exec.CommandContext(e.Context, cmd.Path, cmd.Args[1:]...)
	}

	// inherit or copy environment
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

	// Phase 3: isolate process-group so we can clean up on cancel
	finalCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Phase 4: start, cancel watcher, wait
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
func hokutoChecksum(pkgName string, cfg *Config) error {

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

// reverseStringSlice reverses the order of a string slice in place.
// helper for correct build order
func reverseStringSlice(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
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

	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, buildExec); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
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

func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor) error {

	stagingDir := filepath.Join(tmpDir, "staging", pkgName)

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

	// 5. Rsync staging into root
	if err := rsyncStaging(stagingDir, rootDir, execCtx); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd = exec.Command("rm", "-f", p)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Printf("warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			fmt.Printf("Removed obsolete file: %s\n", p)
		}
	}
	// 7. Run package post-install script (non-fatal on chroot failure)
	if err := executePostInstall(pkgName, rootDir, execCtx); err != nil {
		// executePostInstall will already treat chroot failures as non-fatal,
		// but handle any unexpected errors here.
		fmt.Printf("warning: post-install for %s returned error: %v\n", pkgName, err)
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
		if err := hokutoChecksum(pkg, cfg); err != nil {
			fmt.Println("Error:", err)
		}
	case "build":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto build <package>")
			os.Exit(1)
		}
		pkgName := os.Args[2]

		// Set to non-critical (0 is default, but good to be explicit)
		isCriticalAtomic.Store(0)

		// --- NEW DEPENDENCY CHECK LOGIC ---

		// Initialize tracking maps and list
		processed := make(map[string]bool)
		var missingDeps []string

		// Resolve all missing dependencies, including the target package itself
		// if it's not installed (though the build logic handles that later).
		fmt.Printf("Resolving dependencies for package %s...\n", pkgName)
		if err := resolveMissingDeps(pkgName, processed, &missingDeps); err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving dependencies: %v\n", err)
			os.Exit(1)
		}

		// The list is currently in **reverse build order** (e.g., mpv, libass, ffmpeg).
		// We reverse it to get the correct build order (ffmpeg, libass, mpv).
		// This is a simple form of topological sort.

		packagesToBuild := missingDeps

		// If packagesToBuild is empty, the target package and all its deps are installed.
		if len(packagesToBuild) == 0 {
			// Build the target package only (user requested a rebuild).
			// ... (rest of the logic for rebuild) ...
			fmt.Printf("Package %s and all its dependencies are already installed. Rebuilding target package.\n", pkgName)
			packagesToBuild = []string{pkgName}
		} else {
			// Build the missing dependencies plus the target package.
			fmt.Printf("The following packages need to be built: %s\n", strings.Join(packagesToBuild, ", "))
		}

		// --- EXECUTION OF BUILD LOOP ---
		// Loop through the final list:
		for _, buildPkg := range packagesToBuild {

			// --- STEP 3A: Get Version ---
			// Use the existing global getRepoVersion function.
			version, err := getRepoVersion(buildPkg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fatal error: could not determine version for %s: %v\n", buildPkg, err)
				os.Exit(1)
			}

			// Determine the final tarball path (using the global BinDir)
			tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", buildPkg, version))

			// --- STEP 3B: Build ---
			fmt.Printf("--- Starting Build: %s (%s) ---\n", buildPkg, version)
			// NOTE: pkgBuild uses UserExec because the build process should run under the user's privilege.
			if err := pkgBuild(buildPkg, cfg, UserExec); err != nil {
				fmt.Fprintf(os.Stderr, "Fatal error building %s: %v\n", buildPkg, err)
				os.Exit(1)
			}

			// --- STEP 3C: Install ---
			// If the build was successful, install the result immediately using the RootExecutor.

			// 1. Set to CRITICAL (1) before install (as done in the "install" case)
			isCriticalAtomic.Store(1)

			// 2. Call pkgInstall with the required tarballPath, pkgName, cfg, and RootExec
			if err := pkgInstall(tarballPath, buildPkg, cfg, RootExec); err != nil {
				// 3. Reset CRITICAL state on failure
				isCriticalAtomic.Store(0)
				fmt.Fprintf(os.Stderr, "Fatal error installing %s: %v\n", buildPkg, err)
				os.Exit(1)
			}

			// 4. Reset CRITICAL state on success
			isCriticalAtomic.Store(0)

			fmt.Printf("Package %s installed successfully.\n", buildPkg)
		}

	case "install":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto install <tarball|pkgname>")
			os.Exit(1)
		}

		arg := os.Args[2]
		var tarballPath, pkgName string

		if strings.HasSuffix(arg, ".tar.zst") {
			// Direct tarball path
			tarballPath = arg
			base := filepath.Base(tarballPath)
			pkgName = strings.SplitN(base, "-", 2)[0]
		} else {
			// Package name
			pkgName = arg
			version, err := getRepoVersion(pkgName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			tarballPath = filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, version))
			if _, err := os.Stat(tarballPath); err != nil {
				fmt.Fprintf(os.Stderr, "Tarball not found: %s\n", tarballPath)
				os.Exit(1)
			}
		}

		// Set to CRITICAL (1)
		isCriticalAtomic.Store(1)
		// Ensure it is reset when the install function returns/panics
		defer isCriticalAtomic.Store(0)

		if err := pkgInstall(tarballPath, pkgName, cfg, RootExec); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing package %s: %v\n", pkgName, err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command:", os.Args[1])
	}
}
