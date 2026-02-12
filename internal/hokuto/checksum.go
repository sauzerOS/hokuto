package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"lukechampine.com/blake3"
)

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

// check if b3sum is installed on system
func hasB3sum() bool {
	_, err := exec.LookPath("b3sum")
	return err == nil
}

func resolveLockBaseForVerification(filePath string) string {
	target, err := os.Readlink(filePath)
	if err != nil {
		return filePath
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(filepath.Dir(filePath), target)
}

func withSharedDownloadLock(lockBase string, fn func() error) error {
	lockPath := lockBase + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
		return err
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}

// verifyOrCreateChecksums checks source file integrity, prompting the user for action on mismatch.

func verifyOrCreateChecksums(pkgName, pkgDir string, force bool, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	pkgSrcDir := filepath.Join(SourcesDir, pkgName)
	checksumFile := filepath.Join(pkgDir, "checksums")

	//Read version for consistent hashing
	versionData, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		return fmt.Errorf("could not read version file: %v", err)
	}
	pkgVersion := strings.Fields(string(versionData))[0]

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
				// Checksum is first, filename is the rest
				checksum := parts[0]
				filename := strings.Join(parts[1:], " ")
				existing[filename] = checksum
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
		// git+ sources are checked out, not checksummed as files here usually.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "git+") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 {
			src := parts[0]
			fname := filepath.Base(src)
			expectedFiles = append(expectedFiles, fname)
			urlMap[fname] = src
		}
	}

	// 1. COLLECT: Gather all existing files that need verification
	var filesToVerify []string
	if !force {
		for _, fname := range expectedFiles {
			if _, exists := existing[fname]; exists {
				src := urlMap[fname]
				var path string
				if strings.HasPrefix(src, "files/") {
					path = filepath.Join(pkgDir, src)
				} else {
					path = filepath.Join(pkgSrcDir, fname)
				}
				filesToVerify = append(filesToVerify, path)
			}
		}
	}

	computedSums := make(map[string]string)
	if len(filesToVerify) > 0 {
		var err error
		computedSums, err = ComputeChecksums(filesToVerify, UserExec)
		if err != nil {
			return fmt.Errorf("failed to verify existing files: %v", err)
		}
	}

	var summary []string
	var finalChecksums []string

	for _, fname := range expectedFiles {
		src := urlMap[fname]
		isLocal := strings.HasPrefix(src, "files/")
		var filePath string
		if isLocal {
			filePath = filepath.Join(pkgDir, src)
		} else {
			filePath = filepath.Join(pkgSrcDir, fname)
		}

		originalURL := src
		substitutedURL := applyGnuMirror(originalURL)

		currentSum, sumExists := existing[fname]
		computedSum, hasComputed := computedSums[filePath]
		isHashValid := hasComputed && computedSum == currentSum
		fileMissing := false
		if sumExists && !hasComputed {
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				fileMissing = true
			}
		}

		// 2. DECIDE & ACT: Determine what to do based on checksum validity.
		if isHashValid && !force {
			// Case A: Hash is valid and we are not forcing. Everything is OK.
			finalChecksums = append(finalChecksums, fmt.Sprintf("%s  %s", currentSum, fname))
			summary = append(summary, fmt.Sprintf("%s: ok", fname))
			continue
		}

		// If we are here, the hash is either invalid, missing, or we are forcing an update.
		// If we are here, the hash is either invalid, missing, or we are forcing an update.
		var actionSummary string

		if force {
			if isLocal {
				// Local files are not downloaded, just re-read.
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					return fmt.Errorf("local source file %s is missing", src)
				}
				actionSummary = "Updated (local)"
			} else {
				// Case B: Force mode is enabled. Always redownload.
				actionSummary = "Updated (forced)"
				WithPrompt(func() {
					performRedownload(fname, originalURL, substitutedURL, pkgVersion, pkgSrcDir, (logger != os.Stdout), logger)
				})
			}

		} else if sumExists && !isHashValid {
			// Case C: A checksum exists, but it MISMATCHES. Prompt the user for action.
			if fileMissing {
				if isLocal {
					return fmt.Errorf("local source file %s is missing", src)
				}
				actionSummary = "Updated (missing)"
				WithPrompt(func() {
					performRedownload(fname, originalURL, substitutedURL, pkgVersion, pkgSrcDir, (logger != os.Stdout), logger)
				})
			} else {
				WithPrompt(func() {
					// Try to use /dev/tty for direct user interaction
					var in io.Reader = os.Stdin
					var out io.Writer = os.Stdout

					tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
					if err == nil {
						defer tty.Close()
						in = tty
						out = tty
					}

					// Print a clean prompt line
					fmt.Fprint(out, colArrow.Sprint("-> "))
					if isLocal {
						fmt.Fprintf(out, "%s\n", colWarn.Sprintf("Checksum mismatch for local file %s. (K)eep current checksum, (u)pdate checksum? [K/u]: ", fname))
					} else {
						fmt.Fprintf(out, "%s\n", colWarn.Sprintf("Checksum mismatch for %s. (K)eep local file, (r)edownload file? [K/r]: ", fname))
					}

					// Explicitly sync if it's a file (like stdout/tty)
					if f, ok := out.(*os.File); ok {
						f.Sync()
					}

					var response string
					scanner := bufio.NewScanner(in)
					if scanner.Scan() {
						response = scanner.Text()
					}
					resp := strings.ToLower(strings.TrimSpace(response))
					if (isLocal && resp == "u") || (!isLocal && resp == "r") {
						if isLocal {
							actionSummary = "Updated (local)"
						} else {
							actionSummary = "Redownloaded"
							// PERFORM REDOWNLOAD INSIDE PROMPT LOCK
							performRedownload(fname, originalURL, substitutedURL, pkgVersion, pkgSrcDir, (logger != os.Stdout), logger)
						}
					} else {
						actionSummary = "Kept (mismatch)"
					}
				})
			}
		} else {
			// Case D: No checksum exists and not in force mode.
			// Automatically keep the local file and generate a new checksum. NO PROMPT.
			actionSummary = "Generated"
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprintf(logger, "%s", colSuccess.Sprintf("No checksum for %s, generating from local file.\n", fname))
		}

		// 4. RECALCULATE: Generate the new checksum for the file now on disk.
		debugf("-> Updating checksum for %s\n", fname)
		newSum, err := ComputeChecksum(filePath, UserExec)
		if err != nil {
			return fmt.Errorf("failed to compute checksum for %s: %v", fname, err)
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
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprintln(logger, colSuccess.Sprintf("Checksum %s", s))
	}

	// 6. SIGNATURE VERIFICATION PASS: Check all files for accompanying signatures
	for _, fname := range expectedFiles {
		if strings.HasSuffix(fname, ".sig") {
			continue
		}
		filePath := filepath.Join(pkgSrcDir, fname)
		sigPath := filePath + ".sig"

		if _, err := os.Stat(sigPath); err == nil {
			sigData, err := os.ReadFile(sigPath)
			if err != nil {
				return fmt.Errorf("failed to read signature file %s: %v", sigPath, err)
			}
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read file for verification %s: %v", filePath, err)
			}

			masterPubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
			if err := VerifySignatureRaw(fileData, sigData, masterPubKeyBytes); err != nil {
				colArrow.Print("-> ")
				colError.Printf("SIGNATURE VERIFICATION FAILED for %s: %v\n", fname, err)
				return fmt.Errorf("signature verification failed for %s", fname)
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Signature verified for %s\n", fname)
		}
	}

	return nil
}

// checksum command

func hokutoChecksum(pkgName string, force bool, unpack bool) error {

	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
	}

	if err := fetchSources(pkgName, pkgDir, false); err != nil {
		return fmt.Errorf("error fetching sources: %v", err)
	}
	if err := verifyOrCreateChecksums(pkgName, pkgDir, force, nil); err != nil {
		return fmt.Errorf("error verifying checksums: %v", err)
	}

	// If -unpack flag is set, prepare sources in tmpdir
	if unpack {
		// Load config to get TMPDIR
		cfg, err := loadConfig(ConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %v", err)
		}

		// Determine tmpdir (same logic as build command)
		tmpDir := cfg.Values["TMPDIR"]
		if tmpDir == "" {
			tmpDir = "/var/tmp/hokuto"
		}
		currentTmpDir := tmpDir
		// Check for noram file
		tmpDirfile := filepath.Join(pkgDir, "noram")
		if _, err := os.Stat(tmpDirfile); err == nil {
			currentTmpDir = cfg.Values["TMPDIR2"]
			if currentTmpDir == "" {
				currentTmpDir = "/var/tmpdir"
			}
		}

		// Create build directory in tmpdir
		buildDir := filepath.Join(currentTmpDir, pkgName, "build")
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return fmt.Errorf("failed to create build directory: %v", err)
		}

		// Prepare sources using UserExec (non-root)
		if err := prepareSources(pkgName, pkgDir, buildDir, UserExec); err != nil {
			return fmt.Errorf("failed to prepare sources: %v", err)
		}

		fmt.Printf("Sources unpacked for %s in %s\n", pkgName, buildDir)
	}

	return nil
}

// ComputeChecksums computes checksums for multiple files, using system b3sum if available.
// It handles privilege escalation via execCtx and batches files for efficiency.
func ComputeChecksums(paths []string, execCtx *Executor) (map[string]string, error) {
	if len(paths) == 0 {
		return make(map[string]string), nil
	}

	results := make(map[string]string)
	var mu sync.Mutex

	// 1. Try system b3sum if available
	if hasB3sum() {
		// Filter out paths with backslashes or special characters that confuse b3sum output parsing
		// These files will fall back to the recursive Go implementation below.
		var b3Paths []string
		for _, p := range paths {
			if !strings.Contains(p, "\\") {
				b3Paths = append(b3Paths, p)
			}
		}

		// Batch files to avoid ARG_MAX issues. On Linux, ARG_MAX is typically 2MB.
		// 5000 files with ~200 byte paths is ~1MB, which is safe.
		const batchSize = 5000
		for i := 0; i < len(b3Paths); i += batchSize {
			end := i + batchSize
			if end > len(b3Paths) {
				end = len(b3Paths)
			}
			batch := b3Paths[i:end]

			cmd := exec.Command("b3sum", batch...)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = io.Discard

			var err error
			if execCtx != nil {
				err = execCtx.Run(cmd)
			} else {
				err = cmd.Run()
			}

			if err == nil {
				scanner := bufio.NewScanner(&out)
				for scanner.Scan() {
					fields := strings.Fields(scanner.Text())
					if len(fields) >= 2 {
						// b3sum output: <hash>  <path>
						hash := fields[0]
						// We need to match the path back. Since b3sum might return relative or different absolute style,
						// but usually it's the exact path we passed.
						// The second field might have spaces if the path has spaces.
						// Reconstruct path from fields[1:]
						pathInOutput := strings.Join(fields[1:], " ")
						results[pathInOutput] = hash
					}
				}
			} else {
				// If a batch fails (e.g. one file missing or permission denied even with execCtx),
				// we'll let the fallback handle it or report error later.
				debugf("b3sum batch %d-%d failed: %v\n", i, end, err)
			}
		}

		// If we got results for all files, we're done.
		if len(results) == len(paths) {
			return results, nil
		}
	}

	// 2. Fallback: Internal Go BLAKE3 (Parallel)
	// Compute remaining or all if b3sum failed/missing
	var remaining []string
	for _, p := range paths {
		if _, ok := results[p]; !ok {
			remaining = append(remaining, p)
		}
	}

	if len(remaining) == 0 {
		return results, nil
	}

	numWorkers := runtime.NumCPU() * 2
	if len(remaining) < numWorkers {
		numWorkers = len(remaining)
	}

	jobs := make(chan string, len(remaining))
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for path := range jobs {
				hash, err := computeSingleGoHash(path, execCtx, buf)
				mu.Lock()
				if err != nil {
					errOnce.Do(func() { firstErr = err })
				} else {
					results[path] = hash
				}
				mu.Unlock()
			}
		}()
	}

	for _, p := range remaining {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return results, firstErr
	}

	return results, nil
}

// ComputeChecksum computes a single checksum, using system b3sum if available.
func ComputeChecksum(path string, execCtx *Executor) (string, error) {
	results, err := ComputeChecksums([]string{path}, execCtx)
	if err != nil {
		return "", err
	}
	if hash, ok := results[path]; ok {
		return hash, nil
	}
	return "", fmt.Errorf("failed to compute checksum for %s", path)
}

func computeSingleGoHash(path string, execCtx *Executor, buf []byte) (string, error) {
	// 1. Try to read directly
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		h := blake3.New(32, nil)
		if _, err := io.CopyBuffer(h, f, buf); err == nil {
			return fmt.Sprintf("%x", h.Sum(nil)), nil
		}
	}

	// 2. Fallback: Privileged Read via Executor
	if err != nil && os.IsPermission(err) && execCtx != nil && execCtx.ShouldRunAsRoot {
		catCmd := exec.Command("cat", path)
		var out bytes.Buffer
		catCmd.Stdout = &out
		catCmd.Stderr = io.Discard

		if runErr := execCtx.Run(catCmd); runErr == nil {
			h := blake3.New(32, nil)
			h.Write(out.Bytes())
			return fmt.Sprintf("%x", h.Sum(nil)), nil
		}
	}

	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("hashing failed")
}

// Helper to perform redownload with logging
func performRedownload(fname, originalURL, substitutedURL, pkgVersion, pkgSrcDir string, quiet bool, logger io.Writer) {
	if !quiet {
		if logger != nil && logger != os.Stdout && logger != os.Stderr {
			fmt.Fprintf(logger, "Downloading %s\n", fname)
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Downloading %s\n", fname)
		}
	}

	//Use version-aware hash and cleanup
	hashInput := originalURL + pkgVersion
	hashName := fmt.Sprintf("%s-%s", hashString(hashInput), fname)
	cachePath := filepath.Join(CacheStore, hashName)
	filePath := filepath.Join(pkgSrcDir, fname)

	// Clean up old versions/hashes of this file
	globPattern := filepath.Join(CacheStore, "*-"+fname)
	if matches, err := filepath.Glob(globPattern); err == nil {
		for _, match := range matches {
			if match != cachePath {
				_ = os.Remove(match)
			}
		}
	}

	_ = os.Remove(cachePath)
	_ = os.Remove(filePath)

	if dErr := downloadFileWithOptions(originalURL, substitutedURL, cachePath, downloadOptions{Quiet: quiet, Force: true}); dErr != nil {
		if !quiet {
			fmt.Printf("Msg: failed to redownload %s: %v\n", fname, dErr)
		}
	} else {
		if sErr := os.Symlink(cachePath, filepath.Join(pkgSrcDir, fname)); sErr != nil {
			if !quiet {
				fmt.Printf("Msg: failed to symlink %s -> %s: %v\n", cachePath, filepath.Join(pkgSrcDir, fname), sErr)
			}
		}
	}
}
