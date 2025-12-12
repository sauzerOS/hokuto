package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

func verifyOrCreateChecksums(pkgName, pkgDir string, force bool) error {
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
		fileMissing := false

		// 1. VERIFY: Check the hash if it exists and we aren't forcing a refresh.
		if sumExists && !force {
			lockBase := resolveLockBaseForVerification(filePath)
			_ = withSharedDownloadLock(lockBase, func() error {
				if _, err := os.Stat(filePath); err != nil {
					fileMissing = true
					return nil
				}

				// Prefer the external `b3sum` command if available.
				if hasB3sum() {
					out, err := exec.Command("b3sum", filePath).Output()
					if err == nil {
						fields := strings.Fields(string(out))
						if len(fields) > 0 && fields[0] == currentSum {
							isHashValid = true
						}
					}
				} else {
					// Fallback to internal blake3 calculation.
					sum, err := blake3SumFile(filePath)
					if err == nil && sum == currentSum {
						isHashValid = true
					}
				}
				return nil
			})
		}

		// 2. DECIDE & ACT: Determine what to do based on checksum validity.
		if isHashValid && !force {
			// Case A: Hash is valid and we are not forcing. Everything is OK.
			finalChecksums = append(finalChecksums, fmt.Sprintf("%s  %s", currentSum, fname))
			summary = append(summary, fmt.Sprintf("%s: ok", fname))
			continue
		}

		// If we are here, the hash is either invalid, missing, or we are forcing an update.
		var shouldRedownload bool
		var actionSummary string

		if force {
			// Case B: Force mode is enabled. Always redownload.
			shouldRedownload = true
			actionSummary = "Updated (forced)"
		} else if sumExists && !isHashValid {
			// Case C: A checksum exists, but it MISMATCHES. Prompt the user for action.
			if fileMissing {
				shouldRedownload = true
				actionSummary = "Updated (missing)"
			} else {
				interactiveMu.Lock()
				func() {
					defer interactiveMu.Unlock()
					// Print a clean prompt line (helps if prior output was a progress bar).
					fmt.Fprintln(os.Stderr)
					colArrow.Print("-> ")
					colWarn.Printf("Checksum mismatch for %s. (K)eep local file, (r)edownload file? [K/r]: ", fname)
					var response string
					_, _ = fmt.Scanln(&response)
					if strings.ToLower(strings.TrimSpace(response)) == "r" {
						shouldRedownload = true
						actionSummary = "Updated (redownloaded)"
					} else {
						shouldRedownload = false
						actionSummary = "Updated (kept local)"
					}
				}()
			}
		} else {
			// Case D: No checksum exists and not in force mode.
			// Automatically keep the local file and generate a new checksum. NO PROMPT.
			shouldRedownload = false
			actionSummary = "Generated"
			colArrow.Print("-> ")
			colSuccess.Printf("No checksum for %s, generating from local file.\n", fname)
		}

		// 3. PERFORM REDOWNLOAD (if decided in the logic above)

		if shouldRedownload {
			colArrow.Print("-> ")
			colSuccess.Printf("Downloading %s\n", fname)
			actionSummary = "Updated"

			//Use version-aware hash and cleanup
			hashInput := originalURL + pkgVersion
			hashName := fmt.Sprintf("%s-%s", hashString(hashInput), fname)
			cachePath := filepath.Join(CacheStore, hashName)

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

// unzipGo extracts a zip archive using a native Go library.
// It includes a security check to prevent path traversal attacks (Zip Slip).

func b3sum(path string, execCtx *Executor) (string, error) {
	// First try the system b3sum binary
	if _, err := exec.LookPath("b3sum"); err == nil {
		cmd := exec.Command("b3sum", path)

		var out bytes.Buffer
		cmd.Stdout = &out
		// ** FIX: Discard stderr to silence "No such file or directory" messages. **
		// The error will still be propagated by execCtx.Run if b3sum fails.
		cmd.Stderr = io.Discard

		if err := execCtx.Run(cmd); err == nil {
			fields := strings.Fields(out.String())
			if len(fields) > 0 {
				return fields[0], nil
			}
			// fall through to internal if no output
		}
		// If system b3sum fails, we'll fall through to the internal implementation.
	}

	// Fallback: internal Go BLAKE3 with privilege awareness
	if execCtx.ShouldRunAsRoot {
		catCmd := exec.Command("cat", path)
		var out bytes.Buffer
		catCmd.Stdout = &out
		// Also discard stderr for cat, in case the file disappears.
		catCmd.Stderr = io.Discard

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
		// ** FIX: Discard stderr to silence "No such file or directory" messages. **
		// The error will still be propagated by cmd.Run if b3sum fails.
		cmd.Stderr = io.Discard

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
