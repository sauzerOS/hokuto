package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gookit/color"
	"golang.org/x/sys/unix"
)

func newHttpClient() (*http.Client, error) {
	// Create a new pool from the embedded asset.
	rootCAs := x509.NewCertPool()
	certs, err := embeddedAssets.ReadFile("assets/ca-bundle.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded ca-bundle.crt: %w."+
			" Please ensure the file exists in the 'assets' directory before compiling", err)
	}

	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, fmt.Errorf("failed to parse bundled CA certificates. The file may be invalid")
	}

	// Configure the TLS client to use the selected pool of trusted CAs.
	tlsConfig := &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	// Increase TLS handshake timeout to handle slow/problematic sites like busybox.net
	// Default is 10s, we increase it to 30s.
	transport.TLSHandshakeTimeout = 30 * time.Second

	return &http.Client{
		Transport: transport,
		Timeout:   300 * time.Second, // 5 min total timeout for large downloads
	}, nil
}

// downloadFile downloads a URL into the hokuto cache.

type downloadOptions struct {
	Quiet bool // Quiet suppresses all stdout/stderr/progress output
}

func tryRemoveCachedFile(path string) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		_ = os.Remove(path)
		return
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// Someone is downloading or verifying the file; skip cleanup.
		return
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = os.Remove(path)
	_ = os.Remove(lockPath)
}

func downloadFile(originalURL, finalURL, destFile string) error {
	return downloadFileWithOptions(originalURL, finalURL, destFile, downloadOptions{Quiet: false})
}

func downloadFileQuiet(originalURL, finalURL, destFile string) error {
	return downloadFileWithOptions(originalURL, finalURL, destFile, downloadOptions{Quiet: true})
}

func downloadFileWithOptions(originalURL, finalURL, destFile string, opt downloadOptions) error {
	// If a GNU mirror is being used for this download, print the info message exactly once.
	if !opt.Quiet && originalURL != finalURL {
		gnuMirrorMessageOnce.Do(func() {
			colArrow.Print("-> ")
			colSuccess.Printf("Using GNU mirror: %s\n", gnuMirrorURL)
		})
	}

	// Determine absolute path.
	// If destFile is absolute, use it directly (for binaries).
	// If relative, join with CacheStore (for sources).
	var absPath string
	if filepath.IsAbs(destFile) {
		absPath = destFile
	} else {
		// Legacy behavior for fetchSources
		if err := os.MkdirAll(CacheStore, 0o755); err != nil {
			return fmt.Errorf("failed to create cache directory %s: %w", CacheStore, err)
		}
		absPath = filepath.Join(CacheStore, filepath.Base(destFile))
	}

	// Ensure parent directory exists (critical for BinDir downloads)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", absPath, err)
	}
	lockPath := absPath + ".lock"

	// Create/Open a lock file to prevent race conditions between background prefetcher and main builder
	lFile, err := os.Create(lockPath)
	if err != nil {
		return fmt.Errorf("failed to create lock file: %w", err)
	}
	defer lFile.Close()

	// Acquire an exclusive lock. This will block if another process/goroutine is downloading.
	if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire lock for download: %w", err)
	}
	// Ensure we release the lock when done
	defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

	// DOUBLE CHECK: Now that we have the lock, check if the file exists again.
	// The background worker might have finished it while we were waiting for the lock.
	if _, err := os.Stat(absPath); err == nil {
		debugf("File %s appeared after acquiring lock, skipping download.\n", absPath)
		// Remove lock file since we're not downloading
		_ = os.Remove(lockPath)
		return nil
	}

	// Ensure lock file is removed on successful download
	defer func() {
		if _, err := os.Stat(absPath); err == nil {
			// File exists, download succeeded, remove lock file
			_ = os.Remove(lockPath)
		}
	}()

	debugf("Downloading %s -> %s\n", finalURL, absPath)

	// --- Primary Choice: Try curl with Go-native colorization ---
	if _, err := exec.LookPath("curl"); err == nil {
		curlArgs := []string{"-L", "--fail", "-o", absPath}
		if opt.Quiet {
			curlArgs = append(curlArgs, "-sS")
		} else {
			curlArgs = append(curlArgs, "-#")
		}
		curlArgs = append(curlArgs, finalURL) // Use the final URL for the download
		cmd := exec.Command("curl", curlArgs...)

		if opt.Quiet {
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if err := cmd.Run(); err == nil {
				return nil
			}
			debugf("curl (quiet) failed, falling back to wget\n")
		} else {
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
		}
	} else {
		debugf("curl not found, trying wget")
	}

	// --- Fallback 1: Try wget ---
	if _, err := exec.LookPath("wget"); err == nil {
		args := []string{"-O", absPath}
		if opt.Quiet {
			args = append([]string{"-q"}, args...)
		} else {
			args = append([]string{"-nv"}, args...)
		}
		args = append(args, finalURL) // Use the final URL for the download
		cmd := exec.Command("wget", args...)
		if opt.Quiet {
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
		} else {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
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

// fetchBinaryPackage attempts to download a binary package from the configured mirror.

func fetchBinaryPackage(pkgName, version, revision string, cfg *Config) error {
	if BinaryMirror == "" {
		return fmt.Errorf("no HOKUTO_MIRROR configured")
	}

	arch := GetSystemArch(cfg)
	variant := GetSystemVariantForPackage(cfg, pkgName)
	filename := StandardizeRemoteName(pkgName, version, revision, arch, variant)
	url := fmt.Sprintf("%s/%s", BinaryMirror, filename)
	destPath := filepath.Join(BinDir, filename)

	colArrow.Print("-> ")
	colSuccess.Printf("Checking mirror for binary: %s\n", filename)

	// Use downloadFileQuiet so we don't see curl errors (e.g. 404) during update loop
	if err := downloadFileQuiet(url, url, destPath); err != nil {
		// Clean up partial file on failure to prevent corrupt cache
		os.Remove(destPath)
		return err
	}
	return nil
}

// prefetchSources runs in a background goroutine to download sources.
// It uses a semaphore to limit concurrent downloads to 10.

func prefetchSources(pkgNames []string) {
	if len(pkgNames) == 0 {
		return
	}

	concurrencyLimit := 10
	debugf("Starting background prefetch for %d packages (concurrency: %d)...\n", len(pkgNames), concurrencyLimit)

	// Semaphore to limit concurrency
	sem := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	for _, pkgName := range pkgNames {
		// Acquire a slot in the semaphore (blocks if 10 are already running)
		sem <- struct{}{}
		wg.Add(1)

		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the slot when done

			// Logic to find package directory
			paths := strings.Split(repoPaths, ":")
			var pkgDir string
			found := false
			for _, repo := range paths {
				tryPath := filepath.Join(repo, name)
				if info, err := os.Stat(tryPath); err == nil && info.IsDir() {
					pkgDir = tryPath
					found = true
					break
				}
			}

			if found {
				// We use 'true' for processGit.
				// Since we have file locking in downloadFile, this is thread-safe for files.
				if err := fetchSourcesQuiet(name, pkgDir, true); err != nil {
					// Log debug only, main thread will handle critical failures later
					debugf("Background prefetch failed for %s: %v\n", name, err)
				}
			}
		}(pkgName)
	}

	// Wait for all downloads to finish (optional, but good for cleanup)
	wg.Wait()
	debugf("Background prefetch completed.\n")
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
	return fetchSourcesWithOptions(pkgName, pkgDir, processGit, false)
}

// fetchSourcesQuiet is used by background prefetch to avoid corrupting CLI output.
func fetchSourcesQuiet(pkgName, pkgDir string, processGit bool) error {
	return fetchSourcesWithOptions(pkgName, pkgDir, processGit, true)
}

func fetchSourcesWithOptions(pkgName, pkgDir string, processGit bool, quiet bool) error {
	data, err := os.ReadFile(filepath.Join(pkgDir, "sources"))
	if err != nil {
		return fmt.Errorf("could not read sources file: %v", err)
	}

	// Read package version for cache-busting
	versionData, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		// If we can't read the version file, we can't create a version-aware hash.
		return fmt.Errorf("could not read version file for cache hashing: %v", err)
	}
	fields := strings.Fields(string(versionData))
	if len(fields) == 0 {
		return fmt.Errorf("version file %s is empty", filepath.Join(pkgDir, "version"))
	}
	pkgVersion := fields[0] // Get just the version string, e.g., "1.2.3"

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
				if !quiet {
					cPrintf(colInfo, "Cloning git repository %s into %s\n", gitURL, destPath)
				}
				cmd := exec.Command("git", "clone", gitURL, destPath)
				if quiet && !Debug {
					cmd.Stdout = io.Discard
					cmd.Stderr = io.Discard
				} else {
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
				}
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("git clone failed: %v", err)
				}
			} else if ref == "" {
				cmd := exec.Command("git", "-C", destPath, "pull")
				if quiet && !Debug {
					cmd.Stdout = io.Discard
					cmd.Stderr = io.Discard
				} else {
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
				}
				cmd.Run()
			}
			exec.Command("git", "-C", destPath, "config", "advice.detachedHead", "false").Run()
			if ref != "" {
				checkBranch := exec.Command("git", "-C", destPath, "rev-parse", "--verify", "refs/heads/"+ref)
				if err := checkBranch.Run(); err == nil {
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					if quiet && !Debug {
						cmd.Stdout = io.Discard
						cmd.Stderr = io.Discard
					} else {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}
					cmd.Run()
					cmd = exec.Command("git", "-C", destPath, "pull")
					if quiet && !Debug {
						cmd.Stdout = io.Discard
						cmd.Stderr = io.Discard
					} else {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}
					cmd.Run()
				} else {
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					if quiet && !Debug {
						cmd.Stdout = io.Discard
						cmd.Stderr = io.Discard
					} else {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}
					cmd.Run()
				}
			}
			if !quiet {
				cPrintf(colInfo, "Git repository ready: %s\n", destPath)
			}
			continue // End git block
		}

		// --- HTTP/FTP Source Logic ---
		originalSourceURL := rawSourceURL
		substitutedURL := applyGnuMirror(originalSourceURL)

		parts = strings.Split(originalSourceURL, "/")
		origFilename = parts[len(parts)-1]

		// Create a version-aware hash key by combining the URL and the package version.
		// This busts the cache for static URLs (like .../stable.deb) when the package version file is updated.
		hashInput := originalSourceURL + pkgVersion
		// The hash for the cache is now based on the URL *and* the package version.
		hashName = fmt.Sprintf("%s-%s", hashString(hashInput), origFilename)

		cachePath = filepath.Join(CacheStore, hashName)

		// This removes files like "OLDHASH-filename.tar.xz" so only "NEWHASH-filename.tar.xz" remains.
		globPattern := filepath.Join(CacheStore, "*-"+origFilename)
		if matches, err := filepath.Glob(globPattern); err == nil {
			for _, match := range matches {
				if match != cachePath {
					debugf("Removing obsolete cached file: %s\n", match)
					tryRemoveCachedFile(match)
				}
			}
		}

		if _, err := os.Stat(cachePath); os.IsNotExist(err) {
			if !quiet {
				colArrow.Print("-> ")
				colSuccess.Printf("Fetching source: %s\n", origFilename)
			}
			downloader := downloadFile
			if quiet {
				downloader = downloadFileQuiet
			}
			if err := downloader(originalSourceURL, substitutedURL, cachePath); err != nil {
				return fmt.Errorf("failed to download %s: %v", substitutedURL, err)
			}
		} else {
			debugf("Already in cache: %s\n", cachePath)
		}

		linkPath = filepath.Join(pkgLinkDir, origFilename)

		// Use atomic symlink creation (Create Temp -> Rename) to prevent "file exists" race conditions
		// if the background prefetcher and main thread overlap.
		tmpLinkPath := fmt.Sprintf("%s.tmp.%d", linkPath, time.Now().UnixNano())

		if err := os.Symlink(cachePath, tmpLinkPath); err != nil {
			return fmt.Errorf("failed to create temp symlink: %v", err)
		}

		// Atomic replace: if linkPath exists (from another thread), this simply overwrites it safely.
		if err := os.Rename(tmpLinkPath, linkPath); err != nil {
			os.Remove(tmpLinkPath) // Cleanup on failure
			return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, linkPath, err)
		}

		debugf("Linked %s -> %s\n", linkPath, cachePath)
	}

	return nil
}
