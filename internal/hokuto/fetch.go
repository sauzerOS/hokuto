package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/klauspost/compress/zstd"
	"github.com/schollz/progressbar/v3"
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
		Timeout:   5 * time.Minute, // User requested 5m global timeout
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Important: Go's http client does NOT forward the User-Agent header by default
			// when redirecting to a different domain (security feature).
			// However, for SourceForge and similar mirrors, we NEED the UA to be preserved
			// or we get an HTML page instead of the file.
			if len(via) > 0 {
				req.Header.Set("User-Agent", via[0].Header.Get("User-Agent"))
			}
			return nil
		},
	}, nil
}

// downloadFile downloads a URL into the hokuto cache.

type downloadOptions struct {
	Quiet bool // Quiet suppresses all stdout/stderr/progress output
}

type IdleTimeoutReader struct {
	src     io.ReadCloser
	timeout time.Duration
	timer   *time.Timer
	cancel  context.CancelFunc
}

func (r *IdleTimeoutReader) Read(p []byte) (int, error) {
	if r.timer == nil {
		r.timer = time.AfterFunc(r.timeout, r.cancel)
	} else {
		r.timer.Reset(r.timeout)
	}
	return r.src.Read(p)
}

func (r *IdleTimeoutReader) Close() error {
	if r.timer != nil {
		r.timer.Stop()
	}
	return r.src.Close()
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

	// --- Primary Choice: Native Go HTTP Client ---
	// We try native first for speed and standard behavior.
	debugf("Downloading %s -> %s\n", finalURL, absPath)

	var resp *http.Response
	var nativeErr error // Renamed to avoid shadowing the outer 'err'

	// Retry loop for download
	maxRetries := 3
	for i := 0; i <= maxRetries; i++ {
		client, err := newHttpClient()
		if err != nil {
			nativeErr = fmt.Errorf("failed to create http client: %w", err)
			break // Cannot proceed with native client
		}

		// Local context for this attempt, allowing cancellation on idle timeout
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", finalURL, nil)
		if err != nil {
			nativeErr = fmt.Errorf("failed to create http request: %w", err)
			break
		}
		// Use a realistic browser User-Agent to avoid being flagged as a bot (e.g. by GitHub or SourceForge)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Connection", "keep-alive")

		resp, err = client.Do(req)
		if err != nil {
			if i < maxRetries {
				backoff := time.Duration(1<<i) * time.Second
				debugf("Native download attempt %d/%d failed: %v. Retrying in %s...\n", i+1, maxRetries+1, err, backoff)
				time.Sleep(backoff)
				continue
			}
			// If we exhausted retries on network errors, we might still want to try browser?
			// The user said "use chromedp as fallback".
			// So if native fails completely, we fall back.
			nativeErr = fmt.Errorf("native http get failed after %d attempts: %w", maxRetries+1, err)
			debugf("Native download failed after %d attempts: %v\n", maxRetries+1, nativeErr)
			break // Fall through to browser
		}

		// Check status codes
		if resp.StatusCode == http.StatusOK {
			// Sanity Check: If we downloaded text/html but expected a binary, fallback to browser.
			// This happens when servers return a "Click here to download" page or bot check page with 200 OK.
			ct := resp.Header.Get("Content-Type")
			isBinary := strings.HasSuffix(finalURL, ".gz") || strings.HasSuffix(finalURL, ".bz2") ||
				strings.HasSuffix(finalURL, ".xz") || strings.HasSuffix(finalURL, ".zip") ||
				strings.HasSuffix(finalURL, ".tgz") || strings.HasSuffix(finalURL, ".zst")

			if strings.HasPrefix(ct, "text/html") && isBinary {
				resp.Body.Close()
				nativeErr = fmt.Errorf("server returned text/html content for binary file (likely bot check or redirect page)")
				debugf("Native download got text/html for binary, falling back to browser...\n")
				break
			}

			// Success! Proceed to write file.
			out, err := os.Create(absPath)
			if err != nil {
				resp.Body.Close()
				return fmt.Errorf("failed to create destination file %s: %w", absPath, err)
			}
			defer out.Close()

			var writer io.Writer = out
			var bar *progressbar.ProgressBar
			if !opt.Quiet {
				displayFilename := filepath.Base(finalURL)
				sizeStr := humanReadableSize(resp.ContentLength)
				colArrow.Print("-> ")
				colSuccess.Printf("Downloading %s (%s)\n", displayFilename, sizeStr)

				bar = progressbar.NewOptions64(
					resp.ContentLength,
					progressbar.OptionSetDescription("   "),
					progressbar.OptionSetWriter(os.Stderr),
					progressbar.OptionShowBytes(true),
					progressbar.OptionSetWidth(30),
					progressbar.OptionThrottle(10*time.Millisecond),
					progressbar.OptionShowCount(),
					progressbar.OptionOnCompletion(func() {
						fmt.Fprint(os.Stderr, "\n")
					}),
					progressbar.OptionSetTheme(progressbar.Theme{
						Saucer:        "▓",
						SaucerHead:    "▓",
						SaucerPadding: "░",
						BarStart:      "┃",
						BarEnd:        "┃",
					}),
				)
				writer = io.MultiWriter(out, bar)
			}

			// Wrap response body with idle timeout reader
			wrappedBody := &IdleTimeoutReader{
				src:     resp.Body,
				timeout: 15 * time.Second,
				cancel:  cancel,
			}

			_, err = io.Copy(writer, wrappedBody)
			wrappedBody.Close() // Close response body and stop timer
			if bar != nil {
				bar.Finish()
			}
			if err != nil {
				// Write failed
				return fmt.Errorf("failed to write to destination file: %w", err)
			}

			if !opt.Quiet {
				debugf("Download successful: %s\n", filepath.Base(finalURL))
			}
			debugf("\nDownload successful with native Go HTTP client.\n")
			return nil
		}

		// If status is 418, 403, or 429, or 5xx, we might fallback or retry.
		// 418/403 -> Fallback immediately (Bot check).
		if resp.StatusCode == http.StatusTeapot || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			nativeErr = fmt.Errorf("native download failed with status %d (likely bot check)", resp.StatusCode)
			debugf("Native download failed with status %d (likely bot check), falling back to browser...\n", resp.StatusCode)
			break // Fall through to browser
		}

		// 5xx / 429 -> Retry
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			if i < maxRetries {
				backoff := time.Duration(1<<i) * time.Second
				debugf("Native download attempt %d/%d returned status %s. Retrying in %s...\n", i+1, maxRetries+1, resp.Status, backoff)
				time.Sleep(backoff)
				continue
			}
			nativeErr = fmt.Errorf("native download failed with status %s after retries", resp.Status)
			debugf("Native download failed with status %s after retries.\n", resp.Status)
			break // Fall through to browser
		}

		// 404 or other client errors -> Likely fatal, but maybe browser works?
		// "Revert and use chromedp as fallback" implies general fallback.
		// We will fall back for everything that fails native.
		resp.Body.Close()
		nativeErr = fmt.Errorf("native download failed with status: %s", resp.Status)
		debugf("Native download failed with status: %s. Falling back to browser.\n", resp.Status)
		break
	}

	// --- Fallback: Browser Download (chromedp) ---
	debugf("Falling back to browser download (chromedp)\n")
	if err := downloadViaBrowser(finalURL, absPath, opt.Quiet); err == nil {
		if !opt.Quiet {
			colArrow.Print("-> ")
			displayFilename := filepath.Base(finalURL)
			colSuccess.Printf("Download successful: %s\n", displayFilename)
		}
		debugf("Download successful with browser (chromedp).")
		return nil
	} else {
		// If browser also failed, combine errors
		if nativeErr != nil {
			return fmt.Errorf("all download methods failed. Native error: %w; Browser error: %w", nativeErr, err)
		}
		return fmt.Errorf("all download methods failed. Browser error: %w", err)
	}
}

// downloadViaBrowser uses a headless browser to download the file, bypassing simple bot checks.
// downloadViaBrowser uses a headless browser to download the file, bypassing simple bot checks.
func downloadViaBrowser(url, destPath string, quiet bool) error {
	// Create a temporary directory for the download
	tmpDir, err := os.MkdirTemp("", "hokuto-dl-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) // Cleanup temp dir after we are done

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true), // Often needed in containerized environments
		chromedp.Flag("disable-dev-shm-usage", true),

		// Set a realistic User-Agent to avoid immediate blocking by some filters
		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Timeout for the entire operation (10 minutes to be safe for large files, though we wait for file existence)
	ctx, cancel = context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	// Setup Progress Bar
	var bar *progressbar.ProgressBar
	var barLock sync.Mutex

	// Channel to signal that we found the downloaded file
	foundCh := make(chan string, 1)
	// Channel to signal chromedp error (if any)
	chromeErrCh := make(chan error, 1)

	// Listen for download events and network responses
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *browser.EventDownloadProgress:
			barLock.Lock()
			defer barLock.Unlock()

			if !quiet {
				if bar == nil && e.TotalBytes > 0 {
					displayFilename := filepath.Base(url)
					sizeStr := humanReadableSize(int64(e.TotalBytes))
					colArrow.Print("-> ")
					colSuccess.Printf("Downloading %s (%s) (browser)\n", displayFilename, sizeStr)

					bar = progressbar.NewOptions64(
						int64(e.TotalBytes),
						progressbar.OptionSetDescription("   "),
						progressbar.OptionSetWriter(os.Stderr),
						progressbar.OptionShowBytes(true),
						progressbar.OptionSetWidth(30),
						progressbar.OptionThrottle(10*time.Millisecond),
						progressbar.OptionShowCount(),
						progressbar.OptionOnCompletion(func() {
							fmt.Fprint(os.Stderr, "\n")
						}),
						progressbar.OptionSetTheme(progressbar.Theme{
							Saucer:        "▓",
							SaucerHead:    "▓",
							SaucerPadding: "░",
							BarStart:      "┃",
							BarEnd:        "┃",
						}),
					)
				}
				if bar != nil {
					bar.Set(int(e.ReceivedBytes))
					if e.State == browser.DownloadProgressStateCompleted {
						bar.Finish()
					}
				}
			}

		case *network.EventResponseReceived:
			// Check for fatal status codes (404, 403, 429) on the main document
			status := e.Response.Status
			if status == http.StatusNotFound || status == http.StatusForbidden || status == http.StatusTooManyRequests {
				if e.Type == network.ResourceTypeDocument {
					select {
					case chromeErrCh <- fmt.Errorf("browser received status %d %s", status, http.StatusText(int(status))):
					default:
					}
				}
			}
		}
	})

	// 1. Start polling the directory in a separate goroutine.
	// We do this BEFORE running chromedp so we are ready to catch the file if it downloads instantly.
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				entries, err := os.ReadDir(tmpDir)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					name := entry.Name()
					// Check for completed file (not crdownload or tmp)
					if !strings.HasSuffix(name, ".crdownload") && !strings.HasSuffix(name, ".tmp") {
						foundCh <- filepath.Join(tmpDir, name)
						return
					}
				}
			}
		}
	}()

	// 2. Run chromedp in a separate goroutine.
	// We use an indefinite ActionFunc at the end so this goroutine BLOCKS until ctx is done.
	// This prevents "browser finished" errors when a bot check page loads properly.
	go func() {
		err := chromedp.Run(ctx,
			network.Enable(), // Enable network events to catch 404s
			browser.SetDownloadBehavior(browser.SetDownloadBehaviorBehaviorAllow).
				WithDownloadPath(tmpDir).
				WithEventsEnabled(true), // Enable events for progress bar
			chromedp.Navigate(url),
			// Keep the browser open until the context is cancelled (by the poller finding the file)
			chromedp.ActionFunc(func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			}),
		)
		chromeErrCh <- err
	}()

	// 3. Wait for either the file to be found, or a chrome error/timeout.
	var downloadedFile string

	select {
	case file := <-foundCh:
		downloadedFile = file
		// Success! The defer cancel() at end of function will kill chrome.

	case err := <-chromeErrCh:
		// If Chrome exits, check error.
		if err != nil && !errors.Is(err, context.Canceled) {
			// Special handling for net::ERR_ABORTED
			if strings.Contains(err.Error(), "net::ERR_ABORTED") {
				debugf("Browser navigation aborted (likely download started), waiting for file...\n")
				select {
				case file := <-foundCh:
					downloadedFile = file
				case <-time.After(10 * time.Second):
					return fmt.Errorf("browser download failed (aborted and no file found): %w", err)
				}
			} else {
				return fmt.Errorf("browser download failed: %w", err)
			}
		} else {
			// If Chrome exited cleanly (nil error), check for file one last time.
			select {
			case file := <-foundCh:
				downloadedFile = file
			case <-time.After(5 * time.Second):
				return fmt.Errorf("browser finished but file was not found")
			}
		}

	case <-ctx.Done():
		return fmt.Errorf("timeout or context cancelled: %w", ctx.Err())
	}

	// Move the downloaded file to the final destination
	if err := os.Rename(downloadedFile, destPath); err != nil {
		// Fallback copy if rename fails (cross-device)
		src, err := os.Open(downloadedFile)
		if err != nil {
			return err
		}
		defer src.Close()

		dst, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer dst.Close()

		if _, err := io.Copy(dst, src); err != nil {
			return err
		}
	}

	return nil
}

// fetchBinaryPackage attempts to download a binary package from the configured mirror.

// fetchBinaryPackage attempts to download a binary package from the configured mirror.
func fetchBinaryPackage(pkgName, version, revision string, cfg *Config, quiet bool, expectedSum string) error {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if BinaryMirror == "" {
		return fmt.Errorf("no HOKUTO_MIRROR configured")
	}

	arch := GetSystemArchForPackage(cfg, lookupName)
	variant := GetSystemVariantForPackage(cfg, lookupName)
	filename := StandardizeRemoteName(lookupName, version, revision, arch, variant)
	url := fmt.Sprintf("%s/%s", BinaryMirror, filename)
	destPath := filepath.Join(BinDir, filename)

	// Use downloadFileWithOptions to show progress if not quiet
	if err := downloadFileWithOptions(url, url, destPath, downloadOptions{Quiet: quiet}); err != nil {
		// Clean up partial file on failure to prevent corrupt cache
		os.Remove(destPath)
		return err
	}

	// Check checksum if provided
	if expectedSum != "" {
		computedSum, err := ComputeChecksum(destPath, nil)
		if err != nil {
			os.Remove(destPath)
			return fmt.Errorf("failed to compute checksum for %s: %w", filename, err)
		}
		if computedSum != expectedSum {
			os.Remove(destPath)
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filename, expectedSum, computedSum)
		}
		if !quiet {
			colArrow.Print("-> ")
			colSuccess.Printf("Checksum verified: %s\n", expectedSum)
		}
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

	// Special handling for 'hokuto' package: invalidate cache on revision change
	if pkgName == "hokuto" && len(fields) > 1 {
		pkgVersion += "-" + fields[1]
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

// SyncPkgDB downloads the global package database from the mirror if newer.
func SyncPkgDB(cfg *Config) error {
	if BinaryMirror == "" {
		return fmt.Errorf("no HOKUTO_MIRROR configured")
	}

	filename := filepath.Base(PkgDBPath)
	url := fmt.Sprintf("%s/%s", BinaryMirror, filename)
	tmpPath := filepath.Join(os.TempDir(), filename)

	colArrow.Print("-> ")
	colNote.Printf("Checking for updated global database from mirror\n")

	// Use downloadFileQuiet to check mirror
	if err := downloadFileQuiet(url, url, tmpPath); err != nil {
		return fmt.Errorf("failed to download database from mirror: %w", err)
	}
	defer os.Remove(tmpPath)

	// Read remote revision
	remoteDB, err := readPkgDB(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to read remote database: %w", err)
	}

	// Read local revision
	var localRevision int64
	if localDB, err := readPkgDB(PkgDBPath); err == nil {
		localRevision = localDB.Revision
	}

	if remoteDB.Revision > localRevision {
		colArrow.Print("-> ")
		colSuccess.Printf("Newer database found (revision: %d > %d). Updating local copy.\n", remoteDB.Revision, localRevision)

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(PkgDBPath), 0755); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}

		// Use RootExec to move the file if target is not writable
		// Actually, /var/db/hokuto is usually owned by root.
		// Let's copy it using standard methods first, or use RootExec if needed.

		data, err := os.ReadFile(tmpPath)
		if err != nil {
			return err
		}

		if os.Geteuid() == 0 {
			err = os.WriteFile(PkgDBPath, data, 0644)
		} else {
			// Write to a temporary file and move with sudo
			tempFile, _ := os.CreateTemp("", "pkg-db-sync-*.zst")
			_ = os.WriteFile(tempFile.Name(), data, 0644)
			tempFile.Close()
			mvCmd := exec.Command("mv", tempFile.Name(), PkgDBPath)
			err = RootExec.Run(mvCmd)
		}

		if err != nil {
			return fmt.Errorf("failed to update local database: %w", err)
		}
		colSuccess.Println("Global database updated successfully.")
	} else {
		colArrow.Print("-> ")
		colSuccess.Printf("Local database is already up to date (revision: %d).\n", localRevision)
	}

	return nil
}

func readPkgDB(path string) (*PkgDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var db PkgDB
	if err := json.NewDecoder(zr).Decode(&db); err != nil {
		return nil, err
	}

	return &db, nil
}
