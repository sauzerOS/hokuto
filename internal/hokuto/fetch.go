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
	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
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

func simpleHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

type goGitRefCandidate struct {
	revision plumbing.Revision
	remote   plumbing.ReferenceName
	local    plumbing.ReferenceName
}

func normalizeGitSourceRef(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	for _, prefix := range []string{"tag=", "branch=", "revision=", "rev=", "commit=", "ref="} {
		if strings.HasPrefix(ref, prefix) {
			return strings.TrimSuffix(prefix, "="), strings.TrimSpace(strings.TrimPrefix(ref, prefix))
		}
	}
	return "", ref
}

func goGitRefCandidates(ref string) []goGitRefCandidate {
	kind, cleanRef := normalizeGitSourceRef(ref)
	if cleanRef == "" {
		return nil
	}

	add := func(candidates *[]goGitRefCandidate, revision, remote, local string) {
		candidate := goGitRefCandidate{
			revision: plumbing.Revision(revision),
			remote:   plumbing.ReferenceName(remote),
			local:    plumbing.ReferenceName(local),
		}
		for _, existing := range *candidates {
			if existing.revision == candidate.revision && existing.remote == candidate.remote && existing.local == candidate.local {
				return
			}
		}
		*candidates = append(*candidates, candidate)
	}

	var candidates []goGitRefCandidate
	remoteRef := strings.TrimPrefix(cleanRef, "origin/")
	switch kind {
	case "tag":
		tagName := strings.TrimPrefix(cleanRef, "refs/tags/")
		add(&candidates, "refs/tags/"+tagName, "refs/tags/"+tagName, "refs/tags/"+tagName)
	case "branch":
		branchName := strings.TrimPrefix(remoteRef, "refs/heads/")
		add(&candidates, "refs/remotes/origin/"+branchName, "refs/heads/"+branchName, "refs/remotes/origin/"+branchName)
		add(&candidates, "refs/heads/"+branchName, "refs/heads/"+branchName, "refs/remotes/origin/"+branchName)
	default:
		if strings.HasPrefix(cleanRef, "refs/tags/") {
			add(&candidates, cleanRef, cleanRef, cleanRef)
		} else if strings.HasPrefix(cleanRef, "refs/heads/") {
			branchName := strings.TrimPrefix(cleanRef, "refs/heads/")
			add(&candidates, "refs/remotes/origin/"+branchName, cleanRef, "refs/remotes/origin/"+branchName)
			add(&candidates, cleanRef, cleanRef, "refs/remotes/origin/"+branchName)
		} else {
			add(&candidates, "refs/remotes/origin/"+remoteRef, "refs/heads/"+remoteRef, "refs/remotes/origin/"+remoteRef)
			add(&candidates, "refs/remotes/"+cleanRef, "refs/heads/"+remoteRef, "refs/remotes/"+cleanRef)
			add(&candidates, "refs/heads/"+cleanRef, "refs/heads/"+remoteRef, "refs/remotes/origin/"+remoteRef)
			add(&candidates, "refs/tags/"+cleanRef, "refs/tags/"+cleanRef, "refs/tags/"+cleanRef)
			add(&candidates, cleanRef, cleanRef, cleanRef)
		}
	}
	return candidates
}

func fetchGoGitRef(repo *gogit.Repository, ref string, quiet bool) error {
	candidates := goGitRefCandidates(ref)
	if len(candidates) == 0 {
		return nil
	}

	var lastErr error
	for _, candidate := range candidates {
		fetchOpts := &gogit.FetchOptions{
			RemoteName: "origin",
			RefSpecs: []gogitconfig.RefSpec{
				gogitconfig.RefSpec("+" + candidate.remote.String() + ":" + candidate.local.String()),
			},
			Tags: gogit.AllTags,
		}
		if !quiet || Debug {
			fetchOpts.Progress = os.Stderr
		}
		if err := repo.Fetch(fetchOpts); err != nil && err != gogit.NoErrAlreadyUpToDate {
			lastErr = err
			debugf("go-git fetch refspec %s failed: %v\n", fetchOpts.RefSpecs[0], err)
			continue
		}
		return nil
	}
	if tagRef, err := findGoGitSuffixTagRef(repo, ref); err == nil {
		fetchOpts := &gogit.FetchOptions{
			RemoteName: "origin",
			RefSpecs: []gogitconfig.RefSpec{
				gogitconfig.RefSpec("+" + tagRef.String() + ":" + tagRef.String()),
			},
			Tags: gogit.AllTags,
		}
		if !quiet || Debug {
			fetchOpts.Progress = os.Stderr
		}
		if err := repo.Fetch(fetchOpts); err == nil || err == gogit.NoErrAlreadyUpToDate {
			debugf("go-git resolved %s via matching remote tag %s\n", ref, tagRef.Short())
			return nil
		} else {
			lastErr = err
			debugf("go-git fetch matching tag %s failed: %v\n", tagRef, err)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return plumbing.ErrReferenceNotFound
}

func findGoGitSuffixTagRef(repo *gogit.Repository, ref string) (plumbing.ReferenceName, error) {
	kind, cleanRef := normalizeGitSourceRef(ref)
	if kind != "" && kind != "tag" {
		return "", plumbing.ErrReferenceNotFound
	}
	if cleanRef == "" || strings.HasPrefix(cleanRef, "refs/") {
		return "", plumbing.ErrReferenceNotFound
	}

	remote, err := repo.Remote("origin")
	if err != nil {
		return "", err
	}
	remoteRefs, err := remote.List(&gogit.ListOptions{})
	if err != nil {
		return "", err
	}

	return matchGoGitSuffixTagRef(cleanRef, remoteRefs)
}

func matchGoGitSuffixTagRef(cleanRef string, remoteRefs []*plumbing.Reference) (plumbing.ReferenceName, error) {
	suffix := "-" + cleanRef
	var match plumbing.ReferenceName
	for _, remoteRef := range remoteRefs {
		name := remoteRef.Name()
		if !name.IsTag() {
			continue
		}
		shortName := name.Short()
		if shortName != cleanRef && !strings.HasSuffix(shortName, suffix) {
			continue
		}
		if match != "" && match != name {
			return "", fmt.Errorf("multiple remote tags match %s", cleanRef)
		}
		match = name
	}
	if match == "" {
		return "", plumbing.ErrReferenceNotFound
	}
	return match, nil
}

func goGitTagCommitHash(repo *gogit.Repository, ref *plumbing.Reference) (plumbing.Hash, bool) {
	if commit, err := repo.CommitObject(ref.Hash()); err == nil {
		return commit.Hash, true
	}
	if tag, err := repo.TagObject(ref.Hash()); err == nil {
		if commit, err := tag.Commit(); err == nil {
			return commit.Hash, true
		}
	}
	return plumbing.ZeroHash, false
}

func goGitHeadTag(repo *gogit.Repository, requestedRef string, head plumbing.Hash) (string, bool) {
	var exact []string
	var suffix []string
	var other []string
	_, cleanRef := normalizeGitSourceRef(requestedRef)
	suffixMatch := "-" + cleanRef

	iter, err := repo.Tags()
	if err != nil {
		return "", false
	}
	_ = iter.ForEach(func(ref *plumbing.Reference) error {
		commitHash, ok := goGitTagCommitHash(repo, ref)
		if !ok || commitHash != head {
			return nil
		}
		name := ref.Name().Short()
		switch {
		case name == cleanRef:
			exact = append(exact, name)
		case cleanRef != "" && strings.HasSuffix(name, suffixMatch):
			suffix = append(suffix, name)
		default:
			other = append(other, name)
		}
		return nil
	})

	switch {
	case len(exact) == 1:
		return exact[0], true
	case len(suffix) == 1:
		return suffix[0], true
	case len(exact)+len(suffix) == 0 && len(other) == 1:
		return other[0], true
	default:
		return "", false
	}
}

func goGitArchivalDescribeName(tagName string, commitHash plumbing.Hash) string {
	return fmt.Sprintf("%s-0-g%s", tagName, commitHash.String()[:7])
}

func hydrateGoGitArchivalMetadata(repo *gogit.Repository, requestedRef, worktreePath string) {
	archivalPath := filepath.Join(worktreePath, ".git_archival.txt")
	if _, err := os.Stat(archivalPath); err != nil {
		return
	}

	head, err := repo.Head()
	if err != nil {
		return
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return
	}
	describeName, ok := goGitHeadTag(repo, requestedRef, commit.Hash)
	if !ok {
		debugf("Skipping .git_archival.txt hydration for %s: no unambiguous tag at HEAD\n", worktreePath)
		return
	}

	describeName = goGitArchivalDescribeName(describeName, commit.Hash)
	content := fmt.Sprintf("node: %s\nnode-date: %s\ndescribe-name: %s\n",
		commit.Hash.String(),
		commit.Committer.When.Format(time.RFC3339),
		describeName,
	)
	if err := os.WriteFile(archivalPath, []byte(content), 0o644); err != nil {
		debugf("Failed to hydrate .git_archival.txt for %s: %v\n", worktreePath, err)
	}
}

func checkoutGoGitRef(repo *gogit.Repository, ref string, quiet bool) error {
	if strings.TrimSpace(ref) == "" {
		return nil
	}

	resolve := func() *plumbing.Hash {
		for _, candidate := range goGitRefCandidates(ref) {
			resolved, err := repo.ResolveRevision(candidate.revision)
			if err == nil && resolved != nil {
				return resolved
			}
		}
		return nil
	}

	hash := resolve()
	if hash == nil {
		if err := fetchGoGitRef(repo, ref, quiet); err == nil {
			hash = resolve()
			if hash == nil {
				if tagRef, err := findGoGitSuffixTagRef(repo, ref); err == nil {
					if resolved, err := repo.ResolveRevision(plumbing.Revision(tagRef)); err == nil && resolved != nil {
						hash = resolved
					}
				}
			}
		} else {
			debugf("go-git explicit ref fetch for %s failed: %v\n", ref, err)
		}
	}
	if hash == nil {
		return fmt.Errorf("git ref %s not found", ref)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	return wt.Checkout(&gogit.CheckoutOptions{
		Hash:  *hash,
		Force: true,
	})
}

func ensureGoGitCheckout(gitURL, ref, sharedPath string, quiet bool) error {
	var repo *gogit.Repository
	if _, err := os.Stat(sharedPath); os.IsNotExist(err) {
		cloneOpts := &gogit.CloneOptions{
			URL:  gitURL,
			Tags: gogit.AllTags,
		}
		if !quiet || Debug {
			cloneOpts.Progress = os.Stderr
		}
		var cloneErr error
		repo, cloneErr = gogit.PlainClone(sharedPath, false, cloneOpts)
		if cloneErr != nil {
			return fmt.Errorf("go-git clone failed: %w", cloneErr)
		}
	} else {
		var openErr error
		repo, openErr = gogit.PlainOpen(sharedPath)
		if openErr != nil {
			_ = os.RemoveAll(sharedPath)
			return ensureGoGitCheckout(gitURL, ref, sharedPath, quiet)
		}

		fetchOpts := &gogit.FetchOptions{
			RemoteName: "origin",
			RefSpecs: []gogitconfig.RefSpec{
				"+refs/heads/*:refs/remotes/origin/*",
				"+refs/tags/*:refs/tags/*",
			},
			Tags: gogit.AllTags,
		}
		if !quiet || Debug {
			fetchOpts.Progress = os.Stderr
		}
		if err := repo.Fetch(fetchOpts); err != nil && err != gogit.NoErrAlreadyUpToDate {
			return fmt.Errorf("go-git fetch failed: %w", err)
		}
	}

	if err := checkoutGoGitRef(repo, ref, quiet); err != nil {
		return err
	}
	hydrateGoGitArchivalMetadata(repo, ref, sharedPath)
	return nil
}

func linkSharedGitCheckout(pkgName, pkgLinkDir, repoName, sharedPath string) (string, error) {
	destPath := filepath.Join(pkgLinkDir, repoName)
	if _, err := os.Lstat(destPath); err == nil {
		if err := os.RemoveAll(destPath); err != nil {
			return "", fmt.Errorf("failed to replace git checkout link for %s: %v", pkgName, err)
		}
	}
	if err := os.Symlink(sharedPath, destPath); err != nil {
		return "", fmt.Errorf("failed to link shared checkout for %s: %v", pkgName, err)
	}
	return destPath, nil
}

// downloadFile downloads a URL into the hokuto cache.

type downloadOptions struct {
	Quiet                  bool // Quiet suppresses all stdout/stderr/progress output
	Force                  bool // Force re-download even if file exists
	WgetNoCheckCertificate bool // Pass --no-check-certificate to wget fallback
	NativeAttempts         int  // Number of native HTTP attempts; zero uses the default
	NativeOnly             bool // Disable browser/wget fallbacks
}

var wgetNoCheckCertificate bool

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
	return downloadFileWithOptions(originalURL, finalURL, destFile, downloadOptions{Quiet: false, WgetNoCheckCertificate: wgetNoCheckCertificate})
}

func downloadFileQuiet(originalURL, finalURL, destFile string) error {
	return downloadFileWithOptions(originalURL, finalURL, destFile, downloadOptions{Quiet: true, WgetNoCheckCertificate: wgetNoCheckCertificate})
}

func downloadDestMatchesSourceBasename(originalURL, finalURL, destPath string) bool {
	destBase := filepath.Base(destPath)
	for _, sourceURL := range []string{originalURL, finalURL} {
		sourceBase := filepath.Base(sourceURL)
		if sourceBase == "." || sourceBase == string(filepath.Separator) || sourceBase == "" {
			continue
		}
		if destBase == sourceBase || strings.HasSuffix(destBase, "-"+sourceBase) {
			return true
		}
	}
	return false
}

func downloadFileWithOptions(originalURL, finalURL, destFile string, opt downloadOptions) (retErr error) {
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
	if strings.HasSuffix(absPath, ".lock") && !downloadDestMatchesSourceBasename(originalURL, finalURL, absPath) {
		return fmt.Errorf("refusing to download to lock file path: %s", absPath)
	}

	// Ensure parent directory exists (critical for BinDir downloads)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", absPath, err)
	}
	lockPath := absPath + ".lock"
	tmpPath := fmt.Sprintf("%s.part.%d.%d", absPath, os.Getpid(), time.Now().UnixNano())
	_ = os.Remove(tmpPath)
	defer os.Remove(tmpPath)

	// Create/Open a lock file to prevent race conditions between background prefetcher and main builder
	lFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create lock file: %w", err)
	}

	// Acquire an exclusive lock. This will block if another process/goroutine is downloading.
	if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
		_ = lFile.Close()
		return fmt.Errorf("failed to acquire lock for download: %w", err)
	}
	defer func() {
		_ = unix.Flock(int(lFile.Fd()), unix.LOCK_UN)
		_ = lFile.Close()
		// Lock files are only coordination sentinels. Keep the cache tidy and
		// clear stale failed-download locks on the next run.
		if retErr != nil {
			_ = os.Remove(lockPath)
			return
		}
		if _, err := os.Stat(absPath); err == nil {
			_ = os.Remove(lockPath)
		}
	}()

	// DOUBLE CHECK: Now that we have the lock, check if the file exists again.
	// The background worker might have finished it while we were waiting for the lock.
	if _, err := os.Stat(absPath); err == nil && !opt.Force {
		debugf("File %s appeared after acquiring lock, skipping download.\n", absPath)
		return nil
	}

	// --- Primary Choice: Native Go HTTP Client ---
	// We try native first for speed and standard behavior.
	debugf("Downloading %s -> %s\n", finalURL, absPath)

	var resp *http.Response
	var nativeErr error // Renamed to avoid shadowing the outer 'err'

	// Retry loop for download
	maxRetries := 3
	if opt.NativeAttempts > 0 {
		maxRetries = opt.NativeAttempts - 1
	}
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
				strings.HasSuffix(finalURL, ".tgz") || strings.HasSuffix(finalURL, ".zst") ||
				strings.HasSuffix(finalURL, ".tar") || strings.HasSuffix(finalURL, ".rpm") ||
				strings.HasSuffix(finalURL, ".deb") || strings.HasSuffix(finalURL, ".pkg.tar.xz") ||
				strings.HasSuffix(finalURL, ".pkg.tar.zst")

			if strings.HasPrefix(ct, "text/html") && isBinary {
				resp.Body.Close()
				nativeErr = fmt.Errorf("server returned text/html content for binary file (likely bot check or redirect page)")
				debugf("Native download got text/html for binary, falling back to browser\n")
				break
			}

			// Success! Proceed to write a temporary file, then atomically publish it.
			out, err := os.Create(tmpPath)
			if err != nil {
				resp.Body.Close()
				return fmt.Errorf("failed to create temporary destination file %s: %w", tmpPath, err)
			}

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
				_ = out.Close()
				// Write failed
				return fmt.Errorf("failed to write to destination file: %w", err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to close temporary destination file %s: %w", tmpPath, err)
			}
			if err := os.Rename(tmpPath, absPath); err != nil {
				return fmt.Errorf("failed to publish downloaded file %s: %w", absPath, err)
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

	if opt.NativeOnly {
		return nativeErr
	}

	// --- Fallback: Browser Download (chromedp) ---
	debugf("Falling back to browser download (chromedp)\n")
	browserErr := downloadViaBrowser(finalURL, tmpPath, opt.Quiet)
	if browserErr == nil {
		if err := os.Rename(tmpPath, absPath); err != nil {
			return fmt.Errorf("failed to publish browser-downloaded file %s: %w", absPath, err)
		}
		if !opt.Quiet {
			colArrow.Print("-> ")
			displayFilename := filepath.Base(finalURL)
			colSuccess.Printf("Download successful: %s\n", displayFilename)
		}
		debugf("Download successful with browser (chromedp).")
		return nil
	}

	// --- Fallback: Wget ---
	debugf("Browser download failed: %v. Falling back to wget...\n", browserErr)
	if err := downloadViaWget(finalURL, tmpPath, opt.Quiet, opt.WgetNoCheckCertificate); err == nil {
		if err := os.Rename(tmpPath, absPath); err != nil {
			return fmt.Errorf("failed to publish wget-downloaded file %s: %w", absPath, err)
		}
		if !opt.Quiet {
			colArrow.Print("-> ")
			displayFilename := filepath.Base(finalURL)
			colSuccess.Printf("Download successful (wget): %s\n", displayFilename)
		}
		debugf("Download successful with wget.\n")
		return nil
	} else {
		return fmt.Errorf("all download methods failed. Native error: %v; Browser error: %v; Wget error: %v", nativeErr, browserErr, err)
	}
}

func downloadViaWget(url, destPath string, quiet bool, noCheckCertificate bool) error {
	// check if wget is available
	if _, err := exec.LookPath("wget"); err != nil {
		return fmt.Errorf("wget not found in PATH")
	}

	args := []string{"-O", destPath}
	if noCheckCertificate {
		args = append(args, "--no-check-certificate")
	}
	args = append(args, url)
	if quiet {
		args = append(args, "-q")
	} else {
		args = append(args, "--show-progress")
	}

	// Set user agent - REMOVED to match user's successful manual test with default wget
	// args = append(args, "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	cmd := exec.Command("wget", args...)
	if quiet {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wget execution failed: %w", err)
	}
	return nil
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
						// Signal completion through foundCh
						select {
						case foundCh <- "completed":
						default:
						}
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

	// 1. Run chromedp in a separate goroutine.
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

	// 2. Wait for completion or error.
	var downloadedFile string

	// Helper to find the completed file in tmpDir
	findFile := func() string {
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			return ""
		}
		for _, entry := range entries {
			name := entry.Name()
			// Check for completed file (not crdownload or tmp)
			if !strings.HasSuffix(name, ".crdownload") && !strings.HasSuffix(name, ".tmp") {
				return filepath.Join(tmpDir, name)
			}
		}
		return ""
	}

	select {
	case <-foundCh:
		// Chromium says it's done. Now find the file.
		downloadedFile = findFile()
		if downloadedFile == "" {
			return fmt.Errorf("browser reported download complete but no file found in %s", tmpDir)
		}

	case err := <-chromeErrCh:
		// If Chrome exits, check error.
		if err != nil && !errors.Is(err, context.Canceled) {
			// Special handling for net::ERR_ABORTED
			if strings.Contains(err.Error(), "net::ERR_ABORTED") {
				debugf("Browser navigation aborted (likely download started), waiting for completion...\n")
				select {
				case <-foundCh:
					downloadedFile = findFile()
				case <-time.After(30 * time.Second): // Give it some time to finish if it was already progressing
					// Check if it finished anyway
					downloadedFile = findFile()
				}
				if downloadedFile == "" {
					return fmt.Errorf("browser download failed (aborted and no file found): %w", err)
				}
			} else {
				return fmt.Errorf("browser download failed: %w", err)
			}
		} else {
			// If Chrome exited cleanly (nil error), check for file.
			downloadedFile = findFile()
			if downloadedFile == "" {
				return fmt.Errorf("browser finished but no file was found")
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

func fetchSpecificBinaryPackage(pkgName, version, revision, variant string, cfg *Config, quiet bool, expectedSum string, force bool) error {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	if BinaryMirror == "" {
		return fmt.Errorf("no HOKUTO_MIRROR configured")
	}

	arch := GetSystemArchForPackage(cfg, lookupName)
	filename := StandardizeRemoteName(lookupName, version, revision, arch, variant)
	url := fmt.Sprintf("%s/%s", BinaryMirror, filename)
	destPath := filepath.Join(BinDir, filename)

	// Use downloadFileWithOptions to show progress if not quiet
	if err := downloadFileWithOptions(url, url, destPath, downloadOptions{Quiet: quiet, Force: force}); err != nil {
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

// fetchBinaryPackage attempts to download a binary package from the configured mirror.
func fetchBinaryPackage(pkgName, version, revision string, cfg *Config, quiet bool, expectedSum string, force bool) error {
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}
	variant := GetSystemVariantForPackage(cfg, lookupName)
	return fetchSpecificBinaryPackage(pkgName, version, revision, variant, cfg, quiet, expectedSum, force)
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
		var origFilename, hashName, cachePath, linkPath, rawSourceURL string

		parts = strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		rawSourceURL = parts[0]
		origFilename = filepath.Base(rawSourceURL)

		// --- NEW: Support "URL -> filename" syntax ---
		if len(parts) >= 3 && parts[1] == "->" {
			origFilename = parts[2]
		}

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
			gitURL := strings.TrimPrefix(rawSourceURL, "git+")
			ref := ""
			if strings.Contains(gitURL, "#") {
				subParts := strings.SplitN(gitURL, "#", 2)
				gitURL = subParts[0]
				ref = subParts[1]
			}
			parts = strings.Split(strings.TrimSuffix(gitURL, ".git"), "/")
			repoName := parts[len(parts)-1]

			// --- SHARED CHECKOUT (Working Tree) ---
			// We share the checkout between packages if they use the same URL and ref.
			checkoutsDir := filepath.Join(CacheStore, "checkouts")
			os.MkdirAll(checkoutsDir, 0o755)

			checkoutHashInput := gitURL
			if ref != "" {
				checkoutHashInput += "#" + ref
			}
			checkoutHash := hashString(checkoutHashInput)[:12]
			sharedPath := filepath.Join(checkoutsDir, repoName+"-"+checkoutHash)

			if _, err := exec.LookPath("git"); err != nil {
				err := func() error {
					lockPath := sharedPath + ".lock"
					lFile, err := os.Create(lockPath)
					if err != nil {
						return fmt.Errorf("failed to create lock file for go-git checkout: %v", err)
					}
					defer os.Remove(lockPath)
					defer lFile.Close()

					if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
						return fmt.Errorf("failed to lock go-git checkout: %v", err)
					}
					defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

					if !quiet {
						cPrintf(colInfo, "git not found; using go-git for %s@%s\n", gitURL, ref)
					}
					return ensureGoGitCheckout(gitURL, ref, sharedPath, quiet)
				}()
				if err != nil {
					return err
				}

				destPath, err := linkSharedGitCheckout(pkgName, pkgLinkDir, repoName, sharedPath)
				if err != nil {
					return err
				}
				if !quiet {
					cPrintf(colInfo, "Git repository ready (go-git): %s\n", destPath)
				}
				continue
			}

			// --- 1. SHARED BARE CACHE (objects only) ---
			gitCacheDir := filepath.Join(CacheStore, "git")
			os.MkdirAll(gitCacheDir, 0o755)

			urlHash := hashString(gitURL)[:12]
			cacheRepoPath := filepath.Join(gitCacheDir, repoName+"-"+urlHash)

			// Update/Clone bare cache
			err := func() error {
				lockPath := cacheRepoPath + ".lock"
				lFile, err := os.Create(lockPath)
				if err != nil {
					return fmt.Errorf("failed to create lock file for git cache: %v", err)
				}
				defer os.Remove(lockPath)
				defer lFile.Close()

				if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
					return fmt.Errorf("failed to lock git cache: %v", err)
				}
				defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

				if _, err := os.Stat(cacheRepoPath); os.IsNotExist(err) {
					if !quiet {
						cPrintf(colInfo, "Initializing shared git cache for %s\n", gitURL)
					}
					// Use --mirror for a complete copy of all refs in a bare repository
					cmd := exec.Command("git", "clone", "--mirror", gitURL, cacheRepoPath)
					if quiet && !Debug {
						cmd.Stdout = io.Discard
						cmd.Stderr = io.Discard
					} else {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to clone git cache: %v", err)
					}
				} else {
					// Update existing cache
					debugf("Updating shared git cache for %s\n", gitURL)
					cmd := exec.Command("git", "-C", cacheRepoPath, "remote", "update", "--prune")
					if err := cmd.Run(); err != nil {
						debugf("Warning: failed to update git cache: %v\n", err)
					}
				}
				return nil
			}()
			if err != nil {
				return err
			}

			err = func() error {
				lockPath := sharedPath + ".lock"
				lFile, err := os.Create(lockPath)
				if err != nil {
					return fmt.Errorf("failed to create lock file for shared checkout: %v", err)
				}
				defer os.Remove(lockPath)
				defer lFile.Close()

				if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
					return fmt.Errorf("failed to lock shared checkout: %v", err)
				}
				defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

				if _, err := os.Stat(sharedPath); os.IsNotExist(err) {
					if !quiet {
						cPrintf(colInfo, "Creating shared git checkout for %s@%s\n", gitURL, ref)
					}
					// Use --shared to save space (links to cache objects)
					cmd := exec.Command("git", "clone", "--shared", cacheRepoPath, sharedPath)
					if quiet && !Debug {
						cmd.Stdout = io.Discard
						cmd.Stderr = io.Discard
					} else {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}
					if err := cmd.Run(); err != nil {
						return fmt.Errorf("failed to create shared checkout from cache: %v", err)
					}
					// Reset the origin URL to the real one
					exec.Command("git", "-C", sharedPath, "remote", "set-url", "origin", gitURL).Run()
				}

				// Finalize checkout state (ref and updates)
				exec.Command("git", "-C", sharedPath, "config", "advice.detachedHead", "false").Run()
				if ref != "" {
					// Try to see if it's a branch first
					checkBranch := exec.Command("git", "-C", sharedPath, "rev-parse", "--verify", "refs/heads/"+ref)
					if err := checkBranch.Run(); err == nil {
						exec.Command("git", "-C", sharedPath, "checkout", ref).Run()
						// If it's a branch, we try to update
						debugf("Updating shared branch %s from cache\n", ref)
						exec.Command("git", "-C", sharedPath, "pull").Run()
					} else {
						// Fallback: checkout as a tag or commit hash
						exec.Command("git", "-C", sharedPath, "checkout", ref).Run()
					}
				} else {
					// If no ref, we try to update the default branch
					debugf("Updating shared default branch for %s from cache\n", gitURL)
					exec.Command("git", "-C", sharedPath, "pull").Run()
				}
				return nil
			}()
			if err != nil {
				return err
			}

			// --- 3. LINK PACKAGE TO SHARED CHECKOUT ---
			destPath, err := linkSharedGitCheckout(pkgName, pkgLinkDir, repoName, sharedPath)
			if err != nil {
				return err
			}

			if !quiet {
				cPrintf(colInfo, "Git repository ready (shared): %s\n", destPath)
			}
			continue // End git block
		}

		// --- SVN Source Logic ---
		if strings.HasPrefix(rawSourceURL, "svn+") {
			// If we are not supposed to process VCS repos (e.g., in 'checksum' command), skip.
			if !processGit {
				debugf("Skipping SVN repository for this operation: %s\n", rawSourceURL)
				continue
			}

			baseURL, repoPath, revision, err := parseSVNSourceURL(rawSourceURL)
			if err != nil {
				return fmt.Errorf("failed to parse SVN source URL: %v", err)
			}

			dirName := svnDirName(rawSourceURL)

			// --- SHARED SVN CHECKOUT LOGIC ---
			checkoutsDir := filepath.Join(CacheStore, "checkouts")
			os.MkdirAll(checkoutsDir, 0o755)

			checkoutHash := hashString(rawSourceURL)[:12]
			sharedPath := filepath.Join(checkoutsDir, dirName+"-"+checkoutHash)

			err = func() error {
				lockPath := sharedPath + ".lock"
				lFile, err := os.Create(lockPath)
				if err != nil {
					return fmt.Errorf("failed to create lock file for SVN: %v", err)
				}
				defer os.Remove(lockPath)
				defer lFile.Close()

				if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
					return fmt.Errorf("failed to lock SVN cache: %v", err)
				}
				defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

				// If the shared checkout already exists, check if revision matches
				if _, err := os.Stat(sharedPath); err == nil {
					// Check the stored revision marker
					markerPath := filepath.Join(sharedPath, ".hokuto_svn_revision")
					storedRev, readErr := os.ReadFile(markerPath)
					storedRevStr := strings.TrimSpace(string(storedRev))

					if readErr == nil && storedRevStr == revision {
						// Same revision — nothing to do
						debugf("SVN checkout already at revision %s: %s\n", revision, sharedPath)
						return nil
					}

					// Revision changed or marker missing — remove and re-checkout
					if !quiet {
						if readErr != nil {
							cPrintf(colInfo, "SVN checkout exists but has no revision marker, re-checking out\n")
						} else {
							cPrintf(colInfo, "SVN revision changed (%s -> %s), re-checking out\n", storedRevStr, revision)
						}
					}
					os.RemoveAll(sharedPath)
				}

				if !quiet {
					revStr := ""
					if revision != "" {
						revStr = fmt.Sprintf(" (revision %s)", revision)
					}
					cPrintf(colInfo, "Checking out shared SVN: %s%s%s\n", baseURL, repoPath, revStr)
				}

				if err := svnCheckout(baseURL, repoPath, revision, sharedPath, quiet); err != nil {
					// Clean up partial checkout on failure
					os.RemoveAll(sharedPath)
					return fmt.Errorf("SVN checkout failed: %v", err)
				}

				// Write revision marker for future cache validation
				if revision != "" {
					markerPath := filepath.Join(sharedPath, ".hokuto_svn_revision")
					os.WriteFile(markerPath, []byte(revision+"\n"), 0o644)
				}

				return nil
			}()
			if err != nil {
				return err
			}

			// --- LINK PACKAGE TO SHARED CHECKOUT ---
			destPath := filepath.Join(pkgLinkDir, dirName)
			if _, err := os.Lstat(destPath); err == nil {
				os.RemoveAll(destPath)
			}
			if err := os.Symlink(sharedPath, destPath); err != nil {
				return fmt.Errorf("failed to link shared SVN checkout for %s: %v", pkgName, err)
			}

			if !quiet {
				cPrintf(colInfo, "SVN checkout ready (shared): %s\n", destPath)
			}
			continue // End SVN block
		}

		// --- Mercurial Source Logic ---
		if strings.HasPrefix(rawSourceURL, "hg+") {
			// If we are not supposed to process VCS repos (e.g., in 'checksum' command), skip.
			if !processGit {
				debugf("Skipping HG repository for this operation: %s\n", rawSourceURL)
				continue
			}

			repoURL, revision, err := parseHGSourceURL(rawSourceURL)
			if err != nil {
				return fmt.Errorf("failed to parse HG source URL: %v", err)
			}

			dirName := hgDirName(rawSourceURL)

			// --- SHARED HG CHECKOUT LOGIC ---
			checkoutsDir := filepath.Join(CacheStore, "checkouts")
			os.MkdirAll(checkoutsDir, 0o755)

			checkoutHash := hashString(rawSourceURL)[:12]
			sharedPath := filepath.Join(checkoutsDir, dirName+"-"+checkoutHash)

			err = func() error {
				lockPath := sharedPath + ".lock"
				lFile, err := os.Create(lockPath)
				if err != nil {
					return fmt.Errorf("failed to create lock file for HG: %v", err)
				}
				defer os.Remove(lockPath)
				defer lFile.Close()

				if err := unix.Flock(int(lFile.Fd()), unix.LOCK_EX); err != nil {
					return fmt.Errorf("failed to lock HG cache: %v", err)
				}
				defer unix.Flock(int(lFile.Fd()), unix.LOCK_UN)

				if !quiet {
					revStr := ""
					if revision != "" {
						revStr = fmt.Sprintf(" (revision %s)", revision)
					}
					cPrintf(colInfo, "Checking out shared HG: %s%s\n", repoURL, revStr)
				}

				if err := hgCheckout(repoURL, revision, sharedPath, quiet); err != nil {
					// Clean up partial checkout on failure? Or let Mercurial handle it?
					return fmt.Errorf("HG checkout failed: %v", err)
				}

				return nil
			}()
			if err != nil {
				return err
			}

			// --- LINK PACKAGE TO SHARED CHECKOUT ---
			destPath := filepath.Join(pkgLinkDir, dirName)
			if _, err := os.Lstat(destPath); err == nil {
				os.RemoveAll(destPath)
			}
			if err := os.Symlink(sharedPath, destPath); err != nil {
				return fmt.Errorf("failed to link shared HG checkout for %s: %v", pkgName, err)
			}

			if !quiet {
				cPrintf(colInfo, "HG checkout ready (shared): %s\n", destPath)
			}
			continue // End HG block
		}

		// --- HTTP/FTP Source Logic ---
		originalSourceURL := rawSourceURL
		substitutedURL := applyGnuMirror(originalSourceURL)

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

		downloadScript := filepath.Join(pkgDir, "download")
		if _, err := os.Stat(downloadScript); err == nil {
			if err := withExclusiveDownloadLock(cachePath, func() error {
				if _, err := os.Stat(cachePath); err == nil {
					debugf("Already in cache: %s\n", cachePath)
					return nil
				}
				tmpPath := fmt.Sprintf("%s.part.%d.%d", cachePath, os.Getpid(), time.Now().UnixNano())
				_ = os.Remove(tmpPath)
				defer os.Remove(tmpPath)

				if !quiet {
					colArrow.Print("-> ")
					colSuccess.Printf("Using custom downloader for %s\n", origFilename)
				}
				cmd := exec.Command(downloadScript, originalSourceURL, tmpPath)
				cmd.Env = os.Environ()
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("custom downloader failed for %s: %v", origFilename, err)
				}
				if err := os.Rename(tmpPath, cachePath); err != nil {
					return fmt.Errorf("failed to publish custom-downloaded file %s: %w", cachePath, err)
				}
				return nil
			}); err != nil {
				return err
			}
		} else {
			downloader := downloadFile
			if quiet {
				downloader = downloadFileQuiet
			}
			// Always enter the downloader so this path honors any in-progress
			// background prefetch lock before considering the cache file complete.
			if err := downloader(originalSourceURL, substitutedURL, cachePath); err != nil {
				return fmt.Errorf("failed to download %s: %v", substitutedURL, err)
			}
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
