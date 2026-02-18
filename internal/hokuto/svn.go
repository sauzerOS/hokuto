package hokuto

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// svnEntry represents a single resource discovered via WebDAV PROPFIND.
type svnEntry struct {
	Href         string
	IsCollection bool // true = directory, false = file
	ContentLen   int64
}

// svnMultistatus is the top-level XML element returned by a PROPFIND response.
type svnMultistatus struct {
	XMLName   xml.Name      `xml:"multistatus"`
	Responses []svnResponse `xml:"response"`
}

// svnResponse is a single <D:response> inside a multistatus.
type svnResponse struct {
	Href      string        `xml:"href"`
	PropStats []svnPropStat `xml:"propstat"`
}

// svnPropStat holds properties and a status for each <D:propstat>.
type svnPropStat struct {
	Prop   svnProp `xml:"prop"`
	Status string  `xml:"status"`
}

// svnProp holds the actual property values we care about.
type svnProp struct {
	ResourceType svnResourceType `xml:"resourcetype"`
	ContentLen   int64           `xml:"getcontentlength"`
}

// svnResourceType wraps the <D:resourcetype> which contains <D:collection/> for directories.
type svnResourceType struct {
	Collection *struct{} `xml:"collection"`
}

// parseSVNSourceURL parses a source URL of the form:
//
//	svn+https://host/path/to/repo/trunk/dir#revision=NNNN
//
// Returns: scheme (https), base URL, path within the repo, revision string (or "").
func parseSVNSourceURL(rawURL string) (baseURL string, repoPath string, revision string, err error) {
	// Strip the "svn+" prefix to get the real URL
	realURL := strings.TrimPrefix(rawURL, "svn+")

	// Split off the fragment (#revision=NNNN)
	revision = ""
	if idx := strings.Index(realURL, "#"); idx != -1 {
		fragment := realURL[idx+1:]
		realURL = realURL[:idx]
		if strings.HasPrefix(fragment, "revision=") {
			revision = strings.TrimPrefix(fragment, "revision=")
		}
	}

	// Parse the URL to extract scheme + host
	u, err := url.Parse(realURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid SVN URL: %w", err)
	}

	baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	repoPath = strings.TrimSuffix(u.Path, "/")

	return baseURL, repoPath, revision, nil
}

// svnDirName returns the directory name from the SVN source URL path.
// For example, "svn+https://svn.code.sf.net/p/lame/svn/trunk/lame" -> "lame"
func svnDirName(rawURL string) string {
	// Strip fragment
	clean := rawURL
	if idx := strings.Index(clean, "#"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimSuffix(clean, "/")
	parts := strings.Split(clean, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "svn-source"
}

// svnPropfind sends a PROPFIND request with Depth:1 to list the immediate
// children of the given path. Returns a slice of svnEntry.
func svnPropfind(client *http.Client, baseURL, path string) ([]svnEntry, error) {
	propfindBody := `<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
  <prop>
    <resourcetype/>
    <getcontentlength/>
  </prop>
</propfind>`

	fullURL := baseURL + path
	req, err := http.NewRequest("PROPFIND", fullURL, strings.NewReader(propfindBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create PROPFIND request: %w", err)
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("User-Agent", "hokuto/svn (Go)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PROPFIND request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 207 {
		return nil, fmt.Errorf("PROPFIND returned status %d for %s", resp.StatusCode, fullURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read PROPFIND response: %w", err)
	}

	var ms svnMultistatus
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("failed to parse PROPFIND XML: %w", err)
	}

	var entries []svnEntry
	for _, r := range ms.Responses {
		href := r.Href
		isCollection := false
		var contentLen int64

		for _, ps := range r.PropStats {
			if !strings.Contains(ps.Status, "200") {
				continue
			}
			if ps.Prop.ResourceType.Collection != nil {
				isCollection = true
			}
			contentLen = ps.Prop.ContentLen
		}

		entries = append(entries, svnEntry{
			Href:         href,
			IsCollection: isCollection,
			ContentLen:   contentLen,
		})
	}

	return entries, nil
}

// svnDownloadFile downloads a single file from the SVN server via HTTP GET.
func svnDownloadFile(client *http.Client, baseURL, remotePath, localPath string) error {
	fullURL := baseURL + remotePath

	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", localPath, err)
	}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "hokuto/svn (Go)")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET failed for %s: %w", fullURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GET returned status %d for %s", resp.StatusCode, fullURL)
	}

	out, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", localPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		os.Remove(localPath)
		return fmt.Errorf("failed to write file %s: %w", localPath, err)
	}

	return nil
}

// svnCheckout performs a full recursive checkout of an SVN directory tree
// via WebDAV PROPFIND + HTTP GET. It writes into destDir.
//
// Parameters:
//   - baseURL: scheme://host (e.g. "https://svn.code.sf.net")
//   - repoPath: the path within the repo (e.g. "/p/lame/svn/trunk/lame")
//   - revision: if non-empty, the revision to pin to (uses !svn/bc/REV prefix)
//   - destDir: local directory to write files into
//   - quiet: suppress progress output
//
// The function uses concurrent downloads (up to 8 parallel) for performance.
func svnCheckout(baseURL, repoPath, revision, destDir string, quiet bool) error {
	client := &http.Client{}

	// Determine the PROPFIND/GET base path.
	// If a revision is specified, we access the tree via !svn/bc/REVISION/path.
	// The "repo root" is needed: for sourceforge, the URL is like
	// https://svn.code.sf.net/p/lame/svn/trunk/lame
	// The repo root in DAV is typically discoverable, but for simplicity we use
	// a heuristic: try to find the "!svn" capable prefix.
	//
	// With !svn/bc/REV: the full access path becomes /p/lame/svn/!svn/bc/6531/trunk/lame
	// We need to figure out where the "svn repo root" ends and the "in-repo path" begins.
	// Strategy: we use an OPTIONS request to discover svn repo root, or we use the
	// revision path directly since we know the format.

	var accessPath string
	if revision != "" {
		// We need to discover the repository root to correctly insert !svn/bc/REVISION.
		repoRoot, inRepoPath, err := svnDiscoverRepoRoot(client, baseURL, repoPath, revision)
		if err != nil {
			return fmt.Errorf("failed to discover SVN repository root: %w", err)
		}
		accessPath = repoRoot + "/!svn/bc/" + revision + inRepoPath
		debugf("SVN: Using revision %s, access path: %s\n", revision, accessPath)
	} else {
		accessPath = repoPath
	}

	// Collect all files to download by walking the tree
	type fileEntry struct {
		remotePath string // full path on server for GET
		localPath  string // local filesystem path
	}

	var files []fileEntry
	var walkErr error

	// Recursive walk using PROPFIND with Depth:1
	var walk func(dirPath string, localBase string) error
	walk = func(dirPath string, localBase string) error {
		entries, err := svnPropfind(client, baseURL, dirPath)
		if err != nil {
			return err
		}

		// The first entry is the directory itself, skip it
		for i, entry := range entries {
			// Normalize: the first entry's href matches the requested directory
			entryPath := entry.Href
			if i == 0 {
				// Skip the directory entry itself
				continue
			}

			// Derive the filename/dirname from the Href
			name := filepath.Base(strings.TrimSuffix(entryPath, "/"))
			if name == "" || name == "." {
				continue
			}

			if entry.IsCollection {
				// Recurse into subdirectory
				subDir := filepath.Join(localBase, name)
				if err := walk(entryPath, subDir); err != nil {
					return err
				}
			} else {
				// It's a file — add to download list
				localFile := filepath.Join(localBase, name)
				files = append(files, fileEntry{
					remotePath: entryPath,
					localPath:  localFile,
				})
			}
		}
		return nil
	}

	walkErr = walk(accessPath, destDir)
	if walkErr != nil {
		return fmt.Errorf("failed to walk SVN tree: %w", walkErr)
	}

	if len(files) == 0 {
		return fmt.Errorf("no files found in SVN path %s", repoPath)
	}

	if !quiet {
		cPrintf(colInfo, "SVN: Found %d files to download\n", len(files))
	}

	// Download files concurrently (up to 8 at a time)
	const maxConcurrency = 8
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var downloadErrors []string
	var errMu sync.Mutex
	var downloaded int64

	for _, f := range files {
		sem <- struct{}{}
		wg.Add(1)
		go func(fe fileEntry) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := svnDownloadFile(client, baseURL, fe.remotePath, fe.localPath); err != nil {
				errMu.Lock()
				downloadErrors = append(downloadErrors, fmt.Sprintf("%s: %v", fe.remotePath, err))
				errMu.Unlock()
				return
			}

			count := atomic.AddInt64(&downloaded, 1)
			if !quiet && count%50 == 0 {
				cPrintf(colInfo, "SVN: Downloaded %d/%d files...\n", count, len(files))
			}
		}(f)
	}

	wg.Wait()

	if len(downloadErrors) > 0 {
		return fmt.Errorf("SVN download had %d errors:\n  %s", len(downloadErrors), strings.Join(downloadErrors, "\n  "))
	}

	if !quiet {
		cPrintf(colInfo, "SVN: Successfully downloaded %d files\n", len(files))
	}

	return nil
}

// svnDiscoverRepoRoot discovers the SVN repository root by sending OPTIONS
// requests and looking for the SVN-specific header "SVN-Repository-Root".
// Falls back to a heuristic if the header is not available.
// The revision parameter is used for the heuristic fallback (some proxies strip SVN headers).
func svnDiscoverRepoRoot(client *http.Client, baseURL, repoPath, revision string) (repoRoot string, inRepoPath string, err error) {
	fullURL := baseURL + repoPath

	req, err := http.NewRequest("OPTIONS", fullURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "hokuto/svn (Go)")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("OPTIONS request failed: %w", err)
	}
	defer resp.Body.Close()

	// mod_dav_svn returns "SVN-Repository-Root" header
	svnRoot := resp.Header.Get("SVN-Repository-Root")
	if svnRoot != "" {
		// The header value is a full URL, e.g., "https://svn.code.sf.net/p/lame/svn"
		// Parse it to get just the path portion
		rootURL, err := url.Parse(svnRoot)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse SVN-Repository-Root: %w", err)
		}
		rootPath := strings.TrimSuffix(rootURL.Path, "/")

		if strings.HasPrefix(repoPath, rootPath) {
			inRepoPath = strings.TrimPrefix(repoPath, rootPath)
			if inRepoPath == "" {
				inRepoPath = "/"
			}
			return rootPath, inRepoPath, nil
		}
	}

	// Fallback heuristic: try inserting !svn/bc/REVISION at different path splits
	// to discover where the repo root ends and the in-repo path begins.
	// Example: for /p/lame/svn/trunk/lame, the repo root is /p/lame/svn
	// so the correct path is /p/lame/svn/!svn/bc/REVISION/trunk/lame
	debugf("SVN: SVN-Repository-Root header not found, falling back to heuristic\n")

	// Use the actual revision for testing; fall back to HEAD (no !svn/bc prefix) if no revision
	testRevision := revision
	if testRevision == "" {
		testRevision = "HEAD"
	}

	// Try progressively longer root paths
	parts := strings.Split(strings.TrimPrefix(repoPath, "/"), "/")
	for i := 1; i < len(parts); i++ {
		tryRoot := "/" + strings.Join(parts[:i], "/")
		tryInRepo := "/" + strings.Join(parts[i:], "/")

		// Try to PROPFIND the !svn/bc/REVISION path to see if this split is correct
		testPath := tryRoot + "/!svn/bc/" + testRevision + tryInRepo
		debugf("SVN heuristic: trying %s\n", testPath)
		testReq, err := http.NewRequest("PROPFIND", baseURL+testPath, strings.NewReader(
			`<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>`))
		if err != nil {
			continue
		}
		testReq.Header.Set("Depth", "0")
		testReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
		testReq.Header.Set("User-Agent", "hokuto/svn (Go)")

		testResp, err := client.Do(testReq)
		if err != nil {
			continue
		}
		testResp.Body.Close()

		if testResp.StatusCode == 207 {
			debugf("SVN: Discovered repo root via heuristic: %s (in-repo: %s)\n", tryRoot, tryInRepo)
			return tryRoot, tryInRepo, nil
		}
	}

	return "", "", fmt.Errorf("could not determine SVN repository root for %s", repoPath)
}
