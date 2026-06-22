package hokuto

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/schollz/progressbar/v3"
)

type lfsPointer struct {
	Path string
	OID  string
	Size int64
}

type lfsBatchObject struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type lfsBatchRequest struct {
	Operation string           `json:"operation"`
	Transfers []string         `json:"transfers,omitempty"`
	Objects   []lfsBatchObject `json:"objects"`
}

type lfsBatchAction struct {
	Href   string            `json:"href"`
	Header map[string]string `json:"header,omitempty"`
}

type lfsBatchResponseObject struct {
	OID     string                    `json:"oid"`
	Size    int64                     `json:"size"`
	Actions map[string]lfsBatchAction `json:"actions"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type lfsBatchResponse struct {
	Objects []lfsBatchResponseObject `json:"objects"`
}

func isGoGitRepository(path string) bool {
	if _, err := gogit.PlainOpen(path); err == nil {
		return true
	}
	return false
}

func cloneRepositoryInternal(repoName, repoURL, targetPath string) error {
	_, err := gogit.PlainClone(targetPath, false, &gogit.CloneOptions{
		URL:      repoURL,
		Progress: os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("go-git clone failed for %s: %w", repoName, err)
	}
	return nil
}

func parseLFSPointer(data []byte) (lfsPointer, bool) {
	text := string(data)
	if !strings.HasPrefix(text, "version https://git-lfs.github.com/spec/v1\n") {
		return lfsPointer{}, false
	}
	var ptr lfsPointer
	hasSize := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "oid sha256:"):
			ptr.OID = strings.TrimPrefix(line, "oid sha256:")
		case strings.HasPrefix(line, "size "):
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "size "), "%d", &ptr.Size); err != nil {
				return lfsPointer{}, false
			}
			hasSize = true
		}
	}
	if ptr.OID == "" || !hasSize || ptr.Size < 0 {
		return lfsPointer{}, false
	}
	return ptr, true
}

func findLFSPointers(repoPath string) ([]lfsPointer, error) {
	var pointers []lfsPointer
	err := filepath.WalkDir(repoPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 1024 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ptr, ok := parseLFSPointer(data)
		if !ok {
			return nil
		}
		ptr.Path = path
		pointers = append(pointers, ptr)
		return nil
	})
	return pointers, err
}

func lfsBatchEndpoint(repoURL string) string {
	base := strings.TrimSuffix(repoURL, "/")
	if !strings.HasSuffix(base, ".git") {
		base += ".git"
	}
	return base + "/info/lfs/objects/batch"
}

func fetchLFSBatch(repoURL string, pointers []lfsPointer) (map[string]lfsBatchResponseObject, error) {
	reqBody := lfsBatchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   make([]lfsBatchObject, 0, len(pointers)),
	}
	for _, ptr := range pointers {
		reqBody.Objects = append(reqBody.Objects, lfsBatchObject{OID: ptr.OID, Size: ptr.Size})
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, lfsBatchEndpoint(repoURL), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.git-lfs+json")
	req.Header.Set("Content-Type", "application/vnd.git-lfs+json")

	client, err := newHttpClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("LFS batch request failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var batch lfsBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, err
	}
	objects := make(map[string]lfsBatchResponseObject, len(batch.Objects))
	for _, obj := range batch.Objects {
		objects[obj.OID] = obj
	}
	return objects, nil
}

func lfsProgressDescription(repoPath string, index, total int, ptr lfsPointer) string {
	displayPath := ptr.Path
	if rel, err := filepath.Rel(repoPath, ptr.Path); err == nil {
		displayPath = rel
	}
	if len(displayPath) > 70 {
		displayPath = "..." + displayPath[len(displayPath)-67:]
	}
	return fmt.Sprintf("   [%d/%d] %s", index, total, displayPath)
}

func newLFSProgressBar(total int64, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions64(
		total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(10*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

func downloadLFSObject(repoPath string, index, total int, ptr lfsPointer, obj lfsBatchResponseObject) error {
	if obj.Error != nil {
		return fmt.Errorf("LFS object %s unavailable: %s", ptr.OID, obj.Error.Message)
	}
	action, ok := obj.Actions["download"]
	if !ok || action.Href == "" {
		return fmt.Errorf("LFS object %s has no download action", ptr.OID)
	}
	req, err := http.NewRequest(http.MethodGet, action.Href, nil)
	if err != nil {
		return err
	}
	for k, v := range action.Header {
		req.Header.Set(k, v)
	}
	client, err := newHttpClient()
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("LFS download failed for %s: %s", ptr.OID, resp.Status)
	}

	tmpPath := ptr.Path + ".hokuto-lfs"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	bar := newLFSProgressBar(ptr.Size, lfsProgressDescription(repoPath, index, total, ptr))
	written, copyErr := io.Copy(io.MultiWriter(out, hasher, bar), resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if written != ptr.Size {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("LFS object %s size mismatch: got %d, want %d", ptr.OID, written, ptr.Size)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != ptr.OID {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("LFS object %s checksum mismatch: got %s", ptr.OID, got)
	}
	info, err := os.Stat(ptr.Path)
	if err == nil {
		_ = os.Chmod(tmpPath, info.Mode().Perm())
	}
	return os.Rename(tmpPath, ptr.Path)
}

func resolveRepositoryLFS(repoName, repoURL, repoPath string) error {
	pointers, err := findLFSPointers(repoPath)
	if err != nil {
		return err
	}
	if len(pointers) == 0 {
		debugf("No LFS pointer files found for %s\n", repoName)
		return nil
	}

	return downloadRepositoryLFS(repoName, repoURL, repoPath, pointers)
}

func maybeResolveRepositoryLFS(repoName, repoURL, repoPath string, checkoutLFS *bool, askedLFS *bool) error {
	pointers, err := findLFSPointers(repoPath)
	if err != nil {
		return err
	}
	if len(pointers) == 0 {
		debugf("No missing LFS objects found for %s\n", repoName)
		return nil
	}

	if !*askedLFS {
		colArrow.Print("-> ")
		*checkoutLFS = askForConfirmation(colSuccess, "Checkout Git LFS objects now?")
		*askedLFS = true
	}
	if !*checkoutLFS {
		colArrow.Print("-> ")
		colWarn.Printf("Skipping %d LFS assets for %s\n", len(pointers), repoName)
		return nil
	}

	return downloadRepositoryLFS(repoName, repoURL, repoPath, pointers)
}

func downloadRepositoryLFS(repoName, repoURL, repoPath string, pointers []lfsPointer) error {
	colArrow.Print("-> ")
	colSuccess.Printf("Downloading %d LFS assets for %s\n", len(pointers), repoName)
	objects, err := fetchLFSBatch(repoURL, pointers)
	if err != nil {
		return err
	}
	for i, ptr := range pointers {
		obj, ok := objects[ptr.OID]
		if !ok {
			return fmt.Errorf("LFS batch response missing object %s", ptr.OID)
		}
		if err := downloadLFSObject(repoPath, i+1, len(pointers), ptr, obj); err != nil {
			return err
		}
	}
	return nil
}

func handleInitReposCommand(cfg *Config) error {
	rootDir := cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}
	repoDir := filepath.Join(rootDir, "repo")

	repos := []string{"sauzeros", "kde", "cosmic"}
	urls := map[string]string{
		"sauzeros": "https://github.com/sauzerOS/sauzeros",
		"kde":      "https://github.com/sauzerOS/kde",
		"cosmic":   "https://github.com/sauzerOS/cosmic",
	}

	// 1. Check for existing directories
	for _, repo := range repos {
		path := filepath.Join(repoDir, repo)
		if _, err := os.Stat(path); err == nil {
			if isGoGitRepository(path) {
				colArrow.Print("-> ")
				colInfo.Printf("Using existing git repository: %s\n", path)
				continue
			}

			// If it exists but is not a git repo, remove it
			colArrow.Print("-> ")
			colWarn.Printf("Removing non-git directory: %s\n", path)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(path); err != nil {
					return fmt.Errorf("failed to remove existing directory %s natively: %v", path, err)
				}
			} else {
				if err := os.RemoveAll(path); err != nil {
					// Fallback to RootExec (rm -rf) if Go's os.RemoveAll fails (likely permission issue)
					rmCmd := exec.Command("rm", "-rf", path)
					if err := RootExec.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove existing directory %s: %v", path, err)
					}
				}
			}
		}
	}

	// 3. Optional repos
	colArrow.Print("-> ")
	enableKDE := askForConfirmation(colSuccess, "Enable KDE repository?")
	colArrow.Print("-> ")
	enableCosmic := askForConfirmation(colSuccess, "Enable Cosmic repository?")

	// 4. Create repo directory if it doesn't exist
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		colArrow.Print("-> ")
		colInfo.Printf("Creating repository directory: %s\n", repoDir)
		if os.Geteuid() == 0 {
			if err := os.MkdirAll(repoDir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s natively: %v", repoDir, err)
			}
		} else {
			if err := os.MkdirAll(repoDir, 0o755); err != nil {
				mkdirCmd := exec.Command("mkdir", "-p", repoDir)
				if err := RootExec.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", repoDir, err)
				}
			}
		}
	}

	// Ensure the repo directory is owned by the current user
	uid := os.Getuid()
	gid := os.Getgid()
	if os.Geteuid() == 0 {
		if err := os.Chown(repoDir, uid, gid); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to set ownership of %s natively: %v\n", repoDir, err)
		}
	} else {
		chownCmd := exec.Command("chown", "-R", fmt.Sprintf("%d:%d", uid, gid), repoDir)
		if err := RootExec.Run(chownCmd); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to set ownership of %s: %v\n", repoDir, err)
		}
	}

	// 5. Clone the repositories
	enabledRepos := []string{"sauzeros"}
	if enableKDE {
		enabledRepos = append(enabledRepos, "kde")
	}
	if enableCosmic {
		enabledRepos = append(enabledRepos, "cosmic")
	}

	checkoutLFS := false
	askedLFS := false
	for _, repo := range enabledRepos {
		targetPath := filepath.Join(repoDir, repo)
		url := urls[repo]

		if isGoGitRepository(targetPath) {
			colArrow.Print("-> ")
			colSuccess.Printf("Repository %s already initialized at %s\n", repo, targetPath)
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Cloning %s repository from %s\n", repo, url)
			if err := cloneRepositoryInternal(repo, url, targetPath); err != nil {
				return fmt.Errorf("failed to clone %s: %v", repo, err)
			}
		}

		if repo == "sauzeros" {
			// Update cfg.Values["HOKUTO_PATH"] temporarily to include the new repo
			oldPath := cfg.Values["HOKUTO_PATH"]
			if oldPath == "" {
				cfg.Values["HOKUTO_PATH"] = targetPath
			} else if !strings.Contains(oldPath, targetPath) {
				cfg.Values["HOKUTO_PATH"] = oldPath + ":" + targetPath
			}
			// Refresh repo paths in the global variable too
			repoPaths = cfg.Values["HOKUTO_PATH"]
		}

		if err := maybeResolveRepositoryLFS(repo, url, targetPath, &checkoutLFS, &askedLFS); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to download LFS assets for %s: %v\n", repo, err)
		}

		// Install git hooks
		if err := installGitHooks(targetPath); err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to install git hooks for %s: %v\n", repo, err)
		}
	}

	colArrow.Print("-> ")
	colSuccess.Println("Repositories initialized successfully.")

	// 6. Update config file
	if err := updateHokutoConfig(rootDir, enableKDE, enableCosmic); err != nil {
		colArrow.Print("-> ")
		colWarn.Printf("Warning: failed to update config file: %v\n", err)
	} else {
		colArrow.Print("-> ")
		colSuccess.Println("Configuration file updated.")
	}

	return nil
}

func installGitHooks(repoPath string) error {
	hooksDir := filepath.Join(repoPath, ".git", "hooks")
	if _, err := os.Stat(hooksDir); os.IsNotExist(err) {
		if err := os.MkdirAll(hooksDir, 0755); err != nil {
			return fmt.Errorf("failed to create hooks directory: %w", err)
		}
	}

	// 1. Write the script file
	scriptPath := filepath.Join(hooksDir, "git-hook-prepare-commit-msg")
	data, err := embeddedAssets.ReadFile("assets/git-hook-prepare-commit-msg")
	if err != nil {
		return fmt.Errorf("failed to read embedded hook script: %w", err)
	}
	if err := os.WriteFile(scriptPath, data, 0755); err != nil {
		return fmt.Errorf("failed to write hook script: %w", err)
	}

	// 2. Symlink prepare-commit-msg -> git-hook-prepare-commit-msg
	linkPath := filepath.Join(hooksDir, "prepare-commit-msg")
	// Remove if exists to be safe
	_ = os.Remove(linkPath)
	if err := os.Symlink("git-hook-prepare-commit-msg", linkPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	// 3. Ensure ownership if running as root
	// 3. Ensure ownership if running as root
	if os.Geteuid() == 0 {
		// Use the ownership of the repo directory to match
		info, err := os.Stat(repoPath)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok {
				uid := int(stat.Uid)
				gid := int(stat.Gid)
				_ = os.Chown(scriptPath, uid, gid)
				_ = os.Chown(linkPath, uid, gid) // lchown usually
				// Note: os.Chown on symlink might behave differently on Linux (usually changes target).
				// We should use os.Lchown for link.
				_ = os.Lchown(linkPath, uid, gid)
			}
		}
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Installed git hooks in %s\n", hooksDir)
	return nil
}

func updateHokutoConfig(rootDir string, enableKDE, enableCosmic bool) error {
	configPath := filepath.Join(rootDir, "etc", "hokuto", "hokuto.conf")

	// Base paths
	basePath := "/repo/sauzeros/core:/repo/sauzeros/extra"
	if enableKDE {
		basePath += ":/repo/kde"
	}
	if enableCosmic {
		basePath += ":/repo/cosmic"
	}

	newLine := fmt.Sprintf("HOKUTO_PATH=%s", basePath)

	var lines []string
	found := false

	// Try reading existing config
	data, err := os.ReadFile(configPath)
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "HOKUTO_PATH=") {
				lines = append(lines, newLine)
				found = true
			} else {
				lines = append(lines, line)
			}
		}
	}

	if !found {
		lines = append(lines, newLine)
	}

	newContent := strings.Join(lines, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}

	// Write back using RootExec to ensure we have permissions
	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("hokuto.conf.tmp.%d", os.Getpid()))
	if err := os.WriteFile(tmpFile, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("failed to create temporary config file: %v", err)
	}

	// Ensure etc dir exists
	etcDir := filepath.Join(rootDir, "etc")
	if _, err := os.Stat(etcDir); os.IsNotExist(err) {
		mkdirCmd := exec.Command("mkdir", "-p", etcDir)
		if err := RootExec.Run(mkdirCmd); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to create etc directory: %v", err)
		}
	}

	if os.Geteuid() == 0 {
		if err := copyFile(tmpFile, configPath); err != nil {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("failed to update config file natively: %v", err)
		}
		_ = os.Remove(tmpFile)
	} else {
		mvCmd := exec.Command("mv", tmpFile, configPath)
		if err := RootExec.Run(mvCmd); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("failed to update config file: %v", err)
		}
	}

	return nil
}
