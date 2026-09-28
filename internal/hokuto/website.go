package hokuto

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type PackageStatus struct {
	PkgName string `json:"pkgname"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Log     string `json:"log,omitempty"`
	// Logs lists the kept logs, newest first; Log is Logs[0].
	Logs []string `json:"logs,omitempty"`
}

// websiteLogsKept is how many build logs per package stay on the site. Older
// ones are deleted from the checkout (git history keeps them); GitHub Pages
// sites are limited to 1 GB.
const websiteLogsKept = 3

// writeWebsiteLog stores a build log gzip-compressed; log.html decompresses
// it in the browser. hokuto's own logs are xz files and are recompressed.
func writeWebsiteLog(src, dst string) (err error) {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	if strings.HasSuffix(src, ".xz") {
		cmd := exec.Command("xz", "-dc", src)
		cmd.Stdout = gz
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("xz -dc %s: %w", src, err)
		}
	} else {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		_, err = io.Copy(gz, in)
		in.Close()
		if err != nil {
			return err
		}
	}
	return gz.Close()
}

// recordWebsiteLog makes logRelPath the newest log of entry and returns the
// logs that fall out of the kept window.
func recordWebsiteLog(entry *PackageStatus, logRelPath string) []string {
	history := entry.Logs
	if len(history) == 0 && entry.Log != "" {
		history = []string{entry.Log} // entries from before the history existed
	}
	kept := []string{logRelPath}
	for _, old := range history {
		if old != logRelPath {
			kept = append(kept, old)
		}
	}
	var dropped []string
	if len(kept) > websiteLogsKept {
		dropped = kept[websiteLogsKept:]
		kept = kept[:websiteLogsKept]
	}
	entry.Logs = kept
	entry.Log = logRelPath
	return dropped
}

// defaultWebsiteRepo is the sauzerOS.github.io checkout used when
// HOKUTO_WEBSITE_REPO is not set in hokuto.conf.
const defaultWebsiteRepo = "/home/dbz/Documents/sauzerOS.github.io"

// WebsiteRepo is the website checkout build status and logs are pushed to.
var WebsiteRepo = defaultWebsiteRepo

// UpdateWebsiteStatus updates the packages.json and uploads the build log to the website repository.
func UpdateWebsiteStatus(pkgName, version, status, logPath string) error {
	websiteRepo := WebsiteRepo
	// Without the checkout (e.g. a build container that does not mount it)
	// there is nothing to update; creating directories there would only
	// leave a stray tree behind.
	if _, err := os.Stat(filepath.Join(websiteRepo, ".git")); err != nil {
		colWarn.Printf("Warning: website repository %s not found; build status for %s not published\n", websiteRepo, pkgName)
		return nil
	}
	jsonPath := filepath.Join(websiteRepo, "packages.json")
	logsDir := filepath.Join(websiteRepo, "logs")

	// Ensure logs directory exists
	os.MkdirAll(logsDir, 0755)

	// 1. Read existing JSON
	var packages []PackageStatus
	data, err := os.ReadFile(jsonPath)
	if err == nil {
		if err := json.Unmarshal(data, &packages); err != nil {
			debugf("Warning: failed to unmarshal packages.json: %v\n", err)
			packages = []PackageStatus{}
		}
	} else {
		packages = []PackageStatus{}
	}

	// 2. Store the log, gzip-compressed
	var logRelPath string
	if logPath != "" {
		if _, err := os.Stat(logPath); err == nil {
			logFileName := fmt.Sprintf("%s-%s.txt.gz", pkgName, version)
			if err := writeWebsiteLog(logPath, filepath.Join(logsDir, logFileName)); err != nil {
				colWarn.Printf("Warning: failed to store build log for %s: %v\n", pkgName, err)
			} else {
				logRelPath = "logs/" + logFileName
			}
		}
	}

	// 3. Update or add package, keeping its last websiteLogsKept logs
	index := -1
	for i, p := range packages {
		if p.PkgName == pkgName {
			index = i
			break
		}
	}
	if index < 0 {
		packages = append(packages, PackageStatus{PkgName: pkgName})
		index = len(packages) - 1
	}
	packages[index].Version = version
	packages[index].Status = status
	if logRelPath != "" {
		for _, old := range recordWebsiteLog(&packages[index], logRelPath) {
			if err := os.Remove(filepath.Join(websiteRepo, old)); err != nil && !errors.Is(err, os.ErrNotExist) {
				debugf("Warning: failed to remove old log %s: %v\n", old, err)
			}
		}
	}

	// 4. Save JSON
	newData, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(jsonPath, newData, 0644); err != nil {
		return fmt.Errorf("failed to write packages.json: %v", err)
	}

	// 5. Commit and push
	// We use git -C to run it in the website repo
	// -A also stages the logs removed above.
	addCmd := exec.Command("git", "-C", websiteRepo, "add", "-A", "--", "packages.json", "logs")
	if err := addCmd.Run(); err != nil {
		debugf("Warning: git add failed in website repo: %v\n", err)
	}

	commitMsg := fmt.Sprintf("Update status for %s %s (%s)", pkgName, version, status)
	commitCmd := exec.Command("git", "-C", websiteRepo, "commit", "-m", commitMsg)
	if err := commitCmd.Run(); err != nil {
		// Commit might fail if there are no changes, which is fine
		debugf("Note: git commit skipped or failed: %v\n", err)
	}

	// The site's package-index workflow commits repo.json on its own, so
	// rebase onto it before pushing; retry if one lands in between.
	var pushErr error
	for attempt := 1; attempt <= 3; attempt++ {
		pullCmd := exec.Command("git", "-C", websiteRepo, "pull", "--rebase", "--autostash", "--quiet")
		if out, err := pullCmd.CombinedOutput(); err != nil {
			debugf("Warning: git pull --rebase failed in website repo: %v: %s\n", err, strings.TrimSpace(string(out)))
		}
		out, err := exec.Command("git", "-C", websiteRepo, "push", "--quiet").CombinedOutput()
		if err == nil {
			return nil
		}
		pushErr = fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return fmt.Errorf("failed to push to website repo: %v", pushErr)
}
