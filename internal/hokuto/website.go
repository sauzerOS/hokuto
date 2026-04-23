package hokuto

import (
	"encoding/json"
	"fmt"
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
}

// UpdateWebsiteStatus updates the packages.json and uploads the build log to the website repository.
func UpdateWebsiteStatus(pkgName, version, status, logPath string) error {
	websiteRepo := "/home/dbz/Documents/sauzerOS.github.io"
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

	// 2. Handle log file first to get the filename
	var logRelPath string
	if logPath != "" {
		if _, err := os.Stat(logPath); err == nil {
			// Extract/Copy log
			logFileName := fmt.Sprintf("%s-%s.txt", pkgName, version)
			dstLogPath := filepath.Join(logsDir, logFileName)
			
			// If it's a .xz file, decompress it
			if strings.HasSuffix(logPath, ".xz") {
				// Use xz -dc to decompress to stdout and redirect to target file
				cmd := exec.Command("sh", "-c", fmt.Sprintf("xz -dc %s > %s", logPath, dstLogPath))
				if err := cmd.Run(); err != nil {
					debugf("Warning: failed to decompress log %s: %v\n", logPath, err)
					// Fallback to plain copy (it will be binary but at least something is there)
					cpCmd := exec.Command("cp", logPath, dstLogPath)
					cpCmd.Run()
				}
			} else {
				cpCmd := exec.Command("cp", logPath, dstLogPath)
				cpCmd.Run()
			}
			logRelPath = "logs/" + logFileName
		}
	}

	// 3. Update or add package
	found := false
	for i, p := range packages {
		if p.PkgName == pkgName {
			packages[i].Version = version
			packages[i].Status = status
			if logRelPath != "" {
				packages[i].Log = logRelPath
			}
			found = true
			break
		}
	}
	if !found {
		packages = append(packages, PackageStatus{
			PkgName: pkgName,
			Version: version,
			Status:  status,
			Log:     logRelPath,
		})
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
	addCmd := exec.Command("git", "-C", websiteRepo, "add", "packages.json", "logs/")
	if err := addCmd.Run(); err != nil {
		debugf("Warning: git add failed in website repo: %v\n", err)
	}
	
	commitMsg := fmt.Sprintf("Update status for %s %s (%s)", pkgName, version, status)
	commitCmd := exec.Command("git", "-C", websiteRepo, "commit", "-m", commitMsg)
	if err := commitCmd.Run(); err != nil {
		// Commit might fail if there are no changes, which is fine
		debugf("Note: git commit skipped or failed: %v\n", err)
	}
	
	pushCmd := exec.Command("git", "-C", websiteRepo, "push")
	if err := pushCmd.Run(); err != nil {
		return fmt.Errorf("failed to push to website repo: %v", err)
	}

	return nil
}
