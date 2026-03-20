package hokuto

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// parseHGSourceURL parses a Mercurial source URL and extracts the repo URL and revision.
// Supported formats:
//   hg+https://host/repo#tag=TAG
//   hg+https://host/repo#branch=BRANCH
//   hg+https://host/repo#revision=REV
//   hg+https://host/repo#REV
func parseHGSourceURL(rawURL string) (hgURL string, revision string, err error) {
	realURL := strings.TrimPrefix(rawURL, "hg+")

	revision = ""
	if idx := strings.Index(realURL, "#"); idx != -1 {
		revision = realURL[idx+1:]
		hgURL = realURL[:idx]

		// Handle tag=, branch=, revision= prefixes by stripping them
		if strings.HasPrefix(revision, "tag=") {
			revision = strings.TrimPrefix(revision, "tag=")
		} else if strings.HasPrefix(revision, "branch=") {
			revision = strings.TrimPrefix(revision, "branch=")
		} else if strings.HasPrefix(revision, "revision=") {
			revision = strings.TrimPrefix(revision, "revision=")
		}
	} else {
		hgURL = realURL
	}

	return hgURL, revision, nil
}

// hgDirName returns a suitable directory name for the Mercurial repository.
func hgDirName(rawURL string) string {
	clean := rawURL
	if idx := strings.Index(clean, "#"); idx != -1 {
		clean = clean[:idx]
	}
	clean = strings.TrimSuffix(clean, "/")
	parts := strings.Split(clean, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name == "" && len(parts) > 1 {
			name = parts[len(parts)-2]
		}
		if name != "" {
			return name
		}
	}
	return "hg-source"
}

// hgCheckout clones or updates a Mercurial repository.
func hgCheckout(repoURL, revision, destDir string, quiet bool) error {
	// Ensure hg is available
	if _, err := exec.LookPath("hg"); err != nil {
		return fmt.Errorf("mercurial (hg) binary not found in PATH")
	}

	if _, err := os.Stat(destDir); os.IsNotExist(err) {
		// Clone if not exists
		args := []string{"clone"}
		if revision != "" {
			args = append(args, "-r", revision)
		}
		args = append(args, repoURL, destDir)

		cmd := exec.Command("hg", args...)
		if quiet && !Debug {
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
		} else {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("hg clone failed: %w", err)
		}
	} else {
		// Update existing repo
		// 1. Pull latest changes
		pullCmd := exec.Command("hg", "-R", destDir, "pull")
		if quiet && !Debug {
			pullCmd.Stdout = io.Discard
			pullCmd.Stderr = io.Discard
		} else {
			pullCmd.Stdout = os.Stdout
			pullCmd.Stderr = os.Stderr
		}
		if err := pullCmd.Run(); err != nil {
			debugf("Warning: hg pull failed: %v\n", err)
		}

		// 2. Update to the desired revision
		updateArgs := []string{"-R", destDir, "update", "-C"} // -C for clean update
		if revision != "" {
			updateArgs = append(updateArgs, "-r", revision)
		}

		updateCmd := exec.Command("hg", updateArgs...)
		if quiet && !Debug {
			updateCmd.Stdout = io.Discard
			updateCmd.Stderr = io.Discard
		} else {
			updateCmd.Stdout = os.Stdout
			updateCmd.Stderr = os.Stderr
		}
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("hg update failed: %w", err)
		}
	}

	return nil
}
