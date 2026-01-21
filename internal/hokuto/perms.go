package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

// ensureHokutoOwnership checks if critical Hokuto directories are owned by the correct user
// (SUDO_USER or current user) and group (wheel). If not, it attempts to fix them via chown.
func ensureHokutoOwnership(cfg *Config) error {
	// 0. Skip if already root
	if os.Geteuid() == 0 {
		return nil
	}

	// 1. Determine target user and group
	targetUser := os.Getenv("SUDO_USER")
	if targetUser == "" {
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}
		targetUser = currentUser.Username
	}

	// We strictly require 'wheel' group.
	targetGroup := "wheel"

	// Resolve UID/GID for comparison
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", targetUser, err)
	}
	targetUID := u.Uid
	g, err := user.LookupGroup(targetGroup)
	if err != nil {
		// If 'wheel' doesn't exist, we might be on a system where it's called something else,
		// but the user's request was specific.
		return fmt.Errorf("failed to lookup group %s: %w", targetGroup, err)
	}
	targetGID := g.Gid

	// 2. Identify Paths to check
	// The user requested: HOKUTO_ROOT/$TMPDIR, HOKUTO_ROOT/$TMPDIR2, HOKUTO_ROOT/repo/,
	// HOKUTO_ROOT/var/cache/hokuto, HOKUTO_ROOT/var/db/hokuto
	var pathsToCheck []string

	addPath := func(p string) {
		if p == "" {
			return
		}
		full := filepath.Clean(filepath.Join(rootDir, strings.TrimPrefix(p, "/")))
		// NEVER try to chown root or standard system temp dirs
		if full == "/" || full == "/tmp" || full == "/var/tmp" || full == "/home" || full == "/usr" {
			return
		}
		pathsToCheck = append(pathsToCheck, full)
	}

	// TMPDIRs
	addPath(tmpDir)
	if HokutoTmpDir != "" && HokutoTmpDir != tmpDir {
		addPath(HokutoTmpDir)
	}
	if tmp2 := cfg.Values["TMPDIR2"]; tmp2 != "" {
		addPath(tmp2)
	}

	// Repo, Cache, DB
	addPath("repo")
	addPath("var/cache/hokuto")
	addPath("var/db/hokuto")

	// 3. Check for mismatches
	var pathsToFix []string
	for _, path := range pathsToCheck {
		// Use Lstat to check the link itself if it's a symlink
		info, err := os.Lstat(path)
		if err != nil {
			// If it doesn't exist, we don't need to fix it.
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		uidMatch := fmt.Sprint(stat.Uid) == targetUID
		gidMatch := fmt.Sprint(stat.Gid) == targetGID

		// Mismatch detection
		mismatch := false
		if !uidMatch {
			mismatch = true
		} else if !gidMatch {
			// Special case: ignore group mismatch for cache directory
			// (often a symlink to external drive with different group permissions)
			isCache := strings.Contains(path, "var/cache/hokuto")
			if !isCache {
				mismatch = true
			}
		}

		if mismatch {
			pathsToFix = append(pathsToFix, path)
		}
	}

	// 4. Fix if needed
	if len(pathsToFix) > 0 {
		// Inform the user what we are doing (only in debug mode)
		if Debug {
			colArrow.Print("-> ")
			fmt.Printf("Ensuring ownership for Hokuto directories (current user:wheel)...\n")
			for _, p := range pathsToFix {
				fmt.Printf("   Fixing: %s\n", p)
			}
		}

		// We need root to fix ownership. Prompt for sudo.
		if err := authenticateOnce(); err != nil {
			return fmt.Errorf("failed to authenticate for ownership fix: %w", err)
		}

		for _, path := range pathsToFix {
			cmd := exec.Command("sudo", "chown", "-R", fmt.Sprintf("%s:%s", targetUser, targetGroup), path)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to fix ownership of %s: %w", path, err)
			}
		}
	}

	return nil
}
