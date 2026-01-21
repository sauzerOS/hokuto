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
func ensureHokutoOwnership(_ *Config) error {
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

	// TMPDIRs
	if tmpDir != "" {
		pathsToCheck = append(pathsToCheck, filepath.Join(rootDir, strings.TrimPrefix(tmpDir, "/")))
	}
	if HokutoTmpDir != "" && HokutoTmpDir != tmpDir {
		pathsToCheck = append(pathsToCheck, filepath.Join(rootDir, strings.TrimPrefix(HokutoTmpDir, "/")))
	}

	// Repo
	pathsToCheck = append(pathsToCheck, filepath.Join(rootDir, "repo"))

	// Cache
	pathsToCheck = append(pathsToCheck, filepath.Join(rootDir, "var/cache/hokuto"))

	// DB
	pathsToCheck = append(pathsToCheck, filepath.Join(rootDir, "var/db/hokuto"))

	// 3. Check for mismatches
	var pathsToFix []string
	for _, path := range pathsToCheck {
		info, err := os.Stat(path)
		if err != nil {
			// If it doesn't exist, we don't need to fix it.
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		if fmt.Sprint(stat.Uid) != targetUID || fmt.Sprint(stat.Gid) != targetGID {
			pathsToFix = append(pathsToFix, path)
		}
	}

	// 4. Fix if needed
	if len(pathsToFix) > 0 {
		// We need root to fix ownership. Prompt for sudo.
		if err := authenticateOnce(); err != nil {
			return fmt.Errorf("failed to authenticate for ownership fix: %w", err)
		}

		for _, path := range pathsToFix {
			debugf("Enforcing ownership of %s to %s:%s\n", path, targetUser, targetGroup)
			cmd := exec.Command("sudo", "chown", "-R", fmt.Sprintf("%s:%s", targetUser, targetGroup), path)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to fix ownership of %s: %w", path, err)
			}
		}
	}

	return nil
}
