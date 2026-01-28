package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
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
	targetGroup := ""
	var targetGID string

	// Get current user (of the process)
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	if targetUser == "" {
		targetUser = currentUser.Username
		targetGID = currentUser.Gid
	} else {
		// If running via sudo, we want the SUDO_USER's primary group
		u, err := user.Lookup(targetUser)
		if err != nil {
			return fmt.Errorf("failed to lookup user %s: %w", targetUser, err)
		}
		targetGID = u.Gid
	}

	// Lookup group name for display/logging if needed, or verification
	g, err := user.LookupGroupId(targetGID)
	if err == nil {
		targetGroup = g.Name
	} else {
		targetGroup = targetGID // Fallback to GID
	}

	// Resolve UID
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", targetUser, err)
	}
	targetUID := u.Uid

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
			fmt.Printf("Ensuring ownership for Hokuto directories (current user:user)\n")
			for _, p := range pathsToFix {
				fmt.Printf("   Fixing: %s\n", p)
			}
		}

		// We need root to fix ownership. Prompt for sudo.
		if err := authenticateOnce(); err != nil {
			return fmt.Errorf("failed to authenticate for ownership fix: %w", err)
		}

		for _, path := range pathsToFix {
			uid, _ := strconv.Atoi(targetUID)
			gid, _ := strconv.Atoi(targetGID)

			if os.Geteuid() == 0 {
				if err := os.Chown(path, uid, gid); err != nil {
					return fmt.Errorf("failed to fix ownership of %s natively: %w", path, err)
				}
				// Also handle recursive if it was -R, but pathsToFix are individual identified paths?
				// Actually pathsToCheck are only the top level dirs. chown -R was used.
				// If we want to replace chown -R we need a recursive walk.
				if err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					return os.Chown(p, uid, gid)
				}); err != nil {
					return fmt.Errorf("failed to fix recursive ownership of %s natively: %w", path, err)
				}
			} else {
				cmd := exec.Command("sudo", "chown", "-R", fmt.Sprintf("%s:%s", targetUser, targetGroup), path)
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to fix ownership of %s: %w", path, err)
				}
			}
		}
	}

	return nil
}
