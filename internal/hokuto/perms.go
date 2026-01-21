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
	// 1. Determine target user and group
	// If running as root (likely via sudo), we want to own files as the SUDO_USER.
	targetUser := os.Getenv("SUDO_USER")
	if targetUser == "" {
		// Not running via sudo (or SUDO_USER not set), use current user
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get current user: %w", err)
		}
		targetUser = currentUser.Username
	}

	if targetUser == "root" {
		return nil
	}

	// We assume 'wheel' group as requested.
	targetGroup := "wheel"

	// Resolve UID/GID for chown command
	u, err := user.Lookup(targetUser)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", targetUser, err)
	}
	g, err := user.LookupGroup(targetGroup)
	if err != nil {
		// If 'wheel' doesn't exist, we might fail hard or fallback. User requested 'wheel'.
		return fmt.Errorf("failed to lookup group %s: %w", targetGroup, err)
	}

	// 2. Identify Paths
	// HOKUTO_ROOT/var/cache/hokuto
	// HOKUTO_ROOT/var/db/hokuto
	// HOKUTO_ROOT/repo/*
	// HOKUTO_ROOT/$TMPDIR (and TMPDIR2 if distinct)

	// Helper to handle HOKUTO_ROOT prefixing if needed, though Config variables usually have absolute paths?
	// Based on config.go:
	// CacheDir = cfg.Values["HOKUTO_CACHE_DIR"] (default /var/cache/hokuto)
	// Installed = rootDir + "/var/db/hokuto/installed" (implies rootDir/var/db/hokuto)
	// repoPaths = cfg.Values["HOKUTO_PATH"] (colon separated)
	// tmpDir = cfg.Values["TMPDIR"]

	var pathsToCheck []string

	// Cache Dir
	if CacheDir != "" {
		pathsToCheck = append(pathsToCheck, CacheDir)
	}

	// DB Dir: We want /var/db/hokuto, not just installed
	// Installed is defined as rootDir + "/var/db/hokuto/installed".
	// So we want the parent of 'Installed'
	if Installed != "" {
		dbDir := filepath.Dir(Installed) // /var/db/hokuto
		pathsToCheck = append(pathsToCheck, dbDir)
	}

	// Repo Paths
	if repoPaths != "" {
		for _, path := range strings.Split(repoPaths, ":") {
			path = strings.TrimSpace(path)
			if path != " " && path != "" {
				pathsToCheck = append(pathsToCheck, path)
			}
		}
	}

	// Temp Dir
	if tmpDir != "" {
		pathsToCheck = append(pathsToCheck, tmpDir)
	}
	// Check if HokutoTmpDir is different
	if HokutoTmpDir != "" && HokutoTmpDir != tmpDir {
		pathsToCheck = append(pathsToCheck, HokutoTmpDir)
	}

	// 3. Iterate and Check/Fix
	// We need to check if we are root to run chown.
	// If we are NOT root, we can't really fix it if it's owned by root.
	// But check logic:
	// If current user is root, we can Chown.
	// If current user is targetUser, we might be able to Chown if we own the dir? (Wait, chowin to user:wheel)

	// Only attempt fix if we are effectively root (euid 0)
	uid := os.Geteuid()
	isRoot := uid == 0

	for _, path := range pathsToCheck {
		// Evaluate wildcards if any (repo path might not have them but let's be safe if user input has glob?)
		// Assuming paths are literal directories unless they contain glob chars.
		// User request said "HOKUTO_ROOT/repo/*".
		// If repoPaths contains specific dirs, use those. If it's a parent, use that?
		// config.go: repoPaths = cfg.Values["HOKUTO_PATH"]. Usually a specific list of dirs.

		// Check recursive ownership
		// Optimization: Check just the directory itself first?
		// User requested "chown -R".
		// checking every file for ownership to decide whether to chown might be slow.
		// Maybe just run chown -R blindly if we are root?
		// Or check the top level dir, if wrong, chown -R.

		info, err := os.Stat(path)
		if err != nil {
			// If dir doesn't exist, we can't chown it.
			continue
		}

		// Get stat info
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		currentUID := fmt.Sprint(stat.Uid)
		currentGID := fmt.Sprint(stat.Gid)

		// Compare with target
		if currentUID != u.Uid || currentGID != g.Gid {
			// Mismatch found at top level. Fix it recursively.
			if isRoot {
				// fmt.Printf("Fixing ownership of %s to %s:%s\n", path, targetUser, targetGroup)
				cmd := exec.Command("chown", "-R", fmt.Sprintf("%s:%s", targetUser, targetGroup), path)
				if err := cmd.Run(); err != nil {
					// Warn but don't fail hard?
					fmt.Printf("Warning: Failed to chown %s: %v\n", path, err)
				}
			} else {
				// Not root, can't fix.
				// fmt.Printf("Warning: Directory %s has incorrect ownership (is %s:%s, want %s:%s), but strictly require root to chown.\n", path, currentUID, currentGID, u.Uid, g.Gid)
			}
		}
	}

	return nil
}
