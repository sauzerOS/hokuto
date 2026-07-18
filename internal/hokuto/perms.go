package hokuto

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// ensureHokutoOwnership checks if critical Hokuto directories are owned by the
// invoking user and that the owner can write to them. If not, it repairs them.
func ensureHokutoOwnership(cfg *Config, createCacheDirs bool) error {
	// 1. Determine target user and group. Do not skip an effective UID of zero:
	// `sudo hokuto` must repair caches for SUDO_USER rather than leaving them
	// owned by root.
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

	// 2. Identify paths to check. These globals are the paths Hokuto accesses on
	// the host, so do not prefix them with HOKUTO_ROOT a second time.
	var pathsToCheck []string
	createIfMissing := make(map[string]bool)
	seenPaths := make(map[string]bool)

	addPath := func(p string, create bool) {
		if p == "" {
			return
		}
		full := filepath.Clean(p)
		// NEVER try to chown root or standard system temp dirs
		if full == "/" || full == "/tmp" || full == "/var/tmp" || full == "/home" || full == "/usr" {
			return
		}
		if !seenPaths[full] {
			pathsToCheck = append(pathsToCheck, full)
			seenPaths[full] = true
		}
		createIfMissing[full] = createIfMissing[full] || create
	}

	// TMPDIRs
	addPath(tmpDir, false)
	if HokutoTmpDir != "" && HokutoTmpDir != tmpDir {
		addPath(HokutoTmpDir, false)
	}
	if tmp2 := cfg.Values["TMPDIR2"]; tmp2 != "" {
		addPath(tmp2, false)
	}

	// Repo and every independently used cache directory. Checking only the
	// cache root misses a root-owned bin/ or sources/ directory below a correctly
	// owned parent, which prevents lock-file creation during downloads.
	addPath("/repo", false)
	addPath(CacheDir, createCacheDirs)
	addPath(BinDir, createCacheDirs)
	addPath(SourcesDir, createCacheDirs)
	addPath(CacheStore, createCacheDirs)
	//addPath("var/db/hokuto")

	// 3. Check for mismatches
	var pathsToFix []string
	for _, path := range pathsToCheck {
		// Use Lstat to check the link itself if it's a symlink
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) && createIfMissing[path] {
				pathsToFix = append(pathsToFix, path)
			}
			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}

		uidMatch := fmt.Sprint(stat.Uid) == targetUID
		gidMatch := fmt.Sprint(stat.Gid) == targetGID

		mismatch := !uidMatch || !gidMatch
		if info.IsDir() && info.Mode().Perm()&0o700 != 0o700 {
			mismatch = true
		}

		if mismatch {
			pathsToFix = append(pathsToFix, path)
		}
	}

	// If a parent is already being repaired recursively, avoid traversing its
	// children a second time.
	sort.Slice(pathsToFix, func(i, j int) bool { return len(pathsToFix[i]) < len(pathsToFix[j]) })
	compact := pathsToFix[:0]
	for _, path := range pathsToFix {
		// Repairing a parent recursively does not create requested child
		// directories. Keep every missing cache directory in the work list.
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			compact = append(compact, path)
			continue
		}
		covered := false
		for _, parent := range compact {
			// Recursive chown/chmod do not traverse a symlink passed as the
			// command-line operand. Keep checking children through a symlinked
			// cache root so the actual bin/ and sources/ directories are fixed.
			if info, err := os.Lstat(parent); err == nil && info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			rel, err := filepath.Rel(parent, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				covered = true
				break
			}
		}
		if !covered {
			compact = append(compact, path)
		}
	}
	pathsToFix = compact

	// 4. Fix if needed
	if len(pathsToFix) > 0 {
		// Inform the user what we are doing (only in debug mode)
		if Debug {
			colArrow.Print("-> ")
			fmt.Printf("Ensuring ownership for Hokuto directories (%s:%s)\n", targetUser, targetGroup)
			for _, p := range pathsToFix {
				fmt.Printf("   Fixing: %s\n", p)
			}
		}

		// We need root to fix ownership. Prompt for sudo.
		if err := authenticateOnce(true); err != nil {
			return fmt.Errorf("failed to authenticate for ownership fix: %w", err)
		}

		for _, path := range pathsToFix {
			uid, _ := strconv.Atoi(targetUID)
			gid, _ := strconv.Atoi(targetGID)

			if os.Geteuid() == 0 {
				if err := os.MkdirAll(path, 0o755); err != nil {
					return fmt.Errorf("failed to create %s natively: %w", path, err)
				}
				if err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if err := os.Lchown(p, uid, gid); err != nil {
						return err
					}
					if info.Mode()&os.ModeSymlink != 0 {
						return nil
					}
					mode := info.Mode()
					if info.IsDir() {
						mode |= 0o700
					} else {
						mode |= 0o600
						if info.Mode()&0o111 != 0 {
							mode |= 0o100
						}
					}
					return os.Chmod(p, mode)
				}); err != nil {
					return fmt.Errorf("failed to repair permissions for %s natively: %w", path, err)
				}
			} else {
				if err := newPrivilegedCommand("mkdir", "-p", path).Run(); err != nil {
					return fmt.Errorf("failed to create %s: %w", path, err)
				}
				if err := newPrivilegedCommand("chown", "-R", fmt.Sprintf("%s:%s", targetUID, targetGID), path).Run(); err != nil {
					return fmt.Errorf("failed to fix ownership of %s: %w", path, err)
				}
				if err := newPrivilegedCommand("chmod", "-R", "u+rwX", path).Run(); err != nil {
					return fmt.Errorf("failed to fix permissions of %s: %w", path, err)
				}
			}
		}

		// Inform user that ownership was fixed
		colArrow.Print("-> ")
		if len(pathsToFix) == 1 {
			colSuccess.Printf("Fixed ownership for %s\n", pathsToFix[0])
		} else {
			colSuccess.Printf("Fixed ownership for %d directories\n", len(pathsToFix))
			if Debug {
				for _, p := range pathsToFix {
					colNote.Printf("   - %s\n", p)
				}
			}
		}
	}

	return nil
}
