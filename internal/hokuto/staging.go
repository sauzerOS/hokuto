package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type packageOwnershipEntry struct {
	manifestPath string
	modTime      time.Time
	size         int64
	paths        []string
}

type fileOwnershipSnapshot struct {
	owners map[string][]string
}

func (s *fileOwnershipSnapshot) ownerOtherThan(path, excludePkg string) string {
	if s == nil {
		return ""
	}
	for _, owner := range s.owners[path] {
		if owner != excludePkg {
			return owner
		}
	}
	return ""
}

type fileOwnershipCache struct {
	mu           sync.Mutex
	rootDir      string
	installedDir string
	packages     map[string]packageOwnershipEntry
	snapshot     *fileOwnershipSnapshot
}

var globalFileOwnershipCache fileOwnershipCache

func getFileOwnershipSnapshot(rootDir string) *fileOwnershipSnapshot {
	return globalFileOwnershipCache.snapshotFor(rootDir, Installed)
}

func invalidateFileOwnershipPackage(pkgName string) {
	globalFileOwnershipCache.invalidatePackage(pkgName)
}

func (c *fileOwnershipCache) invalidatePackage(pkgName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.packages == nil {
		return
	}
	delete(c.packages, pkgName)
	c.snapshot = nil
}

func (c *fileOwnershipCache) snapshotFor(rootDir, installedDir string) *fileOwnershipSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.packages == nil || c.rootDir != rootDir || c.installedDir != installedDir {
		c.rootDir = rootDir
		c.installedDir = installedDir
		c.packages = make(map[string]packageOwnershipEntry)
		c.snapshot = nil
	}

	entries, err := os.ReadDir(installedDir)
	if err != nil {
		c.packages = make(map[string]packageOwnershipEntry)
		c.snapshot = &fileOwnershipSnapshot{owners: make(map[string][]string)}
		return c.snapshot
	}

	changed := c.snapshot == nil
	dirCache := make(map[string]string)
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		pkgName := e.Name()
		seen[pkgName] = true
		manifestPath := filepath.Join(installedDir, pkgName, "manifest")
		info, err := os.Stat(manifestPath)
		if err != nil {
			if _, ok := c.packages[pkgName]; ok {
				delete(c.packages, pkgName)
				changed = true
			}
			continue
		}

		cached, ok := c.packages[pkgName]
		if ok && cached.manifestPath == manifestPath && cached.modTime.Equal(info.ModTime()) && cached.size == info.Size() {
			continue
		}

		paths := readManifestOwnershipPaths(manifestPath, rootDir, dirCache)
		c.packages[pkgName] = packageOwnershipEntry{
			manifestPath: manifestPath,
			modTime:      info.ModTime(),
			size:         info.Size(),
			paths:        paths,
		}
		changed = true
	}

	for pkgName := range c.packages {
		if !seen[pkgName] {
			delete(c.packages, pkgName)
			changed = true
		}
	}

	if changed {
		owners := make(map[string][]string)
		for pkgName, entry := range c.packages {
			for _, path := range entry.paths {
				owners[path] = appendUniqueOwner(owners[path], pkgName)
			}
		}
		c.snapshot = &fileOwnershipSnapshot{owners: owners}
	}

	return c.snapshot
}

func readManifestOwnershipPaths(manifestPath, rootDir string, dirCache map[string]string) []string {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil
	}

	pathSet := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		entry, ok, err := parseManifestLine(scanner.Text())
		if err != nil || !ok || strings.HasSuffix(entry.Path, "/") {
			continue
		}

		addOwnershipPathVariants(pathSet, rootDir, entry.Path, dirCache)
	}

	paths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		paths = append(paths, path)
	}
	return paths
}

func addOwnershipPathVariants(pathSet map[string]struct{}, rootDir, manifestPath string, dirCache map[string]string) {
	normalizedPath := canonicalizePathCached(rootDir, manifestPath, dirCache)
	normalizedPathNoSlash := strings.TrimPrefix(normalizedPath, "/")
	normalizedPathWithSlash := "/" + normalizedPathNoSlash

	if normalizedPath != "" {
		pathSet[normalizedPath] = struct{}{}
	}
	if normalizedPathWithSlash != "/" {
		pathSet[normalizedPathWithSlash] = struct{}{}
	}
	if normalizedPathNoSlash != "" {
		pathSet[normalizedPathNoSlash] = struct{}{}
	}
}

func canonicalizePathCached(rootDir, path string, dirCache map[string]string) string {
	cleanPath := filepath.Clean(path)
	if cleanPath == "/" {
		if strings.HasPrefix(path, "/") {
			return "/"
		}
		return ""
	}

	absPath := filepath.Join(rootDir, strings.TrimPrefix(cleanPath, "/"))
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	resolvedDir, ok := dirCache[dir]
	if !ok {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			resolvedDir = resolved
		} else {
			resolvedDir = dir
		}
		dirCache[dir] = resolvedDir
	}

	rel, err := filepath.Rel(rootDir, filepath.Join(resolvedDir, base))
	if err != nil {
		return cleanPath
	}
	if strings.HasPrefix(path, "/") {
		return "/" + strings.TrimPrefix(rel, "/")
	}
	return strings.TrimPrefix(rel, "/")
}

func appendUniqueOwner(owners []string, pkgName string) []string {
	for _, owner := range owners {
		if owner == pkgName {
			return owners
		}
	}
	return append(owners, pkgName)
}

// removeObsoleteFiles compares the installed manifest (under Installed/<pkg>/manifest)
// with the manifest present in the staging tree. It returns a slice of absolute
// paths (under rootDir) that should be deleted after the staging has been rsynced.
func removeObsoleteFiles(pkgName, stagingDir, rootDir string) ([]string, error) {
	installedManifestPath := filepath.Join(Installed, pkgName, "manifest")
	stagingManifestPath := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName, "manifest")

	installedData, err := readFileAsRoot(installedManifestPath)
	if err != nil {
		// No installed manifest → nothing to remove
		return nil, nil
	}

	// Read staging manifest if present; treat missing file as empty manifest
	stagingData, _ := os.ReadFile(stagingManifestPath)

	// Build set of paths present in staging manifest
	stagingSet := make(map[string]struct{})
	if len(stagingData) > 0 {
		sc := bufio.NewScanner(strings.NewReader(string(stagingData)))
		for sc.Scan() {
			entry, ok, err := parseManifestLine(sc.Text())
			if err != nil {
				return nil, fmt.Errorf("invalid staging manifest: %w", err)
			}
			if !ok || strings.HasSuffix(entry.Path, "/") {
				continue
			}
			path := entry.Path
			canonical := canonicalizePath(rootDir, path)
			stagingSet[canonical] = struct{}{}
			stagingSet[strings.TrimPrefix(canonical, "/")] = struct{}{}
			stagingSet[path] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("error reading staging manifest: %v", err)
		}
	}

	var filesToDelete []string

	// Build an index of file ownership once (for all packages except current)
	// This avoids scanning all manifests for each file
	debugf("Building file ownership index...\n")
	ownershipSnapshot := getFileOwnershipSnapshot(rootDir)
	debugf("File ownership index built (indexed %d files)\n", len(ownershipSnapshot.owners))

	// Scan installed manifest; add files missing from staging manifest
	iscanner := bufio.NewScanner(strings.NewReader(string(installedData)))
	filesChecked := 0
	for iscanner.Scan() {
		entry, ok, err := parseManifestLine(iscanner.Text())
		if err != nil {
			return nil, fmt.Errorf("invalid installed manifest for %s: %w", pkgName, err)
		}
		if !ok || strings.HasSuffix(entry.Path, "/") {
			continue
		}
		path := entry.Path
		if isPreservedKernelUpgradePath(path) {
			continue
		}

		// Check if canonical path matches
		canonicalPath := canonicalizePath(rootDir, path)
		canonicalPathNoSlash := strings.TrimPrefix(canonicalPath, "/")
		if _, ok := stagingSet[canonicalPath]; ok {
			continue
		}
		if _, ok := stagingSet[canonicalPathNoSlash]; ok {
			continue
		}
		if _, ok := stagingSet[path]; ok {
			continue
		}

		installedPath := filepath.Join(rootDir, path)

		// if installed file exists on disk, check if it's owned by another package
		if fi, err := os.Lstat(installedPath); err == nil && !fi.IsDir() {
			filesChecked++
			if filesChecked%1000 == 0 {
				debugf("Checked %d obsolete files...\n", filesChecked)
			}

			// Check if this file is owned by another package using the index.
			if ownershipSnapshot.ownerOtherThan(canonicalPath, pkgName) != "" ||
				ownershipSnapshot.ownerOtherThan(canonicalPathNoSlash, pkgName) != "" ||
				ownershipSnapshot.ownerOtherThan(path, pkgName) != "" {
				continue
			}
			// File is not owned by another package, schedule for deletion
			filesToDelete = append(filesToDelete, installedPath)
		}
	}
	debugf("Finished checking obsolete files (checked %d files, %d to delete)\n", filesChecked, len(filesToDelete))
	if err := iscanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading installed manifest: %v", err)
	}

	return filesToDelete, nil
}

func isPreservedKernelUpgradePath(path string) bool {
	clean := strings.TrimPrefix(filepath.ToSlash(path), "/")
	if strings.HasPrefix(clean, "boot/vmlinuz-") ||
		strings.HasPrefix(clean, "boot/initramfs-") ||
		strings.HasPrefix(clean, "boot/System.map-") ||
		strings.HasPrefix(clean, "boot/config-") {
		return strings.Contains(clean, "-sauzerOS")
	}
	for _, prefix := range []string{"usr/lib/modules/", "lib/modules/"} {
		if !strings.HasPrefix(clean, prefix) {
			continue
		}
		rest := strings.TrimPrefix(clean, prefix)
		release := rest
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			release = rest[:idx]
		}
		if isSauzerosKernelRelease(release) {
			return true
		}
	}
	return false
}

// buildFileOwnerIndex builds a map of file paths (normalized) to package names
// for all installed packages except excludePkg. This allows O(1) lookups instead
// of scanning all manifests for each file.
func buildFileOwnerIndex(excludePkg, rootDir string) map[string]string {
	index := make(map[string]string)
	snapshot := getFileOwnershipSnapshot(rootDir)
	for path := range snapshot.owners {
		if owner := snapshot.ownerOtherThan(path, excludePkg); owner != "" {
			index[path] = owner
		}
	}

	return index
}

// rsyncStaging syncs the contents of stagingDir into rootDir.
// It uses system rsync if available, otherwise falls back to a Go-native copy.
func rsyncStaging(stagingDir, rootDir string, execCtx *Executor) error {
	stagingPath := filepath.Clean(stagingDir)

	// Ensure rootDir exists
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(rootDir, 0755); err != nil {
			return fmt.Errorf("failed to create rootDir %s natively: %v", rootDir, err)
		}
	} else {
		mkdirCmd := exec.Command("mkdir", "-p", rootDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create rootDir %s: %v", rootDir, err)
		}
	}

	// --- Try system rsync first ---
	if _, err := exec.LookPath("rsync"); err == nil {
		// Note: rsync needs trailing slash on source to copy contents, not the directory itself
		stagingPathWithSlash := stagingPath + string(os.PathSeparator)
		args := []string{
			"-aHAX",
			"--numeric-ids",
			"--no-implied-dirs",
			"--keep-dirlinks",
			stagingPathWithSlash,
			rootDir,
		}
		cmd := exec.Command("rsync", args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := execCtx.Run(cmd); err == nil {
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(stagingDir); err != nil {
					return fmt.Errorf("failed to remove staging dir %s natively: %v", stagingDir, err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", stagingDir)
				if err := execCtx.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
				}
			}
			return nil
		}
	}
	// --- Fallback 1: Try system cp -aT ---
	if _, err := exec.LookPath("cp"); err == nil {
		// The `cp -aT` command is a safer alternative to the tar pipe.
		// -a preserves links, permissions, and ownership.
		// -T prevents `cp` from creating a subdirectory inside rootDir.
		cmd := exec.Command("cp", "-aT", stagingPath, rootDir)
		cmd.Stderr = os.Stderr // Show potential errors.

		debugf("Attempting to sync with 'cp -aT %s %s'\n", stagingPath, rootDir)
		if err := execCtx.Run(cmd); err == nil {
			// Success! Clean up and return.
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(stagingDir); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to remove staging dir %s natively: %v\n", stagingDir, err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", stagingDir)
				if err := execCtx.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to remove staging dir %s: %v\n", stagingDir, err)
				}
			}
			return nil
		}
		debugf("System 'cp -aT' failed, falling back to internal Go implementation.\n")
	} else {
		debugf("System 'cp' not found, falling back to internal Go implementation.\n")
	}

	// --- Fallback 2: Use internal Go tar implementation ---
	// This is resilient to broken system tools during updates
	debugf("rsync not available, using internal Go tar fallback\n")

	if err := copyTreeWithTar(stagingPath, rootDir, execCtx); err != nil {
		return fmt.Errorf("internal tar fallback failed: %v", err)
	}

	if os.Geteuid() == 0 {
		if err := os.RemoveAll(stagingDir); err != nil {
			return fmt.Errorf("failed to remove staging dir %s natively: %v", stagingDir, err)
		}
	} else {
		rmCmd := exec.Command("rm", "-rf", stagingDir)
		if err := execCtx.Run(rmCmd); err != nil {
			return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
		}
	}

	return nil
}
