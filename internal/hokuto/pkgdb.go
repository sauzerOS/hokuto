package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func findOwnerPackage(filePath string) (string, error) {
	// 1. Normalize the search path for the manifest
	// Handle both paths with and without leading slashes
	searchPath := filepath.Clean(filePath)
	searchPathNoSlash := strings.TrimPrefix(searchPath, "/")
	searchPathWithSlash := "/" + searchPathNoSlash

	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No packages installed
		}
		return "", fmt.Errorf("failed to read installed db: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(Installed, pkgName, "manifest")

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // skip unreadable manifests
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			manifestPath := fields[0]

			// Normalize the path found in the manifest for an exact match check
			cleanManifestPath := filepath.Clean(manifestPath)
			cleanManifestPathNoSlash := strings.TrimPrefix(cleanManifestPath, "/")

			// Check for exact match (try both with and without leading slash)
			if cleanManifestPath == searchPath || cleanManifestPath == searchPathWithSlash ||
				cleanManifestPathNoSlash == searchPathNoSlash {
				return pkgName, nil // Found the owner!
			}
		}
	}

	return "", nil // No owner found
}

// isOwnedByAnotherPackage checks if a file is owned by another package (excluding excludePkg).
// Returns true if the file is found in another package's manifest.
func isOwnedByAnotherPackage(filePath, excludePkg string) bool {
	searchPath := filepath.Clean(filePath)

	entries, err := os.ReadDir(Installed)
	if err != nil {
		return false
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		// Skip the excluded package
		if pkgName == excludePkg {
			continue
		}

		manifestPath := filepath.Join(Installed, pkgName, "manifest")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // skip unreadable manifests
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			manifestPath := fields[0]

			// Normalize the path found in the manifest for an exact match check
			cleanManifestPath := filepath.Clean(manifestPath)

			// Check for exact match
			if cleanManifestPath == searchPath {
				return true // Found in another package!
			}
		}
	}

	return false // Not found in any other package
}

// checkFileConflict checks if a file exists in another package's manifest and if the checksum matches.
// Returns (packageName, checksumMatches, isSymlink, symlinkTarget) if found, ("", false, false, "") otherwise.
// Excludes the currentPackage from the search.
// For symlinks, it checks if the symlink path exists in another package's manifest with 000000 checksum,
// and also checks if the resolved symlink target file exists in another package's manifest.
func checkFileConflict(filePath, currentFileAbsPath, currentPackage, rootDir string, execCtx *Executor) (string, bool, bool, string) {
	searchPath := filepath.Clean(filePath)

	// Ignore internal metadata files
	if strings.Contains(searchPath, "/var/db/hokuto/") || strings.HasPrefix(searchPath, "var/db/hokuto/") {
		return "", false, false, ""
	}

	// Check if currentFile is a symlink
	currentInfo, err := os.Lstat(currentFileAbsPath)
	isSymlink := false
	var symlinkTarget string
	var resolvedTargetPath string
	var resolvedTargetRelPath string

	if err == nil && currentInfo.Mode()&os.ModeSymlink != 0 {
		isSymlink = true
		// Read the symlink target
		symlinkTarget, err = os.Readlink(currentFileAbsPath)
		if err != nil {
			// Can't read symlink, treat as regular file
			isSymlink = false
		} else {
			// Resolve the symlink target to an absolute path
			// Handle relative paths like ../usr/file
			if filepath.IsAbs(symlinkTarget) {
				resolvedTargetPath = filepath.Clean(symlinkTarget)
			} else {
				// Relative path - resolve relative to the symlink's directory
				symlinkDir := filepath.Dir(currentFileAbsPath)
				resolvedTargetPath = filepath.Clean(filepath.Join(symlinkDir, symlinkTarget))
			}
			// Convert to relative path from rootDir for manifest comparison
			if rootDir != "" && strings.HasPrefix(resolvedTargetPath, rootDir) {
				resolvedTargetRelPath = strings.TrimPrefix(resolvedTargetPath, rootDir)
				resolvedTargetRelPath = strings.TrimPrefix(resolvedTargetRelPath, "/")
				resolvedTargetRelPath = filepath.Clean(resolvedTargetRelPath)
			}
		}
	}

	entries, err := os.ReadDir(Installed)
	if err != nil {
		return "", false, false, ""
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		// Skip the current package being installed
		if pkgName == currentPackage {
			continue
		}

		manifestPath := filepath.Join(Installed, pkgName, "manifest")
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // skip unreadable manifests
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			manifestPath := fields[0]
			manifestChecksum := fields[1]

			// Normalize the path found in the manifest for an exact match check
			cleanManifestPath := filepath.Clean(manifestPath)

			// For symlinks, check both the symlink path itself and the resolved target path
			if isSymlink {
				// First check if the symlink path itself is in the manifest (with 000000 checksum)
				if cleanManifestPath == searchPath && manifestChecksum == "000000" {
					// Found the symlink in manifest with 000000 checksum - it's a match
					return pkgName, true, true, symlinkTarget
				}

				// Also check if the resolved target file is in the manifest
				if resolvedTargetRelPath != "" && cleanManifestPath == resolvedTargetRelPath {
					// Found the target file in manifest - check if checksum matches
					// Compute checksum of the resolved target file
					targetChecksum, err := ComputeChecksum(resolvedTargetPath, execCtx)
					if err == nil && strings.EqualFold(targetChecksum, manifestChecksum) {
						// Target file matches - this is a conflict
						return pkgName, true, true, symlinkTarget
					}
				}
				// Continue to next manifest entry if no match for symlink
				continue
			}

			// Check for exact match on the file path itself (for regular files only)
			if cleanManifestPath == searchPath {
				// Found the file in another package's manifest
				// Regular file - check if the checksum matches
				currentChecksum, err := ComputeChecksum(currentFileAbsPath, execCtx)
				if err != nil {
					// Can't compute checksum, assume no match
					return pkgName, false, false, ""
				}
				// Compare checksums (case-insensitive, but they should be lowercase hex)
				if strings.EqualFold(currentChecksum, manifestChecksum) {
					return pkgName, true, false, ""
				}
				// File exists in manifest but checksum doesn't match
				return pkgName, false, false, ""
			}
		}
	}

	return "", false, false, "" // No conflict found
}

// checkPackageExactMatch checks if a package with the exact name is installed.
// Returns true only if the package directory exists with an exact name match.
// This is designed for use in build scripts: exit 0 = found, exit 1 = not found.
func checkPackageExactMatch(pkgName string) bool {
	// Construct the exact path for this package
	pkgPath := filepath.Join(Installed, pkgName)

	// Check if it exists and is a directory
	info, err := os.Stat(pkgPath)
	if err != nil {
		// Does not exist or error accessing it
		return false
	}

	// Verify it's actually a directory
	return info.IsDir()
}

// findPackageDir locates the package source directory in repoPaths.
func findPackageDir(pkgName string) (string, error) {
	// Check for versioned package override (e.g., pkg@1.0.0)
	if dir, ok := versionedPkgDirs[pkgName]; ok {
		return dir, nil
	}

	paths := strings.Split(repoPaths, ":")
	for _, repoPath := range paths {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		pkgDir := filepath.Join(repoPath, pkgName)
		if info, err := os.Stat(pkgDir); err == nil && info.IsDir() {
			return pkgDir, nil
		}
	}

	// FALLBACK: Check if it's already installed.
	// This is crucial for resolving dependencies of renamed packages (pkg-MAJOR)
	// which only exist in the installed database and have no source in repositories.
	if checkPackageExactMatch(pkgName) {
		return filepath.Join(Installed, pkgName), nil
	}

	return "", fmt.Errorf("package %s not found in any repository", pkgName)
}

func findInstalledSatisfying(name, op, refVersion string) string {
	// 1. Check the exact package name
	if checkPackageExactMatch(name) {
		ver, ok := getInstalledVersion(name)
		if ok && (op == "" || refVersion == "" || versionSatisfies(ver, op, refVersion)) {
			return name
		}
	}

	// 2. Scan for name-MAJOR versions
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return ""
	}

	prefix := name + "-"
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		if strings.HasPrefix(pkgName, prefix) {
			// Check if the suffix is a major version (integer)
			suffix := strings.TrimPrefix(pkgName, prefix)
			if _, err := strconv.Atoi(suffix); err == nil {
				ver, ok := getInstalledVersion(pkgName)
				if ok && (op == "" || refVersion == "" || versionSatisfies(ver, op, refVersion)) {
					return pkgName
				}
			}
		}
	}

	return ""
}

func getInstalledVersion(pkgName string) (string, bool) {
	versionFile := filepath.Join(Installed, pkgName, "version")
	if data, err := os.ReadFile(versionFile); err == nil {
		v := strings.TrimSpace(string(data))
		if v == "" {
			return "", false
		}
		// Extract just the version (first field)
		fields := strings.Fields(v)
		if len(fields) == 0 {
			return "", false
		}
		return fields[0], true
	}
	return "", false
}

// readLockFile reads /etc/hokuto/hokuto.lock and returns a map of package name -> locked version.
// Returns an empty map if the file doesn't exist or on error (errors are silently ignored).
func readLockFile() map[string]string {
	locked := make(map[string]string)
	data, err := os.ReadFile(LockFile)
	if err != nil {
		// File doesn't exist or can't be read - return empty map
		return locked
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line: "package-name version"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkgName := fields[0]
			version := fields[1]
			locked[pkgName] = version
		}
	}

	return locked
}

// checkLock returns an error if the package is locked at a lower version than the target version.
func checkLock(pkgName, version string) error {
	locked := readLockFile()
	if lockedVersion, ok := locked[pkgName]; ok {
		if compareVersions(lockedVersion, version) < 0 {
			return fmt.Errorf("package %s is locked at version %s (locked in %s), refusing to install higher version %s", pkgName, lockedVersion, LockFile, version)
		}
	}
	return nil
}

// isMultilibPackage checks if a package name (without -multi suffix) is in the MultilibPackages list
func isMultilibPackage(pkgName string) bool {
	if pkgName == "sauzeros-base" {
		return false
	}
	// Remove -multi suffix if present for lookup
	baseName := strings.TrimSuffix(pkgName, "-multi")
	for _, multilibPkg := range MultilibPackages {
		if multilibPkg == baseName {
			return true
		}
	}
	return false
}

// resolveMultilibPackageName resolves a package name to its multilib variant if enabled
// Returns the package name to use (either original or -multi variant)
func resolveMultilibPackageName(pkgName string, cfg *Config) string {
	// If multilib is not enabled, return original name
	if cfg.Values["HOKUTO_MULTILIB"] != "1" {
		return pkgName
	}

	// If package already has -multi suffix, return as-is
	if strings.HasSuffix(pkgName, "-multi") {
		return pkgName
	}

	// Check if this package has a multilib variant
	if pkgName != "sauzeros-base" && isMultilibPackage(pkgName) {
		return pkgName + "-multi"
	}

	// No multilib variant, return original
	return pkgName
}
