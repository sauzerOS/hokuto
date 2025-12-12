package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func findOwnerPackage(filePath string) (string, error) {
	// 1. Normalize the search path for the manifest (e.g., "usr/lib/libnssckbi.so")
	// The filePath comes from the 'file' variable which is relative to rootDir
	// so it doesn't need to be stripped of rootDir, but we'll ensure it's clean.
	searchPath := filepath.Clean(filePath)

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

			// Check for exact match
			if cleanManifestPath == searchPath {
				return pkgName, nil // Found the owner!
			}
		}
	}

	return "", nil // No owner found
}

// PostInstallTasks runs common system cache updates after package installs.
// It uses a worker pool to execute tasks with limited concurrency,
// preventing I/O contention and providing a significant speedup.

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
	return "", fmt.Errorf("not found in any repository")
}
