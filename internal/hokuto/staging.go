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
)

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
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			// Split into path and optional checksum: path is always first token
			parts := strings.SplitN(line, "  ", 2) // manifest uses "␣␣" separator
			path := strings.Fields(parts[0])[0]    // defensive: take first token
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
	fileOwnerIndex := buildFileOwnerIndex(pkgName)
	debugf("File ownership index built (indexed %d files)\n", len(fileOwnerIndex))

	// Scan installed manifest; add files missing from staging manifest
	iscanner := bufio.NewScanner(strings.NewReader(string(installedData)))
	filesChecked := 0
	for iscanner.Scan() {
		line := strings.TrimSpace(iscanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		path := strings.Fields(parts[0])[0]

		// if present in staging manifest -> skip
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

			// Check if this file is owned by another package using the index
			// Try both with and without leading slash for matching
			normalizedPath := filepath.Clean(path)
			normalizedPathNoSlash := strings.TrimPrefix(normalizedPath, "/")
			normalizedPathWithSlash := "/" + normalizedPathNoSlash

			if _, owned := fileOwnerIndex[normalizedPath]; owned {
				// File is owned by another package, don't delete it
				continue
			}
			if _, owned := fileOwnerIndex[normalizedPathWithSlash]; owned {
				// File is owned by another package, don't delete it
				continue
			}
			if _, owned := fileOwnerIndex[normalizedPathNoSlash]; owned {
				// File is owned by another package, don't delete it
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

// buildFileOwnerIndex builds a map of file paths (normalized) to package names
// for all installed packages except excludePkg. This allows O(1) lookups instead
// of scanning all manifests for each file.
func buildFileOwnerIndex(excludePkg string) map[string]string {
	index := make(map[string]string)

	entries, err := os.ReadDir(Installed)
	if err != nil {
		return index
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

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
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

			// Normalize the path and add to index
			// Handle both "/usr/bin/file" and "usr/bin/file" formats consistently
			normalizedPath := filepath.Clean(manifestPath)
			// Also add normalized path without leading slash for matching
			normalizedPathNoSlash := strings.TrimPrefix(normalizedPath, "/")
			normalizedPathWithSlash := "/" + normalizedPathNoSlash

			// Store in index with both formats (with and without leading slash)
			// Store the first package that owns this file (in case of duplicates)
			if _, exists := index[normalizedPath]; !exists {
				index[normalizedPath] = pkgName
			}
			if normalizedPath != normalizedPathWithSlash {
				if _, exists := index[normalizedPathWithSlash]; !exists {
					index[normalizedPathWithSlash] = pkgName
				}
			}
			if normalizedPath != normalizedPathNoSlash && normalizedPathNoSlash != "" {
				if _, exists := index[normalizedPathNoSlash]; !exists {
					index[normalizedPathNoSlash] = pkgName
				}
			}
		}
	}

	return index
}

// rsyncStaging syncs the contents of stagingDir into rootDir.
// It uses system rsync if available, otherwise falls back to a Go-native copy.
func rsyncStaging(stagingDir, rootDir string, execCtx *Executor) error {
	stagingPath := filepath.Clean(stagingDir)

	// Ensure rootDir exists
	mkdirCmd := exec.Command("mkdir", "-p", rootDir)
	if err := execCtx.Run(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create rootDir %s: %v", rootDir, err)
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
			rmCmd := exec.Command("rm", "-rf", stagingDir)
			if err := execCtx.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
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
			rmCmd := exec.Command("rm", "-rf", stagingDir)
			if err := execCtx.Run(rmCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to remove staging dir %s: %v\n", stagingDir, err)
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

	rmCmd := exec.Command("rm", "-rf", stagingDir)
	if err := execCtx.Run(rmCmd); err != nil {
		return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
	}

	return nil
}
