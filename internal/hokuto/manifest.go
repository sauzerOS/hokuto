package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type ManifestEntry struct {
	Path     string
	Checksum string
}

// parseManifest reads a manifest file and returns a map of file paths to their entries.
// The map key is the file Path.
// parseManifest reads a manifest file and returns a map of file paths to their entries.
// It specifically skips entries that represent directories (end with '/').

func generateManifest(outputDir, installedDir string, execCtx *Executor) error {
	manifestFile := filepath.Join(installedDir, "manifest")

	// Create a secure, unique temporary file
	fTmp, err := os.CreateTemp("", "hokuto-manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary manifest file: %v", err)
	}
	tmpManifest := fTmp.Name()
	fTmp.Close() // Close immediately, we re-open it with specific flags later

	// Set permissions to 0644 so it's readable if we switch contexts (e.g. root reading user file)
	if err := os.Chmod(tmpManifest, 0o644); err != nil {
		os.Remove(tmpManifest)
		return fmt.Errorf("failed to chmod temp manifest: %v", err)
	}

	// Ensure cleanup happens even if we error out early
	defer os.Remove(tmpManifest)

	if os.Geteuid() == 0 {
		if err := os.MkdirAll(installedDir, 0755); err != nil {
			return fmt.Errorf("failed to create installedDir natively: %v", err)
		}
	} else {
		mkdirCmd := exec.Command("mkdir", "-p", installedDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create installedDir: %v", err)
		}
	}

	// Optimized file listing
	entries, err := listOutputFilesWithTypes(outputDir, execCtx)
	if err != nil {
		// fallback to RootExec
		execCtx = RootExec
		entries, err = listOutputFilesWithTypes(outputDir, execCtx)
		if err != nil {
			return fmt.Errorf("failed to list output files: %v", err)
		}
	}

	relManifest, err := filepath.Rel(outputDir, manifestFile)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for manifest: %v", err)
	}
	manifestEntryPath := "/" + relManifest

	// Filter and categorize
	var dirs, symlinks, regularFiles, allEntries []string
	symlinkMap := make(map[string]bool)

	for _, e := range entries {
		if e.Path == manifestEntryPath {
			continue
		}

		allEntries = append(allEntries, e.Path)
		absPath := filepath.Join(outputDir, strings.TrimPrefix(e.Path, "/"))

		switch e.FileType {
		case "d":
			dirs = append(dirs, e.Path)
		case "l":
			symlinks = append(symlinks, e.Path)
			symlinkMap[e.Path] = true
		default:
			regularFiles = append(regularFiles, absPath)
		}
	}

	f, err := os.OpenFile(tmpManifest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open temporary manifest file: %v", err)
	}

	// Write directory entries
	for _, entry := range dirs {
		// Ensure it ends with /
		cleaned := entry
		if !strings.HasSuffix(cleaned, "/") {
			cleaned += "/"
		}
		if _, err := fmt.Fprintln(f, cleaned); err != nil {
			f.Close()
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}
	}

	// Write symlink entries (000000 checksum)
	for _, entry := range symlinks {
		if _, err := fmt.Fprintf(f, "%s 000000\n", entry); err != nil {
			f.Close()
			return fmt.Errorf("failed to write symlink entry: %v", err)
		}
	}

	// Compute checksums for regular files
	var checksums map[string]string
	checksums, err = ComputeChecksums(regularFiles, execCtx)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to compute checksums: %v", err)
	}

	// Write regular file entries
	for _, entry := range allEntries {
		if strings.HasSuffix(entry, "/") || symlinkMap[entry] {
			continue
		}
		absPath := filepath.Join(outputDir, strings.TrimPrefix(entry, "/"))
		checksum, exists := checksums[absPath]
		if !exists {
			f.Close()
			return fmt.Errorf("missing checksum for %s", absPath)
		}
		if _, err := fmt.Fprintf(f, "%s  %s\n", entry, checksum); err != nil {
			f.Close()
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}
	}

	f.Close()

	// Append the manifest's own checksum
	tempChecksum, err := ComputeChecksum(tmpManifest, execCtx)
	if err != nil {
		return fmt.Errorf("failed to compute checksum for temporary manifest %s: %v", tmpManifest, err)
	}

	f, err = os.OpenFile(tmpManifest, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to re-open temporary manifest file for final entry: %v", err)
	}
	if _, err := fmt.Fprintf(f, "%s  %s\n", manifestEntryPath, tempChecksum); err != nil {
		f.Close()
		return fmt.Errorf("failed to write final manifest entry: %v", err)
	}
	f.Close()

	if os.Geteuid() == 0 {
		if err := copyFile(tmpManifest, manifestFile); err != nil {
			return fmt.Errorf("failed to copy temporary manifest into place natively: %v", err)
		}
	} else {
		cpCmd := exec.Command("cp", "--remove-destination", tmpManifest, manifestFile)
		if err := execCtx.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to copy temporary manifest into place: %v", err)
		}
	}

	debugf("Manifest written to %s (%d entries)\n", manifestFile, len(allEntries))
	return nil
}

// copyFile copies a single file from src to dst

func parseManifest(filePath string) (map[string]ManifestEntry, error) {
	entries := make(map[string]ManifestEntry)

	file, err := os.Open(filePath)
	if err != nil {
		// Treat non-existent base manifest as an empty manifest.
		if os.IsNotExist(err) {
			return entries, nil
		}
		return nil, fmt.Errorf("failed to open manifest file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if the line represents a directory.
		// We look for a line that ends with '/'.
		if strings.HasSuffix(line, "/") {
			// Directories in manifest are just paths ending in /
			// We don't check for field count because paths can contain spaces.
			continue
		}

		// The manifest format is: FILENAME<whitespace>CHECKSUM
		// or FILENAME<whitespace><whitespace>CHECKSUM
		// Since filenames can contain spaces, we separate by the LAST whitespace.

		lastSpace := strings.LastIndexAny(line, " \t")
		if lastSpace == -1 {
			return nil, fmt.Errorf("invalid manifest line format (no separation): %s", line)
		}

		path := strings.TrimSpace(line[:lastSpace])
		checksum := strings.TrimSpace(line[lastSpace:])

		if path == "" || checksum == "" {
			return nil, fmt.Errorf("invalid manifest line format: %s", line)
		}

		entries[path] = ManifestEntry{Path: path, Checksum: checksum}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading manifest file %s: %w", filePath, err)
	}

	return entries, nil
}

// updateManifestWithNewFiles appends new entries from stagingManifest2 to stagingManifest.
// This operation requires root privileges, so it uses the global RootExec.

func updateManifestWithNewFiles(stagingManifest, stagingManifest2 string) error {
	// 1. Parse the base manifest (currently tracked files)
	// NOTE: parseManifest likely handles reading the file contents, which may require
	// elevated access if called during installation, but here it's likely called on
	// staged files, which should be accessible by the running user.
	baseEntries, err := parseManifest(stagingManifest)
	if err != nil {
		return fmt.Errorf("error parsing base manifest (%s): %w", stagingManifest, err)
	}

	// 2. Parse the new manifest (newly staged files)
	newEntries, err := parseManifest(stagingManifest2)
	if err != nil {
		return fmt.Errorf("error parsing new manifest (%s): %w", stagingManifest2, err)
	}

	// 3. Determine new files to add
	newFilesToTrack := make([]ManifestEntry, 0)
	const zeroChecksum = "000000" // The required replacement checksum

	for path, newEntry := range newEntries {
		// Ignore manifest and signature files.
		if strings.Contains(path, "staging-manifest") || strings.HasSuffix(path, "/signature") {
			continue
		}

		// Check if the file path exists in the original base manifest
		if _, exists := baseEntries[path]; !exists {
			// This is a new file! Add it to the list to be appended,
			// but with the zero checksum.

			entryToAdd := newEntry
			entryToAdd.Checksum = zeroChecksum
			newFilesToTrack = append(newFilesToTrack, entryToAdd)
		}
	}

	// If no new files were found, we are done.
	if len(newFilesToTrack) == 0 {
		return nil
	}

	// 4. CENTRALIZED PRIVILEGED APPEND (Replaces os.OpenFile and writer logic)

	// First, format the data we want to append into an in-memory string.
	var manifestLines strings.Builder
	for _, entry := range newFilesToTrack {
		// Append new entries in the specified format: path<space><space>checksum<newline>
		manifestLines.WriteString(fmt.Sprintf("%s  %s\n", entry.Path, entry.Checksum))
	}

	if os.Geteuid() == 0 {
		f, err := os.OpenFile(stagingManifest, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open manifest for appending natively: %w", err)
		}
		defer f.Close()
		if _, err := f.WriteString(manifestLines.String()); err != nil {
			return fmt.Errorf("failed to append to manifest natively: %w", err)
		}
	} else {
		// Second, use the RootExec to run the privileged 'tee -a' command.
		// 'tee -a' reads from stdin and appends to the specified file, running as root
		// via the Executor's mechanism (e.g., sudo).

		// Arguments: tee -a <stagingManifest>
		cmd := exec.Command("tee", "-a", stagingManifest)
		cmd.Stdout = io.Discard

		// Pipe the data from the strings.Builder into the command's standard input
		cmd.Stdin = strings.NewReader(manifestLines.String())

		// Run the command using the global RootExec
		if err := RootExec.Run(cmd); err != nil {
			return fmt.Errorf("failed to append to manifest file %s via RootExec: %w", stagingManifest, err)
		}
	}

	return nil
}

// removeManifestEntries removes specified file paths from a manifest file.
// filesToRemove is a map of file paths (relative to root) that should be removed from the manifest.
func removeManifestEntries(manifestPath string, filesToRemove map[string]bool, execCtx *Executor) error {
	// Check if manifest exists
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return nil // No manifest to update
	}

	// Read the manifest
	entries, err := parseManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Remove entries that are in filesToRemove
	removed := false
	for path := range entries {
		// Normalize path for comparison (remove leading/trailing slashes, clean)
		cleanPath := filepath.Clean(path)
		// Also check without leading slash
		cleanPathNoSlash := strings.TrimPrefix(cleanPath, "/")
		if filesToRemove[cleanPath] || filesToRemove[cleanPathNoSlash] {
			delete(entries, path)
			removed = true
		}
	}

	// If nothing was removed, we're done
	if !removed {
		return nil
	}

	// Write the updated manifest back
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "hokuto-manifest-remove-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Write all remaining entries
	// Sort entries for consistent output
	var sortedPaths []string
	for path := range entries {
		sortedPaths = append(sortedPaths, path)
	}
	sort.Strings(sortedPaths)

	// Separate directories, symlinks, and regular files
	var dirs, symlinks, regularFiles []string
	for _, path := range sortedPaths {
		entry := entries[path]
		if strings.HasSuffix(path, "/") {
			dirs = append(dirs, path)
		} else if entry.Checksum == "000000" {
			symlinks = append(symlinks, path)
		} else {
			regularFiles = append(regularFiles, path)
		}
	}

	// Write directories first, then symlinks, then regular files
	for _, path := range dirs {
		if _, err := fmt.Fprintf(tmpFile, "%s\n", path); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write directory entry: %w", err)
		}
	}
	for _, path := range symlinks {
		entry := entries[path]
		if _, err := fmt.Fprintf(tmpFile, "%s  %s\n", path, entry.Checksum); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write symlink entry: %w", err)
		}
	}
	for _, path := range regularFiles {
		entry := entries[path]
		if _, err := fmt.Fprintf(tmpFile, "%s  %s\n", path, entry.Checksum); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write file entry: %w", err)
		}
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if os.Geteuid() == 0 {
		if err := copyFile(tmpPath, manifestPath); err != nil {
			return fmt.Errorf("failed to update manifest natively: %w", err)
		}
	} else {
		// Copy temp file to manifest location using executor for proper permissions
		cpCmd := exec.Command("cp", tmpPath, manifestPath)
		if err := execCtx.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to update manifest: %w", err)
		}
	}

	return nil
}
