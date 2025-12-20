package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gookit/color"
)

// getRebuildTriggers parses /etc/hokuto.rebuild and returns packages that should
// be rebuilt when the given trigger package is installed.
// Format: triggerpkg pkg1 pkg2 pkg3...
// Returns empty slice if no triggers found or file doesn't exist.
func getRebuildTriggers(triggerPkg string, rootDir string) []string {
	rebuildFilePath := filepath.Join(rootDir, "etc/hokuto.rebuild")
	if rootDir == "/" {
		rebuildFilePath = "/etc/hokuto.rebuild"
	}

	data, err := readFileAsRoot(rebuildFilePath)
	if err != nil {
		// File doesn't exist or can't be read - that's fine, just return empty
		return nil
	}

	var packagesToRebuild []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue // Need at least trigger package and one package to rebuild
		}

		// First field is the trigger package
		if fields[0] == triggerPkg {
			// Return all packages after the trigger
			packagesToRebuild = append(packagesToRebuild, fields[1:]...)
			break // Found matching trigger, no need to continue
		}
	}

	return packagesToRebuild
}

func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes bool) error {

	// Special handling for glibc: direct extraction without staging or checks
	if pkgName == "glibc" {
		// Check lock for glibc by parsing version from filename
		base := filepath.Base(tarballPath)
		nameWithoutExt := strings.TrimSuffix(base, ".tar.zst")
		parts := strings.Split(nameWithoutExt, "-")
		if len(parts) >= 3 {
			version := parts[len(parts)-2]
			if err := checkLock(pkgName, version); err != nil {
				colArrow.Print("-> ")
				colError.Println(err)
				return err
			}
		}

		colArrow.Print("-> ")
		colSuccess.Println("Installing glibc using direct extraction method")

		var extractErr error

		// Use system tar if available
		if _, err := exec.LookPath("tar"); err == nil {
			args := []string{"xf", tarballPath, "-C", rootDir}
			tarCmd := exec.Command("tar", args...)
			tarCmd.Stdout = os.Stdout
			tarCmd.Stderr = os.Stderr

			extractErr = execCtx.Run(tarCmd)
			if extractErr == nil {
				colArrow.Print("-> ")
				colSuccess.Println("glibc installed successfully via direct extraction.")
			}
		} else {
			// Fallback to Go implementation if tar not available
			extractErr = unpackTarballFallback(tarballPath, rootDir)
			if extractErr == nil {
				colArrow.Print("-> ")
				colSuccess.Println("glibc installed successfully via direct extraction (fallback).")
			}
		}

		if extractErr != nil {
			return fmt.Errorf("failed to extract glibc tarball: %v", extractErr)
		}

		// Always run post-install hook for glibc
		if err := executePostInstall(pkgName, rootDir, execCtx, cfg); err != nil {
			colArrow.Print("-> ")
			color.Danger.Printf("post-install for %s returned error: %v\n", pkgName, err)
		}

		return nil
	}

	stagingDir := filepath.Join(tmpDir, pkgName, "staging")
	pkgTmpDir := filepath.Join(tmpDir, pkgName)

	// Declare and initialize the 'failed' slice for tracking non-fatal errors
	var failed []string

	// Clean staging dir
	os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("failed to create staging dir: %v", err)
	}

	// 1. Unpack tarball into staging
	debugf("Unpacking %s into %s\n", tarballPath, stagingDir)

	// Try system tar first
	if _, err := exec.LookPath("tar"); err == nil {
		untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
		if err := execCtx.Run(untarCmd); err == nil {
			// success with system tar
		} else {
			// fallback if tar failed
			if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
				return fmt.Errorf("failed to unpack tarball (fallback): %v", err)
			}
		}
	} else {
		// fallback if tar not found
		if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
			return fmt.Errorf("failed to unpack tarball (fallback): %v", err)
		}
	}

	// Helper function to run diff with root executor fallback if permission denied
	runDiffWithFallback := func(file1, file2 string, outputToStdout bool) error {
		// Helper to filter binary diff messages
		printFiltered := func(out string) {
			if strings.HasPrefix(out, "Binary files") && strings.Contains(out, "differ") {
				if Debug {
					fmt.Print(out)
				}
			} else {
				fmt.Print(out)
			}
		}
		// Try to check if we can read the file first
		if f, err := os.Open(file1); err != nil {
			// If we can't read file1 due to permissions, try with root executor
			if os.IsPermission(err) {
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var outBuf bytes.Buffer
				if outputToStdout {
					diffCmd.Stdout = &outBuf
					diffCmd.Stderr = os.Stderr
				}
				// diff returns non-zero when files differ, which is normal - ignore that
				_ = RootExec.Run(diffCmd)

				if outputToStdout {
					printFiltered(outBuf.String())
				}
				return nil
			}
		} else {
			f.Close()
		}

		// Try normal diff first
		diffCmd := exec.Command("diff", "-u", file1, file2)
		var outBuf bytes.Buffer
		if outputToStdout {
			diffCmd.Stdout = &outBuf
			diffCmd.Stderr = os.Stderr
		}

		err := diffCmd.Run()

		// If diff returns error (exit code 1 means diffs found, >1 means error)
		if err != nil {
			// Check if it's a permission issue by trying to read the file again
			if _, readErr := os.Open(file1); readErr != nil && os.IsPermission(readErr) {
				// Retry with root executor
				diffCmd := exec.Command("diff", "-u", file1, file2)
				outBuf.Reset()
				if outputToStdout {
					diffCmd.Stdout = &outBuf
					diffCmd.Stderr = os.Stderr
				}
				_ = RootExec.Run(diffCmd)

				if outputToStdout {
					printFiltered(outBuf.String())
				}
				return nil
			}
		}

		// Print the captured output (if any) from the normal run
		if outputToStdout {
			printFiltered(outBuf.String())
		}
		return nil
	}

	// Helper function to get diff output with root executor fallback if permission denied
	getDiffOutput := func(file1, file2 string) ([]byte, error) {
		// Try to check if we can read the file first
		if f, err := os.Open(file1); err != nil {
			// If we can't read file1 due to permissions, try with root executor
			if os.IsPermission(err) {
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var out bytes.Buffer
				diffCmd.Stdout = &out
				diffCmd.Stderr = &out
				// diff returns non-zero when files differ, which is normal - ignore that
				_ = RootExec.Run(diffCmd)
				return out.Bytes(), nil
			}
		} else {
			f.Close()
		}
		// Try normal diff first
		diffOut, err := exec.Command("diff", "-u", file1, file2).Output()
		// If diff fails, check if it's a permission issue by trying to read the file again
		if err != nil {
			if _, readErr := os.Open(file1); readErr != nil && os.IsPermission(readErr) {
				// Retry with root executor
				diffCmd := exec.Command("diff", "-u", file1, file2)
				var out bytes.Buffer
				diffCmd.Stdout = &out
				diffCmd.Stderr = &out
				_ = RootExec.Run(diffCmd)
				return out.Bytes(), nil
			}
		}
		// diff returns non-zero when files differ, which is normal - return output anyway
		return diffOut, nil
	}

	// 2. Detect user-modified files
	debugf("detect user modified files")

	// Determine if this package was built as a user (for optimization)
	// Check for asroot file in the staging directory metadata (embedded during build)
	stagingMetadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	asRootFile := filepath.Join(stagingMetadataDir, "asroot")
	versionFile := filepath.Join(stagingMetadataDir, "version")
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
	}

	// Check if package version is locked
	if data, err := os.ReadFile(versionFile); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			version := fields[0]
			if err := checkLock(pkgName, version); err != nil {
				colArrow.Print("-> ")
				colError.Println(err)
				return err
			}
		}
	}

	// Use appropriate executor for modified files detection
	var modifiedExec *Executor
	if needsRootBuild {
		// Package was built as root, use root executor
		modifiedExec = execCtx
	} else {
		// Package was built as user, use user executor for faster checksum computation
		modifiedExec = &Executor{
			Context:         execCtx.Context,
			ShouldRunAsRoot: false,
		}
		debugf("Using optimized user executor for modified files detection (package built as user)\n")
	}

	modifiedFiles, err := getModifiedFiles(pkgName, rootDir, modifiedExec)
	if err != nil {
		return err
	}

	// 3. Interactive handling of modified files
	stdinReader := bufio.NewReader(os.Stdin)
	skipAllPrompts := false // Flag to skip prompts for all remaining files
	// Track files removed from staging due to conflicts (to remove from manifest later)
	filesRemovedFromStaging := make(map[string]bool)
	// Track files that were already handled in conflict checks (to skip duplicate prompts)
	filesHandledInConflict := make(map[string]bool)
	for _, file := range modifiedFiles {
		stagingFile := filepath.Join(stagingDir, file)
		currentFile := filepath.Join(rootDir, file) // file under the install root

		// --- NEW: Find the owner package ---
		ownerPkg, err := findOwnerPackage(file)
		if err != nil {
			// Non-fatal, but print error
			cPrintf(color.FgRed, "Warning: Failed to find owner for %s: %v\n", file, err)
			ownerPkg = "UNKNOWN" // Use UNKNOWN if the lookup failed
		}
		if ownerPkg == "" {
			ownerPkg = "UNMANAGED" // Use UNMANAGED if no manifest lists the file
		}

		ownerDisplay := fmt.Sprintf("(Owner: %s) ", ownerPkg)

		if _, err := os.Stat(stagingFile); err == nil {
			// file exists in staging

			// --- NEW: Check for file conflict with another package ---
			conflictPkg, conflictChecksumMatches, isSymlink, symlinkTarget := checkFileConflict(file, currentFile, pkgName, rootDir, execCtx)
			if conflictPkg != "" && conflictChecksumMatches {
				// File is already installed from another package and checksum matches
				// Check if staging file (from new package) is a symlink or regular file
				stagingIsSymlink := false
				var stagingSymlinkTarget string
				if stagingInfo, err := os.Lstat(stagingFile); err == nil && stagingInfo.Mode()&os.ModeSymlink != 0 {
					stagingIsSymlink = true
					if target, err := os.Readlink(stagingFile); err == nil {
						stagingSymlinkTarget = target
					}
				}

				// Show conflict-specific prompt
				runDiffWithFallback(currentFile, stagingFile, true)
				os.Stdout.Sync()

				var input string
				if !yes && !skipAllPrompts {
					if isSymlink && symlinkTarget != "" {
						// Existing file is a symlink
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							cPrintf(colInfo, "Symlink %s -> %s already installed from %s package: [K]eep %s symlink, [u]se %s symlink: ", file, symlinkTarget, conflictPkg, conflictPkg, pkgName)
						} else {
							cPrintf(colInfo, "Symlink %s -> %s already installed from %s package: [K]eep %s symlink, [u]se %s file: ", file, symlinkTarget, conflictPkg, conflictPkg, pkgName)
						}
					} else {
						// Existing file is a regular file
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							cPrintf(colInfo, "File %s already installed from %s package: [K]eep %s file, [u]se %s symlink: ", file, conflictPkg, conflictPkg, pkgName)
						} else {
							cPrintf(colInfo, "File %s already installed from %s package: [K]eep %s file, [u]se %s file: ", file, conflictPkg, conflictPkg, pkgName)
						}
					}
					os.Stdout.Sync()
					response, err := stdinReader.ReadString('\n')
					if err != nil {
						response = "k" // Default to keep on read error
					}
					input = strings.TrimSpace(response)
				}
				if input == "" {
					input = "k" // Default to keep if user presses enter or if in --yes mode
				}
				switch strings.ToLower(input) {
				case "k":
					// Keep the file from the other package - delete from staging
					rmCmd := exec.Command("rm", "-f", stagingFile)
					if err := execCtx.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
					}
					// Track this file for manifest removal
					filesRemovedFromStaging[file] = true
					if isSymlink {
						debugf("Kept symlink from %s package, removed from staging: %s -> %s\n", conflictPkg, file, symlinkTarget)
					} else {
						debugf("Kept file from %s package, removed from staging: %s\n", conflictPkg, file)
					}
					continue // Skip to next file
				case "u":
					// Use the new file from current package - mark as handled and skip modified file prompt
					filesHandledInConflict[file] = true
					// File stays in staging, continue to next file (skip modified file handling)
					continue
				default:
					// Invalid input, default to keep
					rmCmd := exec.Command("rm", "-f", stagingFile)
					if err := execCtx.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
					}
					// Track this file for manifest removal
					filesRemovedFromStaging[file] = true
					if isSymlink {
						debugf("Kept symlink from %s package (invalid input), removed from staging: %s -> %s\n", conflictPkg, file, symlinkTarget)
					} else {
						debugf("Kept file from %s package (invalid input), removed from staging: %s\n", conflictPkg, file)
					}
					continue
				}
			}

			// Skip if this file was already handled in conflict check
			if filesHandledInConflict[file] {
				continue
			}

			// Try to display diff, retry with root executor if permission denied
			runDiffWithFallback(currentFile, stagingFile, true)
			// Flush stdout to ensure diff output is visible before prompt
			os.Stdout.Sync()

			var input string
			if !yes && !skipAllPrompts {
				cPrintf(colInfo, "File %s modified, %schoose action: [k]eep current, [U]se new, [e]dit, use new for [A]ll: ", file, ownerDisplay)
				// Flush stdout to ensure prompt is visible
				os.Stdout.Sync()
				// Use the shared, robust bufio.Reader
				response, err := stdinReader.ReadString('\n')
				if err != nil {
					// Default to 'u' on read error (e.g., Ctrl+D)
					response = "u"
				}
				input = strings.TrimSpace(response)
			}
			if input == "" {
				input = "u" // Default to 'use new' if user presses enter or if in --yes mode
			}
			switch strings.ToLower(input) {
			case "k":
				// Check if currentFile is a symlink
				currentInfo, err := os.Lstat(currentFile)
				if err == nil && currentInfo.Mode()&os.ModeSymlink != 0 {
					// It's a symlink - preserve it by reading the target and recreating the symlink
					linkTarget, err := os.Readlink(currentFile)
					if err != nil {
						return fmt.Errorf("failed to read symlink %s: %v", currentFile, err)
					}
					// Remove existing file/symlink in staging if it exists (use executor for proper permissions)
					rmCmd := exec.Command("rm", "-f", stagingFile)
					if err := execCtx.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove existing file %s: %v", stagingFile, err)
					}
					// Recreate the symlink in staging using executor for proper permissions
					lnCmd := exec.Command("ln", "-s", linkTarget, stagingFile)
					if err := execCtx.Run(lnCmd); err != nil {
						return fmt.Errorf("failed to recreate symlink %s -> %s: %v", stagingFile, linkTarget, err)
					}
				} else {
					// It's a regular file - copy it normally
					cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
					if err := execCtx.Run(cpCmd); err != nil {
						return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
					}
				}
			case "u":
				// keep staging file as-is
			case "a":
				// Use new for all remaining files - set flag and use new for this file
				skipAllPrompts = true
				// keep staging file as-is (same as "u")
			case "e":
				// --- NEW: Get original staging file permissions ---
				stagingInfo, err := os.Stat(stagingFile)
				if err != nil {
					return fmt.Errorf("failed to stat staging file %s: %v", stagingFile, err)
				}
				originalMode := stagingInfo.Mode()
				// read staging content
				stContent, err := os.ReadFile(stagingFile)
				if err != nil {
					return fmt.Errorf("failed to read staging file %s: %v", stagingFile, err)
				}

				// produce unified diff (currentFile vs stagingFile); ignore diff errors (non-zero exit means differences)
				// Try to get diff output, retry with root executor if permission denied
				diffOut, _ := getDiffOutput(currentFile, stagingFile) // we don't fail if diff returns non-zero

				// create temp file prefilled with staging content + marked diff
				tmp, err := os.CreateTemp("", "hokuto-edit-")
				if err != nil {
					return fmt.Errorf("failed to create temp file for editing: %v", err)
				}
				tmpPath := tmp.Name()
				defer func() {
					tmp.Close()
					_ = os.Remove(tmpPath)
				}()

				if _, err := tmp.Write(stContent); err != nil {
					return fmt.Errorf("failed to write staging content to temp file: %v", err)
				}

				// append a separator and diff output for reference
				if len(diffOut) > 0 {
					if _, err := tmp.WriteString("\n\n--- diff (installed -> staging) ---\n"); err != nil {
						return fmt.Errorf("failed to write diff header to temp file: %v", err)
					}
					if _, err := tmp.Write(diffOut); err != nil {
						return fmt.Errorf("failed to write diff to temp file: %v", err)
					}
				}

				// close before launching editor
				if err := tmp.Close(); err != nil {
					return fmt.Errorf("failed to close temp file before editing: %v", err)
				}

				editor := os.Getenv("EDITOR")
				if editor == "" {
					editor = "nano"
				}

				// Launch editor against the temp file as the invoking user so they can edit comfortably.
				editCmd := exec.Command(editor, tmpPath)
				editCmd.Stdin, editCmd.Stdout, editCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := editCmd.Run(); err != nil {
					return fmt.Errorf("editor failed: %v", err)
				}

				// After editing, copy temp back to staging
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", tmpPath, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to copy edited file back to staging %s: %v", stagingFile, err)
				}
				// --- NEW: Explicitly restore permissions ---
				// The `cp --preserve=mode` relies on the temp file's mode, which is wrong.
				// Use chmod to ensure the correct original mode is set.
				// We format the mode to an octal string (e.g., "0644").
				modeStr := fmt.Sprintf("%#o", originalMode.Perm())

				chmodCmd := exec.Command("chmod", modeStr, stagingFile)
				if err := execCtx.Run(chmodCmd); err != nil {
					return fmt.Errorf("failed to restore permissions on %s to %s: %v", stagingFile, modeStr, err)
				}
			}
		} else {
			// file does NOT exist in staging
			ans := "n" // Default to not keeping the file
			if !yes {
				cPrintf(colInfo, "User modified %s, but new package has no file. Keep it? [y/N]: ", file)
				// Use the shared, robust bufio.Reader
				response, err := stdinReader.ReadString('\n')
				if err == nil {
					ans = strings.ToLower(strings.TrimSpace(response))
				}
			}
			if ans == "y" {
				// ensure staging directory exists (run as root)
				stagingFileDir := filepath.Dir(stagingFile)
				mkdirCmd := exec.Command("mkdir", "-p", stagingFileDir)
				if err := execCtx.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", stagingFileDir, err)
				}
				// copy current file into staging preserving attributes
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", currentFile, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to copy %s to staging: %v", file, err)
				}
				debugf("Kept modified file by copying %s into staging\n", file)
			} else {
				// user chose not to keep it -> remove the installed file (run as root)
				rmCmd := exec.Command("rm", "-f", currentFile)
				if err := execCtx.Run(rmCmd); err != nil {
					// warn but continue install; do not abort the whole install for a removal failure
					cPrintf(colWarn, "Warning: failed to remove %s: %v\n", currentFile, err)
				} else {
					debugf("Removed user-modified file: %s\n", file)
				}
			}
		}
	}

	// Note: Manifest entries for removed files will be cleaned up in checkStagingConflicts
	// after the manifest is generated, to avoid modifying the tarball's manifest

	// Generate updated manifest of staging
	debugf("Generating staging manifest\n")
	stagingManifest := stagingDir + "/var/db/hokuto/installed/" + pkgName + "/manifest"
	stagingManifest2dir := "/tmp/staging-manifest-" + pkgName
	stagingManifest2file := filepath.Join(stagingManifest2dir, "/manifest")

	// Use appropriate executor for manifest generation (reuse the same logic as modified files detection)
	var manifestExec *Executor
	if needsRootBuild {
		// Package was built as root, use root executor
		manifestExec = execCtx
	} else {
		// Package was built as user, use user executor for faster manifest generation
		manifestExec = &Executor{
			Context:         execCtx.Context,
			ShouldRunAsRoot: false,
		}
		debugf("Using optimized user executor for manifest generation (package built as user)\n")
	}

	if err := generateManifest(stagingDir, stagingManifest2dir, manifestExec); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}
	debugf("Generate update manifest\n")
	if err := updateManifestWithNewFiles(stagingManifest, stagingManifest2file); err != nil {
		fmt.Fprintf(os.Stderr, "Manifest update failed: %v\n", err)
	}

	// Delete stagingManifest2dir
	rmCmd := exec.Command("rm", "-rf", stagingManifest2dir)
	if err := execCtx.Run(rmCmd); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove StagingManifest: %v", err)
	}

	// 3.5. Check for conflicts with existing files (for both fresh installs and upgrades)
	// This handles cases where files exist on disk but are not tracked by any package
	// (e.g., user chose to "keep existing" during a previous install)
	debugf("Checking for conflicts with existing files\n")
	if err := checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest, execCtx, yes, filesRemovedFromStaging, nil); err != nil {
		return err
	}

	// 4. Determine obsolete files (compare manifests)
	debugf("Find obsolete files\n")
	filesToDelete, err := removeObsoleteFiles(pkgName, stagingDir, rootDir)
	if err != nil {
		return err
	}

	// --- NEW: Dependency Check and Backup (Before deletion) ---
	debugf("Dependency check")
	affectedPackages := make(map[string]struct{})
	libFilesToDelete := make(map[string]struct{})
	tempLibBackupDir, err := os.MkdirTemp(tmpDir, "hokuto-lib-backup-")
	if err != nil {
		return fmt.Errorf("failed to create temporary backup directory: %v", err)
	}
	// CLEANUP: Ensure the backup directory is removed on exit
	defer func() {
		if !Debug {
			rmCmd := exec.Command("rm", "-rf", tempLibBackupDir)
			if err := execCtx.Run(rmCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to cleanup temporary library backup: %v\n", err)
			}
		} else {
			fmt.Fprintf(os.Stderr, "INFO: Skipping cleanup of %s due to HOKUTO_DEBUG=1\n", tempLibBackupDir)
		}
	}()

	// 4a. Check filesToDelete against all libdeps
	allInstalledEntries, err := os.ReadDir(Installed)
	if err == nil {
		for _, entry := range allInstalledEntries {
			if !entry.IsDir() || entry.Name() == pkgName {
				continue // Skip files or the package currently being installed
			}

			otherPkgName := entry.Name()
			libdepsPath := filepath.Join(Installed, otherPkgName, "libdeps")

			libdepsContent, err := readFileAsRoot(libdepsPath)
			if err != nil {
				continue // Skip if libdeps file is unreadable
			}

			// Check if any file in filesToDelete is a libdep of otherPkgName
			lines := strings.Split(string(libdepsContent), "\n")
			for _, line := range lines {
				libPath := strings.TrimSpace(line)
				if libPath == "" {
					continue
				}

				// Construct the absolute path to the library file currently on the system
				// This is primarily for the OLD format (full path in libdeps).
				absLibPath := libPath
				if rootDir != "/" && strings.HasPrefix(libPath, "/") {
					// Old format: path is absolute, reconstruct relative to rootDir
					absLibPath = filepath.Join(rootDir, libPath[1:])
				} else if !strings.HasPrefix(libPath, "/") {
					// Handle defensively, but for the NEW format (basename), we will use the full path
					// from filesToDelete, ignoring this potentially incorrect path construction.
					absLibPath = filepath.Join(rootDir, libPath)
				}

				// Determine if the libPath is a full absolute path or just a basename.
				isFullPath := strings.HasPrefix(libPath, "/")

				// Check if this library is scheduled for deletion
				matchFound := false
				finalAbsPath := "" // Stores the correct absolute path of the file being deleted

				for _, fileToDelete := range filesToDelete {

					if isFullPath {
						// Case 1: Old format (full path in libdeps).
						// Match the full path (relying on absLibPath reconstruction).
						if fileToDelete == absLibPath {
							finalAbsPath = absLibPath
							matchFound = true
						}
					} else {
						// Case 2: New format (basename only in libdeps).
						// Match the basename of the file being deleted against the libdep entry.
						fileToDeleteBasename := filepath.Base(fileToDelete)
						if fileToDeleteBasename == libPath {
							// Found a match, use the actual path being deleted
							finalAbsPath = fileToDelete
							matchFound = true
						}
					}

					if matchFound {
						affectedPackages[otherPkgName] = struct{}{}
						libFilesToDelete[finalAbsPath] = struct{}{}
						// Break inner loop (over filesToDelete) and check the next libdep
						break
					}
				}
			}
		}
	}

	// 4b. Backup all affected library files
	for libPath := range libFilesToDelete {
		// libPath is the HOKUTO_ROOT-prefixed path (e.g., /tmp/hokuto/usr/lib/libfoo.so)

		// Determine the relative path inside the HOKUTO_ROOT (e.g., usr/lib/libfoo.so)
		relPath, err := filepath.Rel(rootDir, libPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to determine relative path for backup %s: %v\n", libPath, err)
			continue
		}

		// Construct the full backup path (e.g., /tmp/hokuto-lib-backup-XXXX/usr/lib/libfoo.so)
		backupPath := filepath.Join(tempLibBackupDir, relPath)
		backupDir := filepath.Dir(backupPath)

		// Create the directory structure in the backup location
		mkdirCmd := exec.Command("mkdir", "-p", backupDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create backup dir %s: %v", backupDir, err)
		}

		// Copy the library file to the backup location
		cpCmd := exec.Command("cp", "--remove-destination", "--preserve=mode,ownership,timestamps", libPath, backupPath)
		if err := execCtx.Run(cpCmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to backup library %s: %v\n", libPath, err)
		} else {
			cPrintf(colInfo, "Backed up affected library %s to %s\n", libPath, backupPath)
		}
	}

	// 5. Rsync staging into root
	debugf("Rsync staging into root")
	if err := rsyncStaging(stagingDir, rootDir, execCtx); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd := exec.Command("rm", "-f", p)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Printf("warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			debugf("Removed obsolete file: %s\n", p)
		}
	}

	// 7. Run package post-install script
	colArrow.Print("-> ")
	colSuccess.Println("Executing package post-install script")
	if err := executePostInstall(pkgName, rootDir, execCtx, cfg); err != nil {
		fmt.Printf("warning: post-install for %s returned error: %v\n", pkgName, err)
	}

	// 7.5. Check for rebuild triggers from /etc/hokuto.rebuild
	rebuildTriggerPkgs := getRebuildTriggers(pkgName, rootDir)
	if len(rebuildTriggerPkgs) > 0 {
		colArrow.Print("-> ")
		colSuccess.Print("DKMS trigger: ")
		cPrintf(colNote, "%s\n", strings.Join(rebuildTriggerPkgs, " "))
		shouldRebuild := yes // Default to true if --yes flag is set
		if !yes {
			// Use custom prompt to match requested format
			colArrow.Print("-> ")
			colWarn.Printf("Rebuild the packages? [Y/n]")
			os.Stdout.Sync()
			response, err := stdinReader.ReadString('\n')
			if err != nil {
				shouldRebuild = false // Default to no on read error
			} else {
				response = strings.ToLower(strings.TrimSpace(response))
				shouldRebuild = response == "y" || response == "yes" || response == ""
			}
		}

		if shouldRebuild {
			for _, rebuildPkg := range rebuildTriggerPkgs {
				debugf("\n--- Rebuilding %s (triggered by %s) ---\n", rebuildPkg, pkgName)

				// Pass empty string for oldLibsDir since this is a trigger-based rebuild, not a library dependency rebuild
				if err := pkgBuildRebuild(rebuildPkg, cfg, execCtx, ""); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s (triggered by %s) failed: %v", rebuildPkg, pkgName, err))
					cPrintf(colWarn, "WARNING: Rebuild of %s failed: %v\n", rebuildPkg, err)
					continue
				}

				rebuildOutputDir := filepath.Join(tmpDir, rebuildPkg, "output")

				if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
					failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", rebuildPkg, err))
					cPrintf(colWarn, "WARNING: Failed to sync rebuilt package %s to root: %v\n", rebuildPkg, err)
					continue
				}

				rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, rebuildPkg))
				if err := execCtx.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", rebuildPkg, err)
				}
				colArrow.Print("-> ")
				cPrintf(colSuccess, "Rebuild of %s finished and installed.\n", rebuildPkg)
			}
		} else {
			colArrow.Print("-> ")
			cPrintf(colInfo, "Skipping rebuild of %s\n", strings.Join(rebuildTriggerPkgs, ", "))
		}
	}

	// --- Rebuild Affected Packages (Step 8) ---
	if len(affectedPackages) > 0 {
		affectedList := make([]string, 0, len(affectedPackages))
		for pkg := range affectedPackages {
			affectedList = append(affectedList, pkg)
		}
		sort.Strings(affectedList)

		// 8a. Prompt for rebuild (Hokuto is guaranteed to be run in a terminal)
		cPrintf(colWarn, "\nWARNING: The following packages depend on libraries that were removed/upgraded:\n  %s\n", strings.Join(affectedList, ", "))

		// Interactive rebuild selection
		var packagesToRebuild []string
		rebuildAll := false // Flag to track if 'a' (all) was selected

		if !yes {
			// Use the same robust reader we defined earlier
			for _, pkg := range affectedList {
				if rebuildAll {
					// 'all' was selected, just add and continue
					packagesToRebuild = append(packagesToRebuild, pkg)
					cPrintf(colInfo, "Rebuilding %s (auto-selected by 'all')\n", pkg)
					continue
				}

				// Prompt for this specific package
				cPrintf(colInfo, "Rebuild %s? [Y/n/a(ll)/q(uit)]: ", pkg)
				response, err := stdinReader.ReadString('\n')
				if err != nil {
					response = "q" // Treat error (like Ctrl+D) as 'quit'
				}
				response = strings.ToLower(strings.TrimSpace(response))

				switch response {
				case "y", "": // Default is Yes
					packagesToRebuild = append(packagesToRebuild, pkg)
				case "n": // No
					cPrintf(colInfo, "Skipping rebuild for %s\n", pkg)
					continue
				case "a": // All
					cPrintf(colInfo, "Rebuilding %s and all subsequent packages\n", pkg)
					rebuildAll = true
					packagesToRebuild = append(packagesToRebuild, pkg)
				case "q": // Quit
					cPrintf(colInfo, "Quitting rebuild selection. No more packages will be rebuilt.\n")
					goto RebuildSelectionDone // Break out of the loop
				default: // Invalid, treat as 'No' for safety
					cPrintf(colInfo, "Invalid input. Skipping rebuild for %s\n", pkg)
					continue
				}
			}
		RebuildSelectionDone: // Label for the 'quit' jump
			// This is just a label, execution continues normally after the loop if 'q' wasn't used.
		} else {
			// If --yes is passed, just rebuild all affected packages (original behavior)
			cPrintf(colInfo, "Rebuilding all affected packages due to --yes flag.\n")
			packagesToRebuild = affectedList
		}

		// 8b. Perform rebuild
		if len(packagesToRebuild) > 0 {
			colArrow.Print("-> ")
			colSuccess.Println("Starting rebuild of affected packages")
			for _, pkg := range packagesToRebuild {
				cPrintf(colInfo, "\n--- Rebuilding %s ---\n", pkg)

				if err := pkgBuildRebuild(pkg, cfg, execCtx, tempLibBackupDir); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s failed: %v", pkg, err))
					cPrintf(colWarn, "WARNING: Rebuild of %s failed: %v\n", pkg, err)
					continue // Skip to next package on failure, same as hokuto update
				}

				rebuildOutputDir := filepath.Join(tmpDir, pkg, "output")

				if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
					failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", pkg, err))
					cPrintf(colWarn, "WARNING: Failed to sync rebuilt package %s to root: %v\n", pkg, err)
					continue // Skip cleanup on sync failure
				}

				rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, pkg))
				if err := execCtx.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", pkg, err)
				}
				cPrintf(colNote, "Rebuild of %s finished and installed.\n", pkg)
			}
		}
	}

	// 9. Cleanup
	rmCmd2 := exec.Command("rm", "-rf", pkgTmpDir)
	if err := execCtx.Run(rmCmd2); err != nil {
		fmt.Fprintf(os.Stderr, "failed to cleanup: %v\n", err)
	}

	// 10. Report failures if any
	if len(failed) > 0 { // 'failed' slice is correctly declared at the start of pkgInstall
		return fmt.Errorf("some file actions failed:\n%s", strings.Join(failed, "\n"))
	}

	// 11. Run global post-install tasks
	if err := PostInstallTasks(RootExec); err != nil {
		fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
	}
	return nil
}

// uninstallPackage removes an installed package safely.
// - pkgName: package to remove
// - cfg: configuration (used for HOKUTO_ROOT)
// - execCtx: Executor that must have ShouldRunAsRoot=true (RootExec)
// - force: ignore reverse-dep checks
// - yes: assume confirmation

// checkStagingConflicts checks for conflicts between files in staging and existing files in the target.
// This handles fresh installs where the package is not installed but files may already exist.
// filesHandledInConflict is optional and only used for tracking (can be nil for fresh installs).
func checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest string, execCtx *Executor, yes bool, filesRemovedFromStaging map[string]bool, filesHandledInConflict map[string]bool) error {
	// Read the staging manifest
	stagingData, err := os.ReadFile(stagingManifest)
	if err != nil {
		// No staging manifest (shouldn't happen, but handle gracefully)
		return nil
	}

	// Build a map of file -> owner package once (instead of calling findOwnerPackage for each file)
	// This is much more efficient when checking many files
	fileOwnerMap := make(map[string]string)
	// Also build a set of files owned by the current package (for upgrade scenarios)
	currentPkgFiles := make(map[string]bool)

	// First, check if current package is installed and build its file set
	installedManifestPath := filepath.Join(rootDir, Installed, pkgName, "manifest")
	if data, err := os.ReadFile(installedManifestPath); err == nil {
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
			manifestFilePath := fields[0]
			cleanPath := filepath.Clean(manifestFilePath)
			cleanPathNoSlash := strings.TrimPrefix(cleanPath, "/")
			currentPkgFiles[cleanPath] = true
			currentPkgFiles[cleanPathNoSlash] = true
		}
	}

	entries, err := os.ReadDir(Installed)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			otherPkgName := e.Name()
			if otherPkgName == pkgName {
				continue // Skip current package (already handled above)
			}
			manifestPath := filepath.Join(Installed, otherPkgName, "manifest")
			data, err := os.ReadFile(manifestPath)
			if err != nil {
				continue
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
				manifestFilePath := fields[0]
				// Store both with and without leading slash for fast lookup
				cleanPath := filepath.Clean(manifestFilePath)
				cleanPathNoSlash := strings.TrimPrefix(cleanPath, "/")
				fileOwnerMap[cleanPath] = otherPkgName
				if cleanPathNoSlash != cleanPath {
					fileOwnerMap[cleanPathNoSlash] = otherPkgName
				}
			}
		}
	}

	// Helper function to run diff with root executor fallback if permission denied
	runDiffWithFallback := func(file1, file2 string, outputToStdout bool) error {
		// Helper to filter binary diff messages
		printFiltered := func(out string) {
			if strings.HasPrefix(out, "Binary files") && strings.Contains(out, "differ") {
				if Debug {
					fmt.Printf("%s\n", out)
				}
				return
			}
			if outputToStdout {
				fmt.Print(out)
			}
		}

		diffCmd := exec.Command("diff", "-u", file1, file2)
		var out bytes.Buffer
		diffCmd.Stdout = &out
		diffCmd.Stderr = io.Discard

		// Try with current executor first
		err := execCtx.Run(diffCmd)
		// diff returns exit code 1 when files differ (which is normal), >1 for errors
		if err != nil {
			// Check if it's a permission issue
			if strings.Contains(err.Error(), "permission denied") || strings.Contains(out.String(), "Permission denied") {
				// Try with root executor
				rootDiffCmd := exec.Command("diff", "-u", file1, file2)
				var rootOut bytes.Buffer
				rootDiffCmd.Stdout = &rootOut
				rootDiffCmd.Stderr = io.Discard
				if rootErr := RootExec.Run(rootDiffCmd); rootErr == nil {
					printFiltered(rootOut.String())
					return nil
				}
			}
			// If diff returns non-zero (files differ), that's expected, just print output
			// Exit code 1 means files differ (normal), >1 means error
			if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
				printFiltered(out.String())
				return nil
			}
			// Other errors - try to print what we have
			if out.Len() > 0 {
				printFiltered(out.String())
			}
			return nil // Don't fail on diff errors
		}
		printFiltered(out.String())
		return nil
	}

	stdinReader := bufio.NewReader(os.Stdin)
	skipAllPrompts := false
	useOriginalForAll := false // Flag to use original for all remaining alternatives
	useNewForAll := false      // Flag to use new for all remaining alternatives

	scanner := bufio.NewScanner(strings.NewReader(string(stagingData)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue // Skip directories
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		filePath := parts[0] // Path from manifest (may have leading slash)
		// Normalize path: remove leading slash for comparison
		filePathClean := strings.TrimPrefix(filePath, "/")
		filePathClean = filepath.Clean(filePathClean)

		// Ignore internal metadata files
		if strings.Contains(filePathClean, "var/db/hokuto") {
			continue
		}

		stagingFile := filepath.Join(stagingDir, strings.TrimPrefix(filePath, "/"))
		targetFile := filepath.Join(rootDir, strings.TrimPrefix(filePath, "/"))

		// Check if file exists in target location
		if _, err := os.Lstat(targetFile); os.IsNotExist(err) {
			continue // File doesn't exist, no conflict
		}

		// File exists in target - check for conflicts using cached owner map
		// First check if file is owned by current package (normal upgrade scenario)
		if currentPkgFiles[filePathClean] || currentPkgFiles[filePath] {
			// File is in current package's manifest - this is a normal upgrade, skip conflict check
			continue
		}

		ownerPkg := fileOwnerMap[filePathClean]
		if ownerPkg == "" {
			// Try with leading slash
			ownerPkg = fileOwnerMap[filePath]
		}

		if ownerPkg != "" && ownerPkg != pkgName {
			// File is owned by another package - apply conflict logic
			// Only check checksum if we found an owner (avoid expensive checkFileConflict if not needed)
			conflictPkg, conflictChecksumMatches, isSymlink, symlinkTarget := checkFileConflict(filePath, targetFile, pkgName, rootDir, execCtx)
			if conflictPkg != "" && conflictChecksumMatches {
				// Check if staging file (from new package) is a symlink or regular file
				stagingIsSymlink := false
				var stagingSymlinkTarget string
				if stagingInfo, err := os.Lstat(stagingFile); err == nil && stagingInfo.Mode()&os.ModeSymlink != 0 {
					stagingIsSymlink = true
					if target, err := os.Readlink(stagingFile); err == nil {
						stagingSymlinkTarget = target
					}
				}

				// Show conflict-specific prompt
				runDiffWithFallback(targetFile, stagingFile, true)
				os.Stdout.Sync()

				var input string
				if !yes && !skipAllPrompts {
					if isSymlink && symlinkTarget != "" {
						// Existing file is a symlink
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							cPrintf(colInfo, "Symlink %s -> %s already installed from %s package: [K]eep %s symlink, [u]se %s symlink: ", filePath, symlinkTarget, conflictPkg, conflictPkg, pkgName)
						} else {
							cPrintf(colInfo, "Symlink %s -> %s already installed from %s package: [K]eep %s symlink, [u]se %s file: ", filePath, symlinkTarget, conflictPkg, conflictPkg, pkgName)
						}
					} else {
						// Existing file is a regular file
						if stagingIsSymlink && stagingSymlinkTarget != "" {
							cPrintf(colInfo, "File %s already installed from %s package: [K]eep %s file, [u]se %s symlink: ", filePath, conflictPkg, conflictPkg, pkgName)
						} else {
							cPrintf(colInfo, "File %s already installed from %s package: [K]eep %s file, [u]se %s file: ", filePath, conflictPkg, conflictPkg, pkgName)
						}
					}
					os.Stdout.Sync()
					response, err := stdinReader.ReadString('\n')
					if err != nil {
						response = "k" // Default to keep on read error
					}
					input = strings.TrimSpace(response)
				}
				if input == "" {
					input = "k" // Default to keep if user presses enter or if in --yes mode
				}
				switch strings.ToLower(input) {
				case "k":
					// Keep the file from the other package - save new file as alternative and delete from staging
					if err := saveAlternative(pkgName, filePath, conflictPkg, conflictPkg, stagingFile, execCtx); err != nil {
						debugf("Warning: failed to save alternative: %v\n", err)
					}
					rmCmd := exec.Command("rm", "-f", stagingFile)
					if err := execCtx.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
					}
					// Track this file for manifest removal
					filesRemovedFromStaging[filePath] = true
					if isSymlink {
						debugf("Kept symlink from %s package, saved new file as alternative, removed from staging: %s -> %s\n", conflictPkg, filePath, symlinkTarget)
					} else {
						debugf("Kept file from %s package, saved new file as alternative, removed from staging: %s\n", conflictPkg, filePath)
					}
					continue
				case "u":
					// Use the new file from current package - save existing file as alternative
					debugf("Saving alternative for %s: pkgName=%s, conflictPkg=%s, targetFile=%s\n", filePath, pkgName, conflictPkg, targetFile)
					if err := saveAlternative(pkgName, filePath, conflictPkg, conflictPkg, targetFile, execCtx); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to save alternative for %s: %v\n", filePath, err)
						debugf("Warning: failed to save alternative: %v\n", err)
					} else {
						debugf("Successfully saved alternative for %s\n", filePath)
					}
					// Mark as handled if tracking map provided (file stays in staging)
					if filesHandledInConflict != nil {
						filesHandledInConflict[filePath] = true
					}
					debugf("Using new file from %s, saved existing file from %s as alternative: %s\n", pkgName, conflictPkg, filePath)
				default:
					// Invalid input, default to keep
					if err := saveAlternative(pkgName, filePath, conflictPkg, conflictPkg, stagingFile, execCtx); err != nil {
						debugf("Warning: failed to save alternative: %v\n", err)
					}
					rmCmd := exec.Command("rm", "-f", stagingFile)
					if err := execCtx.Run(rmCmd); err != nil {
						return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
					}
					filesRemovedFromStaging[filePath] = true
					if isSymlink {
						debugf("Kept symlink from %s package (invalid input), removed from staging: %s -> %s\n", conflictPkg, filePath, symlinkTarget)
					} else {
						debugf("Kept file from %s package (invalid input), removed from staging: %s\n", conflictPkg, filePath)
					}
					continue
				}
			}
		} else {
			// File exists but is not owned by any package - save as alternative and ask user which to use
			runDiffWithFallback(targetFile, stagingFile, true)
			os.Stdout.Sync()

			var input string
			// Determine action based on flags or user input
			if useOriginalForAll {
				input = "o"
			} else if useNewForAll {
				input = "n"
			} else if !yes && !skipAllPrompts {
				cPrintf(colInfo, "File %s already exists (not managed by any package): [o]riginal, [n]ew, use [O]riginal for all, use [N]ew for all: ", filePath)
				os.Stdout.Sync()
				response, err := stdinReader.ReadString('\n')
				if err != nil {
					response = "o" // Default to original on read error
				}
				input = strings.TrimSpace(response)
				// Check for uppercase "O" or "N" for "all" flags before converting to lowercase
				if input == "O" {
					useOriginalForAll = true
					input = "o"
				} else if input == "N" {
					useNewForAll = true
					input = "n"
				}
			}
			if input == "" {
				input = "o" // Default to original if user presses enter or if in --yes mode
			}
			switch strings.ToLower(input) {
			case "o":
				// Use original file - save new file (from staging) as alternative
				debugf("Saving alternative for %s: pkgName=%s, filePath=%s, stagingFile=%s\n", filePath, pkgName, filePath, stagingFile)
				if err := saveAlternative(pkgName, filePath, pkgName, "no package", stagingFile, execCtx); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to save alternative for %s: %v\n", filePath, err)
					debugf("Warning: failed to save alternative: %v\n", err)
				} else {
					debugf("Successfully saved alternative for %s\n", filePath)
				}
				rmCmd := exec.Command("rm", "-f", stagingFile)
				if err := execCtx.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
				}
				filesRemovedFromStaging[filePath] = true
				debugf("Kept existing unmanaged file, saved new file as alternative, removed from staging: %s\n", filePath)
			case "n":
				// Use alternative (new file) - save current file (original) as alternative
				// The new file from current package will be installed, so OriginalPkg should be the current package
				debugf("Saving alternative for %s: pkgName=%s, filePath=%s, targetFile=%s\n", filePath, pkgName, filePath, targetFile)
				if err := saveAlternative(pkgName, filePath, "no package", pkgName, targetFile, execCtx); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to save alternative for %s: %v\n", filePath, err)
					debugf("Warning: failed to save alternative: %v\n", err)
				} else {
					debugf("Successfully saved alternative for %s\n", filePath)
				}
				// File stays in staging (will be installed)
				debugf("Using new file, saved existing file as alternative: %s\n", filePath)
			default:
				// Invalid input, default to original
				if err := saveAlternative(pkgName, filePath, pkgName, "no package", stagingFile, execCtx); err != nil {
					debugf("Warning: failed to save alternative: %v\n", err)
				}
				rmCmd := exec.Command("rm", "-f", stagingFile)
				if err := execCtx.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
				}
				filesRemovedFromStaging[filePath] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading staging manifest: %v", err)
	}

	// Remove entries from staging manifest for files that were removed from staging
	if len(filesRemovedFromStaging) > 0 {
		if err := removeManifestEntries(stagingManifest, filesRemovedFromStaging, execCtx); err != nil {
			// Non-fatal, but log the error
			debugf("Warning: failed to remove entries from staging manifest: %v\n", err)
		}
	}

	return nil
}
