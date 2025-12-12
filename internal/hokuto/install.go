package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gookit/color"
)

func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes bool) error {

	// Special handling for glibc: direct extraction without staging or checks
	if pkgName == "glibc" {
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
	needsRootBuild := false
	if _, err := os.Stat(asRootFile); err == nil {
		needsRootBuild = true
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
				cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
				if err := execCtx.Run(cpCmd); err != nil {
					return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
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
