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

// getRebuildTriggers parses /etc/hokuto/hokuto.rebuild and returns packages that should
// be rebuilt when the given trigger package is installed.
// Format: triggerpkg pkg1 pkg2 pkg3...
// Returns empty slice if no triggers found or file doesn't exist.
func getRebuildTriggers(triggerPkg string, rootDir string) []string {
	rebuildFilePath := filepath.Join(rootDir, "etc", "hokuto", "hokuto.rebuild")
	if rootDir == "/" {
		rebuildFilePath = "/etc/hokuto/hokuto.rebuild"
	}

	data, err := os.ReadFile(rebuildFilePath)
	if err != nil {
		data, err = readFileAsRoot(rebuildFilePath)
		if err != nil {
			// File doesn't exist or can't be read - that's fine, just return empty
			return nil
		}
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
			// Check if each package is installed before adding to rebuild list
			for _, pkg := range fields[1:] {
				if isPackageInstalled(pkg) {
					packagesToRebuild = append(packagesToRebuild, pkg)
				} else {
					debugf("Skipping rebuild trigger for %s (not installed)\n", pkg)
				}
			}
			break // Found matching trigger, no need to continue
		}
	}

	return packagesToRebuild
}

// pkgInstall installs a compiled hokuto package from a tarball.
// If yes is true, it assumes 'yes' to all prompts.
// If fast is true, it optimizes for speed (e.g., skip some UI/status updates).
// If managed is true, it skips internal rebuild triggers (e.g. DKMS) assuming the caller handles them.
func pkgInstall(tarballPath, pkgName string, cfg *Config, execCtx *Executor, yes, fast, managed bool, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	// "Installing" message is now handled by the caller (cli.go, update.go, build.go)
	// to avoid duplicate output.

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

		tarSuccess := false
		if _, err := exec.LookPath("tar"); err == nil {
			args := []string{"xf", tarballPath, "-C", rootDir}
			tarCmd := exec.Command("tar", args...)
			tarCmd.Stdout = os.Stdout
			tarCmd.Stderr = os.Stderr

			if err := execCtx.Run(tarCmd); err == nil {
				tarSuccess = true
				colArrow.Print("-> ")
				colSuccess.Println("glibc installed successfully via direct extraction")
			}
		}

		if !tarSuccess {
			if os.Geteuid() == 0 {
				if err := unpackTarballFallback(tarballPath, rootDir); err != nil {
					extractErr = fmt.Errorf("native fallback failed: %v", err)
				} else {
					colArrow.Print("-> ")
					colSuccess.Println("glibc installed successfully via direct extraction")
				}
			} else {
				extractErr = fmt.Errorf("System tar missing or broken, run hokuto as root!")
			}
		}

		if extractErr != nil {
			return fmt.Errorf("failed to extract glibc tarball: %v", extractErr)
		}

		// Always run post-install hook for glibc
		if err := executePostInstall(pkgName, rootDir, execCtx, cfg, logger); err != nil {
			colArrow.Print("-> ")
			color.Danger.Printf("post-install for %s returned error: %v\n", pkgName, err)
		}

		if !fast {
			// Run global post-install tasks immediately if not in fast mode
			if err := PostInstallTasks(execCtx, logger); err != nil {
				fmt.Fprintf(logger, "Warning: %v\n", err)
			}
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

	tarSuccess := false
	if _, err := exec.LookPath("tar"); err == nil {
		untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
		if err := execCtx.Run(untarCmd); err == nil {
			tarSuccess = true
		}
	}

	if !tarSuccess {
		if os.Geteuid() == 0 || execCtx.ShouldRunAsRoot {
			if err := unpackTarballFallback(tarballPath, stagingDir); err != nil {
				return fmt.Errorf("failed to unpack tarball (native): %v", err)
			}
		} else {
			return fmt.Errorf("System tar missing or broken, run hokuto as root!")
		}
	}

	// 1.5. Verify package signature
	sigLogger := logger
	if fast {
		sigLogger = io.Discard
	}
	if err := VerifyPackageSignature(stagingDir, pkgName, cfg, execCtx, sigLogger); err != nil {
		return err
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
		if !modifiedExec.ShouldRunAsRoot {
			debugf("optimized user modified files detection failed, falling back to root executor: %v\n", err)
			modifiedFiles, err = getModifiedFiles(pkgName, rootDir, execCtx) // execCtx is original (likely root)
			if err != nil {
				return err
			}
		} else {
			return err
		}
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

		// Fast path: If user selected "Use new for [A]ll" (or "yes" mode),
		// we skip expensive checks (owner lookup, conflicts, diffs) and default to "Use New".
		if skipAllPrompts || yes {
			// Implicit "Use New": do nothing, let it fall through.
			// The file remains in staging and will overwrite the target during the final rsync.
			continue
		}

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
				if !yes && !skipAllPrompts && !fast {
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
					if fast {
						input = "u" // Use new in fast mode
					} else {
						input = "k" // Default to keep if user presses enter or if in --yes mode
					}
				}
				switch strings.ToLower(input) {
				case "k":
					// Keep the file from the other package - delete from staging
					if os.Geteuid() == 0 {
						if err := os.Remove(stagingFile); err != nil {
							return fmt.Errorf("failed to remove file from staging %s natively: %v", stagingFile, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-f", stagingFile)
						if err := execCtx.Run(rmCmd); err != nil {
							return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
						}
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
					if os.Geteuid() == 0 {
						if err := os.Remove(stagingFile); err != nil {
							return fmt.Errorf("failed to remove file from staging %s natively: %v", stagingFile, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-f", stagingFile)
						if err := execCtx.Run(rmCmd); err != nil {
							return fmt.Errorf("failed to remove file from staging %s: %v", stagingFile, err)
						}
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
			if (!yes && !skipAllPrompts) || fast {
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
					// Remove existing file/symlink in staging if it exists (use executor or native if root)
					if os.Geteuid() == 0 {
						os.Remove(stagingFile)
						if err := os.Symlink(linkTarget, stagingFile); err != nil {
							return fmt.Errorf("failed to recreate symlink %s -> %s natively: %v", stagingFile, linkTarget, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-f", stagingFile)
						if err := execCtx.Run(rmCmd); err != nil {
							return fmt.Errorf("failed to remove existing file %s: %v", stagingFile, err)
						}
						// Recreate the symlink in staging using executor for proper permissions
						lnCmd := exec.Command("ln", "-s", linkTarget, stagingFile)
						if err := execCtx.Run(lnCmd); err != nil {
							return fmt.Errorf("failed to recreate symlink %s -> %s: %v", stagingFile, linkTarget, err)
						}
					}
				} else {
					// It's a regular file - copy it normally
					if os.Geteuid() == 0 {
						if err := copyFile(currentFile, stagingFile); err != nil {
							return fmt.Errorf("failed to overwrite %s natively: %v", stagingFile, err)
						}
					} else {
						cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
						if err := execCtx.Run(cpCmd); err != nil {
							return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
						}
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
				if os.Geteuid() == 0 {
					if err := copyFile(tmpPath, stagingFile); err != nil {
						return fmt.Errorf("failed to copy edited file back to staging %s natively: %v", stagingFile, err)
					}
					// restore mode
					if err := os.Chmod(stagingFile, originalMode.Perm()); err != nil {
						return fmt.Errorf("failed to restore permissions on %s natively: %v", stagingFile, err)
					}
				} else {
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
				stagingFileDir := filepath.Dir(stagingFile)
				if os.Geteuid() == 0 {
					if err := os.MkdirAll(stagingFileDir, 0755); err != nil {
						return fmt.Errorf("failed to create directory %s natively: %v", stagingFileDir, err)
					}
					if err := copyFile(currentFile, stagingFile); err != nil {
						return fmt.Errorf("failed to copy %s to staging natively: %v", file, err)
					}
				} else {
					// ensure staging directory exists (run as root)
					mkdirCmd := exec.Command("mkdir", "-p", stagingFileDir)
					if err := execCtx.Run(mkdirCmd); err != nil {
						return fmt.Errorf("failed to create directory %s: %v", stagingFileDir, err)
					}
					// copy current file into staging preserving attributes
					cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", currentFile, stagingFile)
					if err := execCtx.Run(cpCmd); err != nil {
						return fmt.Errorf("failed to copy %s to staging: %v", file, err)
					}
				}
				debugf("Kept modified file by copying %s into staging\n", file)
			} else {
				if os.Geteuid() == 0 {
					if err := os.Remove(currentFile); err != nil {
						cPrintf(colWarn, "Warning: failed to remove %s natively: %v\n", currentFile, err)
					}
				} else {
					// user chose not to keep it -> remove the installed file (run as root)
					rmCmd := exec.Command("rm", "-f", currentFile)
					if err := execCtx.Run(rmCmd); err != nil {
						// warn but continue install; do not abort the whole install for a removal failure
						fmt.Fprintf(logger, "Warning: failed to remove %s: %v\n", currentFile, err)
					} else {
						debugf("Removed user-modified file: %s\n", file)
					}
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
		if !manifestExec.ShouldRunAsRoot {
			debugf("optimized user manifest generation failed, falling back to root executor: %v\n", err)
			if err := generateManifest(stagingDir, stagingManifest2dir, RootExec); err != nil {
				return fmt.Errorf("failed to generate manifest: %v", err)
			}
		} else {
			return fmt.Errorf("failed to generate manifest: %v", err)
		}
	}
	debugf("Generate update manifest\n")
	if err := updateManifestWithNewFiles(stagingManifest, stagingManifest2file); err != nil {
		fmt.Fprintf(os.Stderr, "Manifest update failed: %v\n", err)
	}

	// Delete stagingManifest2dir
	if os.Geteuid() == 0 {
		os.RemoveAll(stagingManifest2dir)
	} else {
		rmCmd := exec.Command("rm", "-rf", stagingManifest2dir)
		if err := execCtx.Run(rmCmd); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove StagingManifest: %v", err)
		}
	}

	// 3.5. Check for conflicts with existing files (for both fresh installs and upgrades)
	// This handles cases where files exist on disk but are not tracked by any package
	// (e.g., user chose to "keep existing" during a previous install)
	debugf("Checking for conflicts with existing files\n")
	if err := checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest, execCtx, yes, fast, filesRemovedFromStaging, nil); err != nil {
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
	// --- NEW: Dependency Check and Backup (Before deletion) ---
	debugf("Dependency check")
	affectedPackages := make(map[string][]string) // Changed to map[string][]string
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

	// Optimization: Pre-compute lookups
	filesToDeleteMap := make(map[string]struct{}, len(filesToDelete))
	filesToDeleteBasenameMap := make(map[string]string, len(filesToDelete))
	for _, f := range filesToDelete {
		filesToDeleteMap[f] = struct{}{}
		filesToDeleteBasenameMap[filepath.Base(f)] = f
	}

	allInstalledEntries, err := os.ReadDir(Installed)
	if err == nil {
		for _, entry := range allInstalledEntries {
			if !entry.IsDir() || entry.Name() == pkgName {
				continue // Skip files or the package currently being installed
			}

			otherPkgName := entry.Name()
			libdepsPath := filepath.Join(Installed, otherPkgName, "libdeps")

			// Optimization: Try fast read first
			var libdepsContent []byte
			var err error
			if data, lerr := os.ReadFile(libdepsPath); lerr == nil {
				libdepsContent = data
			} else {
				libdepsContent, err = readFileAsRoot(libdepsPath)
				if err != nil {
					continue // Skip if libdeps file is unreadable
				}
			}

			// Check if any file in filesToDelete is a libdep of otherPkgName
			lines := strings.SplitSeq(string(libdepsContent), "\n")
			for line := range lines {
				libPath := strings.TrimSpace(line)
				if libPath == "" {
					continue
				}

				var matchFile string
				if strings.HasPrefix(libPath, "/") {
					// Old format: absolute path
					absLibPath := libPath
					if rootDir != "/" {
						absLibPath = filepath.Join(rootDir, libPath[1:])
					}
					if _, ok := filesToDeleteMap[absLibPath]; ok {
						matchFile = absLibPath
					}
				} else {
					// New format: basename only
					if fullPath, ok := filesToDeleteBasenameMap[libPath]; ok {
						matchFile = fullPath
					}
				}

				if matchFile != "" {
					// Store just the basename for display
					libName := filepath.Base(matchFile)
					// Avoid duplicates
					exists := false
					for _, l := range affectedPackages[otherPkgName] {
						if l == libName {
							exists = true
							break
						}
					}
					if !exists {
						affectedPackages[otherPkgName] = append(affectedPackages[otherPkgName], libName)
					}
					libFilesToDelete[matchFile] = struct{}{}
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
		if os.Geteuid() == 0 {
			if err := os.MkdirAll(backupDir, 0755); err != nil {
				return fmt.Errorf("failed to create backup dir %s natively: %v", backupDir, err)
			}
			if err := copyFile(libPath, backupPath); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to backup library %s natively: %v\n", libPath, err)
			} else {
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("Backed up affected library %s to %s\n", libPath, backupPath))
			}
		} else {
			mkdirCmd := exec.Command("mkdir", "-p", backupDir)
			if err := execCtx.Run(mkdirCmd); err != nil {
				return fmt.Errorf("failed to create backup dir %s: %v", backupDir, err)
			}

			// Copy the library file to the backup location
			cpCmd := exec.Command("cp", "--remove-destination", "--preserve=mode,ownership,timestamps", libPath, backupPath)
			if err := execCtx.Run(cpCmd); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to backup library %s: %v\n", libPath, err)
			} else {
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("Backed up affected library %s to %s\n", libPath, backupPath))
			}
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
	if logger == nil {
		logger = os.Stdout
	}

	if !fast {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprintln(logger, colSuccess.Sprint("Executing package post-install script"))
	}
	if err := executePostInstall(pkgName, rootDir, execCtx, cfg, logger); err != nil {
		fmt.Printf("warning: post-install for %s returned error: %v\n", pkgName, err)
	}

	// 7.5. Check for rebuild triggers from /etc/hokuto/hokuto.rebuild
	rebuildTriggerPkgs := getRebuildTriggers(pkgName, rootDir)
	if len(rebuildTriggerPkgs) > 0 {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprint(logger, colSuccess.Sprint("DKMS trigger: "))
		fmt.Fprintf(logger, "%s", colNote.Sprintf("%s\n", strings.Join(rebuildTriggerPkgs, " ")))
		shouldRebuild := yes // Default to true if --yes flag is set
		if !yes {
			shouldRebuild = askForConfirmation(colWarn, "%sRebuild the packages?", colArrow.Sprint("-> "))
		}

		if shouldRebuild {
			for _, rebuildPkg := range rebuildTriggerPkgs {
				debugf("\n--- Rebuilding %s (triggered by %s) ---\n", rebuildPkg, pkgName)

				// Pass empty string for oldLibsDir since this is a trigger-based rebuild, not a library dependency rebuild
				if err := pkgBuildRebuild(rebuildPkg, cfg, execCtx, "", nil); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s (triggered by %s) failed: %v", rebuildPkg, pkgName, err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Rebuild of %s failed: %v\n", rebuildPkg, err))
					continue
				}

				rebuildOutputDir := filepath.Join(tmpDir, rebuildPkg, "output")

				if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
					failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", rebuildPkg, err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to sync rebuilt package %s to root: %v\n", rebuildPkg, err))
					continue
				}

				rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, rebuildPkg))
				if err := execCtx.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", rebuildPkg, err)
				}
				colArrow.Print("-> ")
				fmt.Fprintf(logger, "%s", colSuccess.Sprint("Rebuild of "))
				colNote.Printf("%s ", rebuildPkg)
				colSuccess.Printf("finished and installed.\n")
			}
		} else {
			colArrow.Print("-> ")
			fmt.Fprintf(logger, "%s", colInfo.Sprintf("Skipping rebuild of %s\n", strings.Join(rebuildTriggerPkgs, ", ")))
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
		var sb strings.Builder
		sb.WriteString("\nWARNING: The following packages depend on libraries that were removed/upgraded:\n")
		for _, pkg := range affectedList {
			libs := affectedPackages[pkg]
			sb.WriteString(fmt.Sprintf("  %s (needs: %s)\n", pkg, strings.Join(libs, ", ")))
		}
		// Interactive rebuild selection
		var packagesToRebuild []string
		rebuildAll := false // Flag to track if 'a' (all) was selected

		if !yes {
			// Use the same robust reader we defined earlier
			shouldQuit := false
			WithPrompt(func() {
				// Print warning inside the prompt block to ensure it's not overwritten
				cPrintf(colWarn, "%s", sb.String())

				for _, pkg := range affectedList {
					if shouldQuit {
						break
					}

					if rebuildAll {
						// 'all' was selected, just add and continue
						packagesToRebuild = append(packagesToRebuild, pkg)
						cPrintf(colInfo, "Rebuilding %s (auto-selected by 'all')\n", pkg)
						// continue // continue doesn't render well here since we are inside closure inside loop?
						// actually we are inside closure.
						// Wait, if we wrap the WHOLE loop in WithPrompt, then we can use continue naturally?
						// No, WithPrompt accepts a func().
						continue
					}

					// Prompt for this specific package
					cPrintf(colInfo, "Rebuild %s? [Y/n/a(ll)/q(uit)]: ", pkg)
					os.Stdout.Sync()
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
					case "a": // All
						cPrintf(colInfo, "Rebuilding %s and all subsequent packages\n", pkg)
						rebuildAll = true
						packagesToRebuild = append(packagesToRebuild, pkg)
					case "q": // Quit
						cPrintf(colInfo, "Quitting rebuild selection. No more packages will be rebuilt.\n")
						shouldQuit = true // Signal to break loop
					default: // Invalid, treat as 'No' for safety
						cPrintf(colInfo, "Invalid input. Skipping rebuild for %s\n", pkg)
					}
				}
			})
		} else {
			// If --yes is passed, just rebuild all affected packages (original behavior)
			fmt.Fprintf(logger, "%s", colInfo.Sprint("Rebuilding all affected packages due to --yes flag.\n"))
			packagesToRebuild = affectedList
		}

		// 8b. Perform rebuild
		if len(packagesToRebuild) > 0 {
			colArrow.Print("-> ")
			colSuccess.Println("Starting rebuild of affected packages")
			for _, pkg := range packagesToRebuild {
				fmt.Fprintf(logger, "%s", colInfo.Sprintf("\n--- Rebuilding %s ---\n", pkg))

				if err := pkgBuildRebuild(pkg, cfg, execCtx, tempLibBackupDir, nil); err != nil {
					failed = append(failed, fmt.Sprintf("rebuild of %s failed: %v", pkg, err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Rebuild of %s failed: %v\n", pkg, err))
					continue // Skip to next package on failure, same as hokuto update
				}

				rebuildOutputDir := filepath.Join(tmpDir, pkg, "output")

				if err := rsyncStaging(rebuildOutputDir, rootDir, execCtx); err != nil {
					failed = append(failed, fmt.Sprintf("failed to sync rebuilt package %s to root: %v", pkg, err))
					fmt.Fprintf(logger, "%s", colWarn.Sprintf("WARNING: Failed to sync rebuilt package %s to root: %v\n", pkg, err))
					continue // Skip cleanup on sync failure
				}

				rmCmd := exec.Command("rm", "-rf", filepath.Join(tmpDir, pkg))
				if err := execCtx.Run(rmCmd); err != nil {
					fmt.Fprintf(os.Stderr, "failed to cleanup rebuild tmpdirs for %s: %v\n", pkg, err)
				}
				colArrow.Print("-> ")
				colSuccess.Printf("Rebuild of ")
				colNote.Printf("%s ", pkg)
				colSuccess.Printf("finished and installed.\n")
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
	if !fast {
		if err := PostInstallTasks(RootExec, logger); err != nil {
			fmt.Fprintf(os.Stderr, "post-install tasks completed with warnings: %v\n", err)
		}
	}
	return nil
}

// checkStagingConflicts checks for conflicts between files in staging and existing files in the target.
// This handles fresh installs where the package is not installed but files may already exist.
// filesHandledInConflict is optional and only used for tracking (can be nil for fresh installs).
func checkStagingConflicts(pkgName, stagingDir, rootDir, stagingManifest string, execCtx *Executor, yes, fast bool, filesRemovedFromStaging map[string]bool, filesHandledInConflict map[string]bool) error {
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
	installedManifestPath := filepath.Join(Installed, pkgName, "manifest")
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

	stdinReader := bufio.NewReader(os.Stdin)
	skipAllPrompts := yes
	useOriginalForAll := false // Flag to use original for all remaining alternatives (unmanaged)
	useNewForAll := false      // Flag to use new for all remaining alternatives (unmanaged)
	// If auto-confirming or fast mode, set flags to default to "new"
	if yes || fast {
		useNewForAll = true
	}
	keepAllConflicts := false   // Flag to keep all conflicting files items (package conflicts)
	useNewAllConflicts := false // Flag to use new file for all conflicting items (package conflicts)
	if fast {
		useNewAllConflicts = true
	}

	// Data structure to collect conflicts grouped by conflicting package
	type conflictInfo struct {
		filePath             string
		stagingFile          string
		targetFile           string
		conflictPkg          string
		isSymlink            bool
		symlinkTarget        string
		stagingIsSymlink     bool
		stagingSymlinkTarget string
	}
	conflictsByPkg := make(map[string][]conflictInfo)
	unmanagedConflicts := []conflictInfo{}

	// First pass: collect all conflicts
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
			// File is owned by another package - this is a conflict
			// Check if the target file is a symlink
			isSymlink := false
			var symlinkTarget string
			if targetInfo, err := os.Lstat(targetFile); err == nil && targetInfo.Mode()&os.ModeSymlink != 0 {
				isSymlink = true
				if target, err := os.Readlink(targetFile); err == nil {
					symlinkTarget = target
				}
			}

			// Check if staging file is a symlink
			stagingIsSymlink := false
			var stagingSymlinkTarget string
			if stagingInfo, err := os.Lstat(stagingFile); err == nil && stagingInfo.Mode()&os.ModeSymlink != 0 {
				stagingIsSymlink = true
				if target, err := os.Readlink(stagingFile); err == nil {
					stagingSymlinkTarget = target
				}
			}

			conflictsByPkg[ownerPkg] = append(conflictsByPkg[ownerPkg], conflictInfo{
				filePath:             filePath,
				stagingFile:          stagingFile,
				targetFile:           targetFile,
				conflictPkg:          ownerPkg,
				isSymlink:            isSymlink,
				symlinkTarget:        symlinkTarget,
				stagingIsSymlink:     stagingIsSymlink,
				stagingSymlinkTarget: stagingSymlinkTarget,
			})
		} else if ownerPkg == "" {
			// File exists but is not owned by any package
			unmanagedConflicts = append(unmanagedConflicts, conflictInfo{
				filePath:    filePath,
				stagingFile: stagingFile,
				targetFile:  targetFile,
				conflictPkg: "",
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading staging manifest: %v", err)
	}

	// Second pass: prompt once per conflicting package
	for conflictPkg, conflicts := range conflictsByPkg {
		var input string
		// Check batch flags first - if already set, skip prompt
		if keepAllConflicts {
			input = "k"
		} else if useNewAllConflicts {
			input = "n"
		} else if !skipAllPrompts && !fast {
			// Display all conflicting files
			cPrintf(colWarn, "Conflicting file(s) detected from %s package:\n", conflictPkg)
			for _, c := range conflicts {
				colArrow.Print("-> ")
				colInfo.Println(c.filePath)
			}
			cPrintf(colInfo, "Use [N]ew %s, keep [o]riginal %s: ", pkgName, conflictPkg)
			os.Stdout.Sync()
			response, err := stdinReader.ReadString('\n')
			if err != nil {
				response = "n" // Default to new on read error
			}
			input = strings.ToLower(strings.TrimSpace(response))
			if input == "" {
				input = "n" // Default to new
			}
			// Set batch flag for remaining conflicts
			switch input {
			case "k", "o":
				keepAllConflicts = true
			case "n":
				useNewAllConflicts = true
			default:
				// Invalid input, default to new
				useNewAllConflicts = true
				input = "n"
			}
		} else {
			input = "n" // Default to new in --yes mode
			useNewAllConflicts = true
		}

		// Apply choice to all files in this conflict group
		// Batch process alternatives for performance
		var batchRequests []AlternativeRequest
		// Keep track of which staging files to remove (Keep Original case)
		stagingFilesToRemove := make(map[string]bool)

		// 1. Gather requests
		for _, c := range conflicts {
			switch input {
			case "k", "o":
				// Keep Original (existing file). Stash the new (incoming) file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   c.conflictPkg,
					IncomingFile: c.stagingFile,
					KeepOriginal: true,
				}
				batchRequests = append(batchRequests, req)
				batchRequests = append(batchRequests, req)
				stagingFilesToRemove[c.filePath] = true
				// Do NOT add to manifestEntriesToRemove. We want the package to "own" the file
				// even if we are using the existing one on disk. This ensures uninstall works.

				debugf("Kept file from %s package, queueing new file (from %s) as alternative: %s\n", c.conflictPkg, pkgName, c.filePath)

			case "n":
				// Use New (incoming file). Stash the original (existing) file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   c.conflictPkg,
					IncomingFile: c.stagingFile,
					KeepOriginal: false,
				}
				batchRequests = append(batchRequests, req)

				if filesHandledInConflict != nil {
					filesHandledInConflict[c.filePath] = true
				}
				debugf("Using new file from %s, queueing existing file (from %s) as alternative: %s\n", pkgName, c.conflictPkg, c.filePath)
			}
		}

		// 2. Execute Batch
		if len(batchRequests) > 0 {
			debugf("Processing %d alternative registrations concurrently...\n", len(batchRequests))
			if err := BatchRegisterAlternatives(rootDir, batchRequests, execCtx); err != nil {
				// We should probably fail or warn?
				cPrintf(colWarn, "Warning: failed to register some alternatives: %v\n", err)
			}
		}

		// 3. Post-processing (Cleanup staging files for "Keep" case)
		for _, c := range conflicts {
			if stagingFilesToRemove[c.filePath] {
				rmCmd := exec.Command("rm", "-f", c.stagingFile)
				if err := execCtx.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove file from staging %s: %v", c.stagingFile, err)
				}
				// filesRemovedFromStaging[c.filePath] = true <--- CHANGED: Keep in manifest for alternatives
			}
		}
	}

	// Handle unmanaged file conflicts
	if len(unmanagedConflicts) > 0 {
		var input string
		if useOriginalForAll {
			input = "k"
		} else if useNewForAll {
			input = "n"
		} else if !skipAllPrompts && !fast {
			cPrintf(colWarn, "Conflicting file(s) detected (unmanaged):\n")
			for _, c := range unmanagedConflicts {
				colArrow.Print("-> ")
				colInfo.Println(c.filePath)
			}
			cPrintf(colInfo, "Use [N]ew %s, [k]eep original: ", pkgName)
			os.Stdout.Sync()
			response, err := stdinReader.ReadString('\n')
			if err != nil {
				response = "n"
			}
			input = strings.ToLower(strings.TrimSpace(response))
			if input == "" {
				input = "n"
			}
			switch input {
			case "k", "o":
				useOriginalForAll = true
			case "n":
				useNewForAll = true
			default:
				useNewForAll = true
				input = "n"
			}
		} else {
			input = "n"
			useNewForAll = true
		}

		var unmanagedBatchRequests []AlternativeRequest
		unmanagedStagingToRemove := make(map[string]bool)
		// unmanagedManifestToRemove := make(map[string]bool) // Not used currently as we keep manifest entries for alternatives

		for _, c := range unmanagedConflicts {
			switch input {
			case "k", "o":
				// Keep Original (unmanaged). Stash new file.
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   "",
					IncomingFile: c.stagingFile,
					KeepOriginal: true,
				}
				unmanagedBatchRequests = append(unmanagedBatchRequests, req)
				unmanagedStagingToRemove[c.filePath] = true
				debugf("Kept existing unmanaged file, queueing new file as alternative: %s\n", c.filePath)

			case "n":
				// Use New. Stash original (unmanaged).
				req := AlternativeRequest{
					FilePath:     c.filePath,
					IncomingPkg:  pkgName,
					CurrentPkg:   "",
					IncomingFile: c.stagingFile,
					KeepOriginal: false,
				}
				unmanagedBatchRequests = append(unmanagedBatchRequests, req)
				debugf("Using new file, queueing existing file as alternative: %s\n", c.filePath)
			}
		}

		if len(unmanagedBatchRequests) > 0 {
			debugf("Processing %d unmanaged alternatives concurrently...\n", len(unmanagedBatchRequests))
			if err := BatchRegisterAlternatives(rootDir, unmanagedBatchRequests, execCtx); err != nil {
				cPrintf(colWarn, "Warning: failed to register unmanaged alternatives: %v\n", err)
			}
		}

		for _, c := range unmanagedConflicts {
			if unmanagedStagingToRemove[c.filePath] {
				rmCmd := exec.Command("rm", "-f", c.stagingFile)
				if err := execCtx.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove file from staging %s: %v", c.stagingFile, err)
				}
				// filesRemovedFromStaging[c.filePath] = true
			}
		}
	}

	// Remove entries from staging manifest for files that were removed from staging
	if len(filesRemovedFromStaging) > 0 {
		// filesRemovedFromStaging was populated from stagingFilesToRemove.
		// Wait, filesRemovedFromStaging is the argument passed to this function.
		// We are updating the map passed by the caller?
		// No, `filesRemovedFromStaging` is a map passed into checkStagingConflicts.
		// BUT `checkStagingConflicts` populates it?
		// Let's check signature: `filesRemovedFromStaging map[string]bool`. It's a map pointer.
		// In previous logic: `filesRemovedFromStaging[c.filePath] = true`.

		// Logic change: We should ONLY call removeManifestEntries for things we REALLY want gone from manifest.
		// Since we decided that "Keep Original" for alternatives means "Shared Ownership", we want it IN manifest.
		// So we should NOT set filesRemovedFromStaging[c.filePath] = true for alternatives.

		// However, we DO want to remove the file from staging disk.
		// That is handled by `stagingFilesToRemove` loop above (lines 1366-1374).

		// So the previous edits I made:
		// `stagingFilesToRemove[c.filePath] = true` handles disk removal.
		// `filesRemovedFromStaging[c.filePath] = true` handled manifest removal.
		// I removed the line `filesRemovedFromStaging[c.filePath] = true` in my mind, but did I remove it in code?
		// In previous step (1610), I replaced the loop.
		// Let's verify what I wrote in step 1610.
		// I wrote: `stagingFilesToRemove[c.filePath] = true`.
		// I did NOT write `filesRemovedFromStaging[c.filePath] = true` inside the loop.
		// BUT in the POST-PROCESSING loop (lines 1366-1374 in new code, lines 1373 in view):
		// `filesRemovedFromStaging[c.filePath] = true` IS THERE.
		// I need to remove THAT line.
	}

	if len(filesRemovedFromStaging) > 0 {
		if err := removeManifestEntries(stagingManifest, filesRemovedFromStaging, execCtx); err != nil {
			// Non-fatal, but log the error
			debugf("Warning: failed to remove entries from staging manifest: %v\n", err)
		}
	}

	return nil
}
