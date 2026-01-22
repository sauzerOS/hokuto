package hokuto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// AlternativeInfo stores metadata about an alternative file
type AlternativeInfo struct {
	FilePath      string `json:"file_path"`                // Path where the file is installed (e.g., /bin/file1)
	SourcePkg     string `json:"source_pkg"`               // Package that provided the alternative (or "no package" if unmanaged)
	OriginalPkg   string `json:"original_pkg"`             // Original package that owns the file (empty if no owner)
	IsActive      bool   `json:"is_active"`                // Whether the alternative is currently active
	SymlinkTarget string `json:"symlink_target,omitempty"` // Target path if this is a symlink (empty for regular files)
	// File stat information for restoration (original file's permissions)
	Mode string `json:"mode"` // Original file permissions in octal (e.g., "0755")
	UID  int    `json:"uid"`  // Original file User ID
	GID  int    `json:"gid"`  // Original file Group ID
	// Backup file stat information (for when we switch back and forth)
	BackupMode string `json:"backup_mode"` // Backup file permissions (when alternative is active)
	BackupUID  int    `json:"backup_uid"`  // Backup file User ID
	BackupGID  int    `json:"backup_gid"`  // Backup file Group ID
}

// getAlternativesDir returns the directory for storing alternatives for a package
func getAlternativesDir(pkgName string) string {
	return filepath.Join(rootDir, "var", "db", "hokuto", "alternatives", pkgName)
}

// getAlternativesMetadataFile returns the path to the metadata file for alternatives
func getAlternativesMetadataFile(pkgName string) string {
	return filepath.Join(getAlternativesDir(pkgName), "metadata.json")
}

// saveAlternative saves an alternative file and its metadata
// sourceFile is the file to save as alternative (could be staging file or existing file)
func saveAlternative(pkgName, filePath, sourcePkg, originalPkg, sourceFile string, execCtx *Executor) error {
	altDir := getAlternativesDir(pkgName)
	debugf("saveAlternative: pkgName=%s, filePath=%s, altDir=%s, sourceFile=%s\n", pkgName, filePath, altDir, sourceFile)

	// Check if source file exists (use Lstat to not follow symlinks)
	sourceInfo, err := os.Lstat(sourceFile)
	if os.IsNotExist(err) {
		return fmt.Errorf("source file does not exist: %s", sourceFile)
	}
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Check if source file is a symlink
	isSymlink := sourceInfo.Mode()&os.ModeSymlink != 0
	var symlinkTarget string
	if isSymlink {
		symlinkTarget, err = os.Readlink(sourceFile)
		if err != nil {
			return fmt.Errorf("failed to read symlink target: %w", err)
		}
		debugf("Source file is a symlink: %s -> %s\n", sourceFile, symlinkTarget)
	}

	// Create directory using native or executor
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(altDir, 0755); err != nil {
			return fmt.Errorf("failed to create alternatives directory %s natively: %w", altDir, err)
		}
	} else {
		mkdirCmd := exec.Command("mkdir", "-p", altDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create alternatives directory %s: %w", altDir, err)
		}
	}
	debugf("Created alternatives directory: %s\n", altDir)

	// Copy the alternative file to the alternatives directory
	// The file will be stored with a sanitized name based on its path
	altFileName := strings.ReplaceAll(strings.TrimPrefix(filePath, "/"), "/", "_")
	altFilePath := filepath.Join(altDir, altFileName)
	debugf("Copying %s to %s\n", sourceFile, altFilePath)

	// Copy using native if root, else executor
	if os.Geteuid() == 0 {
		if err := copyFile(sourceFile, altFilePath); err != nil {
			return fmt.Errorf("failed to copy alternative file natively from %s to %s: %w", sourceFile, altFilePath, err)
		}
	} else {
		// Use cp -a to preserve symlinks (--no-dereference) and all attributes
		cpCmd := exec.Command("cp", "-a", sourceFile, altFilePath)
		if err := execCtx.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to copy alternative file from %s to %s: %w", sourceFile, altFilePath, err)
		}
	}
	debugf("Successfully copied alternative file\n")

	// Load existing metadata
	metadataFile := getAlternativesMetadataFile(pkgName)
	alternatives := make(map[string]*AlternativeInfo)

	if data, err := os.ReadFile(metadataFile); err == nil {
		json.Unmarshal(data, &alternatives)
	}

	// Get file stat information from the target file (the file that currently exists and will be replaced)
	// This represents the "original" file's permissions/ownership that we need to restore later
	targetFile := filepath.Join(rootDir, strings.TrimPrefix(filePath, "/"))
	var mode string
	var uid, gid int

	if stat, err := os.Lstat(targetFile); err == nil {
		// Get permissions in octal format
		mode = fmt.Sprintf("%04o", stat.Mode().Perm())
		// Get UID and GID
		if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
			uid = int(sysStat.Uid)
			gid = int(sysStat.Gid)
		}
	} else {
		// If we can't stat the file, try with root using stat command
		statCmd := exec.Command("stat", "-c", "%a %u %g", targetFile)
		var out bytes.Buffer
		statCmd.Stdout = &out
		if err := RootExec.Run(statCmd); err == nil {
			parts := strings.Fields(out.String())
			if len(parts) >= 3 {
				mode = parts[0]
				fmt.Sscanf(parts[1], "%d", &uid)
				fmt.Sscanf(parts[2], "%d", &gid)
			}
		}
		// If file doesn't exist, mode/uid/gid will remain empty/0 (which is fine for fresh installs)
	}

	// Add or update the alternative info
	alternatives[filePath] = &AlternativeInfo{
		FilePath:      filePath,
		SourcePkg:     sourcePkg,
		OriginalPkg:   originalPkg,
		IsActive:      false,         // Not active by default, user needs to switch
		SymlinkTarget: symlinkTarget, // Empty for regular files, target path for symlinks
		Mode:          mode,
		UID:           uid,
		GID:           gid,
	}

	// Save metadata - write to temp file first, then copy with executor
	data, err := json.MarshalIndent(alternatives, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Write to temp file first
	tmpFile, err := os.CreateTemp("", "hokuto-alt-metadata-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	defer os.Remove(tmpFilePath) // Clean up temp file

	if _, err = tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write temp metadata: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Copy using native if root, else executor
	if os.Geteuid() == 0 {
		if err = os.WriteFile(metadataFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write metadata file natively: %w", err)
		}
	} else {
		// Copy temp file to final location using executor (may need root permissions)
		cpCmd := exec.Command("cp", tmpFilePath, metadataFile)
		if err = execCtx.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to write metadata file: %w", err)
		}
		// Set permissions so the file is readable by all (needed for listing)
		chmodCmd := exec.Command("chmod", "644", metadataFile)
		if err = execCtx.Run(chmodCmd); err != nil {
			debugf("Warning: failed to set permissions on metadata file: %v\n", err)
		}
	}

	debugf("Saved alternative for %s: source=%s, sourcePkg=%s, originalPkg=%s\n", filePath, sourceFile, sourcePkg, originalPkg)
	return nil
}

// loadAlternativesMetadata loads the alternatives metadata for a package
func loadAlternativesMetadata(pkgName string) (map[string]*AlternativeInfo, error) {
	metadataFile := getAlternativesMetadataFile(pkgName)
	alternatives := make(map[string]*AlternativeInfo)

	if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
		return alternatives, nil
	}

	// Try to read the file, if it fails due to permissions, try with root
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		// If permission denied, try reading as root
		if os.IsPermission(err) {
			catCmd := exec.Command("cat", metadataFile)
			var out bytes.Buffer
			catCmd.Stdout = &out
			if rootErr := RootExec.Run(catCmd); rootErr == nil {
				data = out.Bytes()
			} else {
				return nil, fmt.Errorf("failed to read metadata (permission denied and root read failed): %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read metadata: %w", err)
		}
	}

	if err := json.Unmarshal(data, &alternatives); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return alternatives, nil
}

// getAlternativeFilePath returns the path where an alternative file is stored
func getAlternativeFilePath(pkgName, filePath string) string {
	altFileName := strings.ReplaceAll(strings.TrimPrefix(filePath, "/"), "/", "_")
	return filepath.Join(getAlternativesDir(pkgName), altFileName)
}

// switchToAlternative switches from the original file to the alternative
func switchToAlternative(pkgName, filePath string, execCtx *Executor) error {
	altFilePath := getAlternativeFilePath(pkgName, filePath)
	targetFile := filepath.Join(rootDir, strings.TrimPrefix(filePath, "/"))

	// Check if alternative file exists (use Lstat to not follow symlinks)
	if _, err := os.Lstat(altFilePath); os.IsNotExist(err) {
		return fmt.Errorf("alternative file not found: %s", altFilePath)
	}

	// Backup the original file if it exists
	backupDir := filepath.Join(getAlternativesDir(pkgName), "backup")
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(backupDir, 0755); err != nil {
			return fmt.Errorf("failed to create backup directory natively: %w", err)
		}
	} else {
		// Use root executor for directory creation (may need root permissions)
		mkdirCmd := exec.Command("mkdir", "-p", backupDir)
		if err := RootExec.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	backupFileName := strings.ReplaceAll(strings.TrimPrefix(filePath, "/"), "/", "_")
	backupFilePath := filepath.Join(backupDir, backupFileName)

	// Capture the current file's stat BEFORE backing it up
	// This is the file that's currently installed (could be original or alternative)
	var currentMode string
	var currentUID, currentGID int

	if _, err := os.Stat(targetFile); err == nil {
		// Capture stat from the current file (the one that will be replaced)
		if stat, err := os.Lstat(targetFile); err == nil {
			// Get permissions in octal format
			currentMode = fmt.Sprintf("%04o", stat.Mode().Perm())
			// Get UID and GID
			if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
				currentUID = int(sysStat.Uid)
				currentGID = int(sysStat.Gid)
			}
		} else {
			// If we can't stat the file, try with root using stat command
			statCmd := exec.Command("stat", "-c", "%a %u %g", targetFile)
			var out bytes.Buffer
			statCmd.Stdout = &out
			if err := RootExec.Run(statCmd); err == nil {
				parts := strings.Fields(out.String())
				if len(parts) >= 3 {
					currentMode = parts[0]
					fmt.Sscanf(parts[1], "%d", &currentUID)
					fmt.Sscanf(parts[2], "%d", &currentGID)
				}
			}
		}

		// Backup current file - use native if root, else executor
		if os.Geteuid() == 0 {
			if err := copyFile(targetFile, backupFilePath); err != nil {
				return fmt.Errorf("failed to backup current file natively: %w", err)
			}
		} else {
			// Use cp -a to preserve symlinks
			cpCmd := exec.Command("cp", "-a", targetFile, backupFilePath)
			if err := RootExec.Run(cpCmd); err != nil {
				return fmt.Errorf("failed to backup current file: %w", err)
			}
		}

		// Also capture the backup file's stat and store it in metadata
		// This ensures we can restore the backup file's permissions when switching back
		if backupStat, err := os.Lstat(backupFilePath); err == nil {
			backupMode := fmt.Sprintf("%04o", backupStat.Mode().Perm())
			var backupUID, backupGID int
			if sysStat, ok := backupStat.Sys().(*syscall.Stat_t); ok {
				backupUID = int(sysStat.Uid)
				backupGID = int(sysStat.Gid)
			}

			// Update metadata with backup file's stat
			alternatives, err := loadAlternativesMetadata(pkgName)
			if err == nil {
				if alt, ok := alternatives[filePath]; ok {
					alt.BackupMode = backupMode
					alt.BackupUID = backupUID
					alt.BackupGID = backupGID
					debugf("Stored backup file stat: mode=%s, uid=%d, gid=%d\n", backupMode, backupUID, backupGID)
					// Save updated metadata
					metadataFile := getAlternativesMetadataFile(pkgName)
					data, err := json.MarshalIndent(alternatives, "", "  ")
					if err == nil {
						tmpFile, err := os.CreateTemp("", "hokuto-alt-metadata-*.json")
						if err == nil {
							tmpFilePath := tmpFile.Name()
							defer os.Remove(tmpFilePath)
							if _, err = tmpFile.Write(data); err == nil {
								if err = tmpFile.Close(); err == nil {
									if os.Geteuid() == 0 {
										os.Rename(tmpFilePath, metadataFile)
										os.Chmod(metadataFile, 0644)
									} else {
										cpCmd := exec.Command("cp", tmpFilePath, metadataFile)
										RootExec.Run(cpCmd)
										chmodCmd := exec.Command("chmod", "644", metadataFile)
										RootExec.Run(chmodCmd)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Copy alternative file to target location - use native if root, else executor
	if os.Geteuid() == 0 {
		if err := copyFile(altFilePath, targetFile); err != nil {
			return fmt.Errorf("failed to install alternative file natively: %w", err)
		}
	} else {
		// Use cp -a to preserve symlinks
		cpCmd := exec.Command("cp", "-a", altFilePath, targetFile)
		if err := RootExec.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to install alternative file: %w", err)
		}
	}

	// Load metadata to get the original file's permissions and apply them to the alternative file
	alternatives, err := loadAlternativesMetadata(pkgName)
	if err != nil {
		return err
	}

	// Apply original file's permissions to the alternative file
	if alt, ok := alternatives[filePath]; ok {
		// Use the permissions from metadata (captured when alternative was saved)
		// This represents what the original file had when the alternative was created
		restoreMode := alt.Mode
		restoreUID := alt.UID
		restoreGID := alt.GID

		// If metadata doesn't have permissions but we captured them above, use those
		// (This handles the case where metadata was created before we added stat capture)
		if restoreMode == "" && currentMode != "" {
			restoreMode = currentMode
			restoreUID = currentUID
			restoreGID = currentGID
		}

		// Apply permissions to the alternative file (so it matches the original file's permissions)
		if restoreMode != "" {
			chmodCmd := exec.Command("chmod", restoreMode, targetFile)
			if err := RootExec.Run(chmodCmd); err != nil {
				debugf("Warning: failed to set permissions on alternative file: %v\n", err)
			} else {
				debugf("Applied permissions %s to alternative file %s\n", restoreMode, targetFile)
			}
		}

		// Apply ownership to the alternative file (so it matches the original file's ownership)
		if restoreUID != 0 || restoreGID != 0 {
			if os.Geteuid() == 0 {
				if err := os.Chown(targetFile, restoreUID, restoreGID); err != nil {
					debugf("Warning: failed to set ownership on alternative file natively: %v\n", err)
				}
			} else {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", restoreUID, restoreGID), targetFile)
				if err := RootExec.Run(chownCmd); err != nil {
					debugf("Warning: failed to set ownership on alternative file: %v\n", err)
				} else {
					debugf("Applied ownership %d:%d to alternative file %s\n", restoreUID, restoreGID, targetFile)
				}
			}
		}

		// Update metadata to mark as active
		alt.IsActive = true
		metadataFile := getAlternativesMetadataFile(pkgName)
		data, err := json.MarshalIndent(alternatives, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		// Write to temp file first, then copy with executor
		tmpFile, err := os.CreateTemp("", "hokuto-alt-metadata-*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpFilePath := tmpFile.Name()
		defer os.Remove(tmpFilePath)

		if _, err = tmpFile.Write(data); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write temp metadata: %w", err)
		}
		if err = tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp file: %w", err)
		}

		cpCmd := exec.Command("cp", tmpFilePath, metadataFile)
		if err = RootExec.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to write metadata file: %w", err)
		}
		// Set permissions so the file is readable by all
		chmodCmd := exec.Command("chmod", "644", metadataFile)
		if err = RootExec.Run(chmodCmd); err != nil {
			debugf("Warning: failed to set permissions on metadata file: %v\n", err)
		}
	}

	return nil
}

// switchToOriginal switches from the alternative back to the original file
func switchToOriginal(pkgName, filePath string, execCtx *Executor) error {
	backupDir := filepath.Join(getAlternativesDir(pkgName), "backup")
	backupFileName := strings.ReplaceAll(strings.TrimPrefix(filePath, "/"), "/", "_")
	backupFilePath := filepath.Join(backupDir, backupFileName)
	targetFile := filepath.Join(rootDir, strings.TrimPrefix(filePath, "/"))

	// Check if backup exists (use Lstat to not follow symlinks)
	if _, err := os.Lstat(backupFilePath); os.IsNotExist(err) {
		return fmt.Errorf("original file backup not found: %s", backupFilePath)
	}

	// Restore original file from backup - use native if root, else executor
	if os.Geteuid() == 0 {
		if err := copyFile(backupFilePath, targetFile); err != nil {
			return fmt.Errorf("failed to restore original file natively: %w", err)
		}
	} else {
		// Use cp -a to preserve symlinks
		cpCmd := exec.Command("cp", "-a", backupFilePath, targetFile)
		if err := RootExec.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to restore original file: %w", err)
		}
	}

	// Restore permissions and ownership from metadata
	// Use BackupMode/BackupUID/BackupGID if available (for files that were switched multiple times)
	// Otherwise fall back to Mode/UID/GID (original file's permissions)
	alternatives, err := loadAlternativesMetadata(pkgName)
	if err != nil {
		debugf("Warning: failed to load metadata for permission restoration: %v\n", err)
	} else if alt, ok := alternatives[filePath]; ok {
		// Determine which permissions to use
		restoreMode := alt.BackupMode
		restoreUID := alt.BackupUID
		restoreGID := alt.BackupGID

		// If backup stat is not set, use the original file's stat
		if restoreMode == "" {
			restoreMode = alt.Mode
			restoreUID = alt.UID
			restoreGID = alt.GID
		}

		// Restore permissions - use root executor
		if restoreMode != "" {
			chmodCmd := exec.Command("chmod", restoreMode, targetFile)
			if err = RootExec.Run(chmodCmd); err != nil {
				debugf("Warning: failed to restore permissions for %s: %v\n", filePath, err)
			} else {
				debugf("Restored permissions %s to original file %s\n", restoreMode, targetFile)
			}
		}

		// Restore ownership (only if UID/GID are set) - use root executor
		if restoreUID != 0 || restoreGID != 0 {
			chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", restoreUID, restoreGID), targetFile)
			if err = RootExec.Run(chownCmd); err != nil {
				debugf("Warning: failed to restore ownership for %s: %v\n", filePath, err)
			} else {
				debugf("Restored ownership %d:%d to original file %s\n", restoreUID, restoreGID, targetFile)
			}
		}
	}

	// Update metadata to mark as inactive
	// Note: alternatives and err are already declared above, so we reload them
	alternatives, err = loadAlternativesMetadata(pkgName)
	if err != nil {
		return err
	}

	if alt, ok := alternatives[filePath]; ok {
		alt.IsActive = false
		metadataFile := getAlternativesMetadataFile(pkgName)
		data, err := json.MarshalIndent(alternatives, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		// Write to temp file first, then copy with executor
		tmpFile, err := os.CreateTemp("", "hokuto-alt-metadata-*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpFilePath := tmpFile.Name()
		defer os.Remove(tmpFilePath)

		if _, err = tmpFile.Write(data); err != nil {
			tmpFile.Close()
			return fmt.Errorf("failed to write temp metadata: %w", err)
		}
		if err = tmpFile.Close(); err != nil {
			return fmt.Errorf("failed to close temp file: %w", err)
		}

		cpCmd := exec.Command("cp", tmpFilePath, metadataFile)
		if err = RootExec.Run(cpCmd); err != nil {
			return fmt.Errorf("failed to write metadata file: %w", err)
		}
		// Set permissions so the file is readable by all
		chmodCmd := exec.Command("chmod", "644", metadataFile)
		if err = RootExec.Run(chmodCmd); err != nil {
			debugf("Warning: failed to set permissions on metadata file: %v\n", err)
		}
	}

	return nil
}

// restoreAlternativesOnUninstall restores all alternatives when a package is uninstalled
// It only restores alternatives if the source package is still installed or is "no package"
// restoredFilesToKeep is a map that will be populated with file paths that should not be removed
// (files restored from "no package" or other installed packages)
func restoreAlternativesOnUninstall(pkgName string, execCtx *Executor, hRoot string, restoredFilesToKeep map[string]bool) error {
	alternatives, err := loadAlternativesMetadata(pkgName)
	if err != nil {
		return err
	}

	if len(alternatives) == 0 {
		return nil // No alternatives to restore
	}

	// Group alternatives by source package
	type altInfo struct {
		filePath string
		alt      *AlternativeInfo
	}
	alternativesBySource := make(map[string][]altInfo)

	// First pass: collect all alternatives that should be restored, grouped by source
	for filePath, alt := range alternatives {
		var checkPkg string
		var shouldRestore bool

		if alt.IsActive {
			// Active: we're using the alternative, need to restore original from backup
			// The original file belongs to OriginalPkg
			if alt.SourcePkg == pkgName {
				// Alternative is from the package being uninstalled
				// We should restore the ORIGINAL file (from backup) if OriginalPkg is still available
				checkPkg = alt.OriginalPkg
				if checkPkg == "" || checkPkg == "no package" {
					shouldRestore = true
				} else {
					originalPkgDir := filepath.Join(hRoot, "var", "db", "hokuto", "installed", checkPkg)
					if _, err := os.Stat(originalPkgDir); err == nil {
						shouldRestore = true
					}
				}
			} else if alt.SourcePkg == "no package" {
				checkPkg = alt.SourcePkg
				shouldRestore = true
			} else if alt.OriginalPkg == pkgName {
				// The backup contains the package being uninstalled
				// We should keep the current file (which is from SourcePkg)
				// Mark current file to keep
				checkPkg = pkgName
				shouldRestore = false
			} else {
				checkPkg = alt.SourcePkg
				sourcePkgDir := filepath.Join(hRoot, "var", "db", "hokuto", "installed", checkPkg)
				if _, err := os.Stat(sourcePkgDir); err == nil {
					shouldRestore = true
				}
			}
		} else {
			// Inactive: we're using the original (from package), need to restore the alternative file
			checkPkg = alt.SourcePkg
			// Don't restore if the alternative is from the package being uninstalled
			// In this case, keep the current file (which is the original)
			if checkPkg == pkgName {
				shouldRestore = false
			} else if checkPkg == "no package" {
				shouldRestore = true
			} else {
				sourcePkgDir := filepath.Join(hRoot, "var", "db", "hokuto", "installed", checkPkg)
				if _, err := os.Stat(sourcePkgDir); err == nil {
					shouldRestore = true
				}
			}
		}

		if shouldRestore {
			alternativesBySource[checkPkg] = append(alternativesBySource[checkPkg], altInfo{filePath: filePath, alt: alt})
		} else if checkPkg == pkgName {
			// Alternative is from the package being uninstalled, mark current file to keep
			var absPath string
			if filepath.IsAbs(filePath) {
				if hRoot != "/" {
					absPath = filepath.Join(hRoot, filePath[1:])
				} else {
					absPath = filePath
				}
			} else {
				absPath = filepath.Join(hRoot, filePath)
			}
			restoredFilesToKeep[filepath.Clean(absPath)] = true
			debugf("Keeping current file %s (alternative from package being uninstalled)\n", filePath)
		}
	}

	// Second pass: restore alternatives, showing message per source package
	for checkPkg, altList := range alternativesBySource {
		// Show header message for this source
		colArrow.Print("-> ")
		if checkPkg == "no package" {
			colInfo.Println("restoring alternative files from no package:")
		} else {
			colInfo.Printf("restoring alternative files from %s package:\n", checkPkg)
		}

		// Restore each file and show its path
		for _, altInfo := range altList {
			filePath := altInfo.filePath
			alt := altInfo.alt

			if alt.IsActive {
				// Active: restore original from backup
				if err := switchToOriginal(pkgName, filePath, execCtx); err != nil {
					debugf("Warning: failed to restore alternative for %s: %v\n", filePath, err)
					continue
				}
			} else {
				// Inactive: restore alternative file directly
				altFilePath := getAlternativeFilePath(pkgName, filePath)
				targetFile := filepath.Join(hRoot, strings.TrimPrefix(filePath, "/"))

				if _, err := os.Lstat(altFilePath); os.IsNotExist(err) {
					debugf("Warning: alternative file not found for %s: %s\n", filePath, altFilePath)
					continue
				}

				// Use native if root, else executor
				if os.Geteuid() == 0 {
					if err := copyFile(altFilePath, targetFile); err != nil {
						debugf("Warning: failed to restore alternative file natively for %s: %v\n", filePath, err)
						continue
					}
				} else {
					// Use cp -a to preserve symlinks
					cpCmd := exec.Command("cp", "-a", altFilePath, targetFile)
					if err := RootExec.Run(cpCmd); err != nil {
						debugf("Warning: failed to restore alternative file for %s: %v\n", filePath, err)
						continue
					}
				}

				// Restore permissions and ownership
				if alt.Mode != "" {
					chmodCmd := exec.Command("chmod", alt.Mode, targetFile)
					RootExec.Run(chmodCmd)
				}

				if alt.UID != 0 || alt.GID != 0 {
					chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", alt.UID, alt.GID), targetFile)
					RootExec.Run(chownCmd)
				}
			}

			// Show the file path
			colArrow.Print("-> ")
			colInfo.Println(filePath)

			// Mark it to keep
			var absPath string
			if filepath.IsAbs(filePath) {
				if hRoot != "/" {
					absPath = filepath.Join(hRoot, filePath[1:])
				} else {
					absPath = filePath
				}
			} else {
				absPath = filepath.Join(hRoot, filePath)
			}
			restoredFilesToKeep[filepath.Clean(absPath)] = true
		}
	}

	return nil
}

// listPackagesWithAlternatives returns a list of packages that have alternatives
func listPackagesWithAlternatives() ([]string, error) {
	alternativesBaseDir := filepath.Join(rootDir, "var", "db", "hokuto", "alternatives")
	var packages []string

	debugf("Checking for alternatives in: %s\n", alternativesBaseDir)
	if _, err := os.Stat(alternativesBaseDir); os.IsNotExist(err) {
		debugf("Alternatives base directory does not exist: %s\n", alternativesBaseDir)
		return packages, nil
	}

	entries, err := os.ReadDir(alternativesBaseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read alternatives directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Check if this package has any alternatives
			metadataFile := getAlternativesMetadataFile(entry.Name())
			debugf("Checking metadata file: %s\n", metadataFile)
			if _, err := os.Stat(metadataFile); err == nil {
				alternatives, err := loadAlternativesMetadata(entry.Name())
				if err == nil && len(alternatives) > 0 {
					debugf("Found %d alternatives for package %s\n", len(alternatives), entry.Name())
					packages = append(packages, entry.Name())
				} else if err != nil {
					debugf("Error loading alternatives for %s: %v\n", entry.Name(), err)
				}
			}
		}
	}

	return packages, nil
}

// handleAlternativesCommand handles the 'hokuto alt' command
func handleAlternativesCommand(args []string) error {
	if len(args) == 0 {
		// List all packages with alternatives
		packages, err := listPackagesWithAlternatives()
		if err != nil {
			return err
		}

		if len(packages) == 0 {
			colInfo.Println("No packages have alternatives.")
			return nil
		}

		for _, pkg := range packages {
			alternatives, err := loadAlternativesMetadata(pkg)
			if err != nil {
				continue
			}
			count := len(alternatives)
			colArrow.Print("-> ")
			colInfo.Printf("%s has %d alternative(s)\n", pkg, count)
		}
		return nil
	}

	// Show alternatives for a specific package
	pkgName := args[0]
	alternatives, err := loadAlternativesMetadata(pkgName)
	if err != nil {
		return fmt.Errorf("failed to load alternatives for %s: %w", pkgName, err)
	}

	if len(alternatives) == 0 {
		colInfo.Printf("Package %s has no alternatives.\n", pkgName)
		return nil
	}

	// Display alternatives
	hasActive := false
	hasInactive := false

	for filePath, alt := range alternatives {
		if alt.IsActive {
			hasActive = true
			colArrow.Print("-> ")
			// When alternative is active, current file is from SourcePkg
			if alt.SourcePkg == "no package" {
				colInfo.Printf("%s using file from no package\n", filePath)
			} else {
				colInfo.Printf("%s using file from %s package\n", filePath, alt.SourcePkg)
			}
		} else {
			hasInactive = true
			colArrow.Print("-> ")
			// When alternative is inactive, current file is from OriginalPkg (if set) or pkgName
			// It's the file KEPT or RESTORED to its original place
			src := pkgName
			if alt.OriginalPkg != "" {
				src = alt.OriginalPkg
			}
			colInfo.Printf("%s using file from %s package\n", filePath, src)
		}
	}

	// Prompt for switching
	stdinReader := bufio.NewReader(os.Stdin)
	if hasActive {
		// Some alternatives are active, offer to switch to original
		// Find the OriginalPkg to show in the prompt
		var originalPkg string
		for _, alt := range alternatives {
			if alt.IsActive {
				if alt.OriginalPkg == "no package" || alt.OriginalPkg == "" {
					originalPkg = "no package"
				} else {
					originalPkg = alt.OriginalPkg
				}
				break // Use first active alternative's OriginalPkg
			}
		}
		fmt.Println()
		colArrow.Print("-> ")
		if originalPkg == "no package" {
			colInfo.Print("Do you want to switch to files from no package? [y/N]: ")
		} else {
			colInfo.Printf("Do you want to switch to files from %s package? [y/N]: ", originalPkg)
		}
		response, err := stdinReader.ReadString('\n')
		if err != nil {
			return nil
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "y" || response == "yes" {
			for filePath, alt := range alternatives {
				if alt.IsActive {
					if err := switchToOriginal(pkgName, filePath, RootExec); err != nil {
						colError.Printf("Failed to switch %s to original: %v\n", filePath, err)
					} else {
						colSuccess.Printf("Switched %s to original file\n", filePath)
					}
				}
			}
		}
	} else if hasInactive {
		// Some alternatives are inactive, offer to switch to alternatives
		// Find the SourcePkg to show in the prompt
		var sourcePkg string
		for _, alt := range alternatives {
			if !alt.IsActive {
				if alt.SourcePkg == "no package" {
					sourcePkg = "no package"
				} else {
					sourcePkg = alt.SourcePkg
				}
				break // Use first inactive alternative's SourcePkg
			}
		}
		fmt.Println()
		colArrow.Print("-> ")
		if sourcePkg == "no package" {
			colInfo.Print("Do you want to switch to files from no package? [y/N]: ")
		} else {
			colInfo.Printf("Do you want to switch to files from %s package? [y/N]: ", sourcePkg)
		}
		response, err := stdinReader.ReadString('\n')
		if err != nil {
			return nil
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "y" || response == "yes" {
			for filePath, alt := range alternatives {
				if !alt.IsActive {
					if err := switchToAlternative(pkgName, filePath, RootExec); err != nil {
						colError.Printf("Failed to switch %s to alternative: %v\n", filePath, err)
					} else {
						colSuccess.Printf("Switched %s to alternative file\n", filePath)
					}
				}
			}
		}
	}

	return nil
}
