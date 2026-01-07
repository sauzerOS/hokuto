package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type fileMetadata struct {
	AbsPath string
	B3Sum   string
}

// askForConfirmation prompts the user and defaults to 'yes'.
// It can print the prompt with a specific color style if p is not nil.

func lstatViaExecutor(path string, execCtx *Executor) (string, error) {
	if !execCtx.ShouldRunAsRoot {
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("failed to lstat %s: %v", path, err)
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			return "symbolic link", nil
		}
		if mode.IsDir() {
			return "directory", nil
		}
		if mode.IsRegular() {
			if info.Size() == 0 {
				return "regular empty file", nil
			}
			return "regular file", nil
		}
		return "unknown", nil
	}

	cmd := exec.Command("stat", "-c", "%F", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := execCtx.Run(cmd); err != nil {
		return "", fmt.Errorf("failed to stat %s: %v: %s", path, err, out.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func listOutputFiles(outputDir string, execCtx *Executor) ([]string, error) {
	var entries []string

	cmd := exec.Command("find", outputDir)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := execCtx.Run(cmd); err != nil {
		return nil, fmt.Errorf("failed to list output files via find: %v", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		path := scanner.Text()

		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			continue
		}
		if rel == "." {
			continue
		}

		// Filter out libtool .la files and charset.alias
		if strings.HasSuffix(rel, ".la") || strings.HasSuffix(rel, "charset.alias") {
			continue
		}

		isDir, err := isDirectoryPrivileged(path, execCtx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to stat file with privilege, skipping %s: %v\n", path, err)
			continue
		}

		if isDir {
			entries = append(entries, "/"+rel+"/")
		} else {
			entries = append(entries, "/"+rel)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %v", err)
	}

	sort.Strings(entries)
	return entries, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Copy file mode
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, info.Mode())
}

// copyDir recursively copies a directory from src to dst

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// shouldStripTar inspects the tarball to check for a single top-level directory.

func copyTreeWithTar(src, dst string, execCtx *Executor) error {
	// Create an in-memory tar archive of the source
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Walk the source directory and add everything to tar
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get the path relative to src
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself (we want contents only)
		if rel == "." {
			return nil
		}

		// For symlinks, we need to use Lstat to get the link info, not the target
		var linkTarget string
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				// If we can't read the symlink as the current user and need root
				if execCtx.ShouldRunAsRoot {
					cmd := exec.Command("readlink", path)
					var out bytes.Buffer
					cmd.Stdout = &out
					if err := execCtx.Run(cmd); err != nil {
						return fmt.Errorf("failed to read symlink %s: %w", path, err)
					}
					linkTarget = strings.TrimSpace(out.String())
				} else {
					return fmt.Errorf("failed to read symlink %s: %w", path, err)
				}
			}
		}

		// Create tar header
		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}

		// Set the name to the relative path
		hdr.Name = rel

		// Write header
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// For regular files, write the content
		if info.Mode().IsRegular() {
			// If we need root privileges to read the file, use cat
			if execCtx.ShouldRunAsRoot {
				cmd := exec.Command("cat", path)
				var out bytes.Buffer
				cmd.Stdout = &out
				if err := execCtx.Run(cmd); err != nil {
					return fmt.Errorf("failed to read file %s with privileges: %w", path, err)
				}
				if _, err := tw.Write(out.Bytes()); err != nil {
					return err
				}
			} else {
				// Try to open directly
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				if _, err := io.Copy(tw, f); err != nil {
					f.Close()
					return err
				}
				f.Close()
			}
		}

		return nil
	})

	if err != nil {
		tw.Close()
		return fmt.Errorf("failed to create tar archive: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	// Now extract the tar archive to the destination
	tr := tar.NewReader(&buf)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read error: %w", err)
		}

		target := filepath.Join(dst, hdr.Name)

		// Create parent directory if needed
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			// If we can't create as user, try with privileges
			if execCtx.ShouldRunAsRoot {
				mkdirCmd := exec.Command("mkdir", "-p", filepath.Dir(target))
				if err := execCtx.Run(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create parent dir %s: %w", filepath.Dir(target), err)
				}
			} else {
				return fmt.Errorf("failed to create parent dir %s: %w", filepath.Dir(target), err)
			}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				if execCtx.ShouldRunAsRoot {
					mkdirCmd := exec.Command("mkdir", "-p", target)
					if err := execCtx.Run(mkdirCmd); err != nil {
						return fmt.Errorf("failed to create dir %s: %w", target, err)
					}
					chmodCmd := exec.Command("chmod", fmt.Sprintf("%o", hdr.Mode), target)
					execCtx.Run(chmodCmd) // best effort
				} else {
					return err
				}
			}
			// Set ownership and times
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}
			os.Chtimes(target, hdr.AccessTime, hdr.ModTime) // best effort

		case tar.TypeReg:
			// Write file content
			outFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				if execCtx.ShouldRunAsRoot {
					// Create file via shell redirection
					var content bytes.Buffer
					if _, err := io.Copy(&content, tr); err != nil {
						return fmt.Errorf("failed to read file content: %w", err)
					}

					// Write via dd for privilege escalation
					ddCmd := exec.Command("dd", "of="+target, "status=none")
					ddCmd.Stdin = &content
					if err := execCtx.Run(ddCmd); err != nil {
						return fmt.Errorf("failed to write file %s with privileges: %w", target, err)
					}

					chmodCmd := exec.Command("chmod", fmt.Sprintf("%o", hdr.Mode), target)
					execCtx.Run(chmodCmd) // best effort
				} else {
					return fmt.Errorf("failed to create file %s: %w", target, err)
				}
			} else {
				if _, err := io.Copy(outFile, tr); err != nil {
					outFile.Close()
					return fmt.Errorf("failed to write file %s: %w", target, err)
				}
				outFile.Close()
			}

			// Set ownership and times
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}
			os.Chtimes(target, hdr.AccessTime, hdr.ModTime) // best effort

		case tar.TypeSymlink:
			// Remove existing file/link if present
			os.Remove(target)

			if err := os.Symlink(hdr.Linkname, target); err != nil {
				if execCtx.ShouldRunAsRoot {
					lnCmd := exec.Command("ln", "-sf", hdr.Linkname, target)
					if err := execCtx.Run(lnCmd); err != nil {
						return fmt.Errorf("failed to create symlink %s: %w", target, err)
					}
				} else {
					return fmt.Errorf("failed to create symlink %s: %w", target, err)
				}
			}

			// Set ownership on the symlink itself
			if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", "-h", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}

		case tar.TypeLink:
			// Hard link
			linkTarget := filepath.Join(dst, hdr.Linkname)
			os.Remove(target)

			if err := os.Link(linkTarget, target); err != nil {
				if execCtx.ShouldRunAsRoot {
					lnCmd := exec.Command("ln", linkTarget, target)
					if err := execCtx.Run(lnCmd); err != nil {
						return fmt.Errorf("failed to create hard link %s: %w", target, err)
					}
				} else {
					return fmt.Errorf("failed to create hard link %s: %w", target, err)
				}
			}

		default:
			debugf("Skipping unsupported tar entry type %c: %s\n", hdr.Typeflag, hdr.Name)
		}
	}

	return nil
}

// executePostInstall runs the post-install script for pkgName if present.
// If rootDir != "/" it attempts to run the same absolute path via chroot.
// If chroot fails the function prints a warning and returns nil.

func getModifiedFiles(pkgName, rootDir string, execCtx *Executor) ([]string, error) {

	installedDir := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName)
	manifestFile := filepath.Join(installedDir, "manifest")

	// Check if manifest exists
	if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
		return nil, nil // no previously installed files
	}

	// Read manifest entries
	data, err := readFileAsRoot(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %v", err)
	}

	// First pass: collect all file paths that need checksumming
	var filesToCheck []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		relPath := parts[0]
		relSlash := filepath.ToSlash(relPath)
		// Skip all metadata files under var/db/hokuto (internal package metadata)
		// Handles both "var/db/hokuto/..." and "/var/db/hokuto/..." paths
		cleanSlash := strings.TrimPrefix(relSlash, "/")
		if strings.HasPrefix(cleanSlash, "var/db/hokuto/") {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)

		// Skip entries with 000000 hash (symlinks)
		if len(parts) > 1 && parts[1] == "000000" {
			continue
		}

		filesToCheck = append(filesToCheck, absPath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	// Compute checksums - use optimized path for user-built packages
	var checksums map[string]string
	if !execCtx.ShouldRunAsRoot {
		// Fast path: parallel processing for user-built packages
		var err error
		checksums, err = b3sumBatch(filesToCheck, runtime.NumCPU()*2)
		if err != nil {
			// Fall back to sequential processing if batch fails
			checksums = make(map[string]string)
			for _, absPath := range filesToCheck {
				sum, err := b3sum(absPath, execCtx)
				if err != nil {
					continue // skip missing files or checksum failures
				}
				checksums[absPath] = sum
			}
		}
	} else {
		// Slow path: sequential processing for root-built packages
		checksums = make(map[string]string)
		for _, absPath := range filesToCheck {
			sum, err := b3sum(absPath, execCtx)
			if err != nil {
				continue // skip missing files or checksum failures
			}
			checksums[absPath] = sum
		}
	}

	// Second pass: compare checksums and find modified files
	var modified []string
	scanner = bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		relPath := parts[0]
		relSlash := filepath.ToSlash(relPath)
		// Skip all metadata files under var/db/hokuto (internal package metadata)
		// Handles both "var/db/hokuto/..." and "/var/db/hokuto/..." paths
		cleanSlash := strings.TrimPrefix(relSlash, "/")
		if strings.HasPrefix(cleanSlash, "var/db/hokuto/") {
			continue
		}

		// Skip entries with 000000 hash (symlinks)
		if parts[1] == "000000" {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)
		currentSum, exists := checksums[absPath]
		if !exists {
			continue // file doesn't exist or checksum failed
		}

		if parts[1] != currentSum {
			modified = append(modified, relPath)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	return modified, nil
}

func isDirectoryPrivileged(path string, execCtx *Executor) (bool, error) {
	// We use the shell 'test -d <path>' command.
	// It returns exit code 0 if the path is a directory, 1 otherwise.
	// Since this command is simple, we run it directly through the Executor.
	cmd := exec.Command("test", "-d", path)

	// The Run method returns nil on success (exit code 0).
	err := execCtx.Run(cmd)

	if err == nil {
		// Exit code 0: it is a directory.
		return true, nil
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		// Exit code 1: it is NOT a directory (or the path doesn't exist, etc.).
		// Since 'find' already gave us the path, we assume exit code 1 means 'not a directory'.
		if exitError.ExitCode() == 1 {
			return false, nil
		}
		// Handle other non-zero exit codes as a genuine error (e.g., -1 for failure)
		return false, fmt.Errorf("privileged test failed with unexpected exit code %d: %w", exitError.ExitCode(), err)
	}

	// Handle non-ExitError (e.g., failed to start the command)
	return false, err
}

func readFileAsRoot(path string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return os.ReadFile(path)
	}

	cmd := exec.Command("sudo", "cat", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
