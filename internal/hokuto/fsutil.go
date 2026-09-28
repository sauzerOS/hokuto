package hokuto

import (
	"archive/tar"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type fileMetadata struct {
	AbsPath string
	B3Sum   string
}

// askForConfirmation prompts the user and defaults to 'yes'.
// It can print the prompt with a specific color style if p is not nil.

func lstatViaExecutor(path string, execCtx *Executor) (string, error) {
	if os.Geteuid() == 0 || !execCtx.ShouldRunAsRoot {
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

type FileListEntry struct {
	Path     string
	FileType string // "f" for file, "d" for directory, "l" for symlink, "o" for anything else (FIFO, socket, device)
}

func listOutputFilesWithTypes(outputDir string, execCtx *Executor) ([]FileListEntry, error) {
	// Optimization: If we have root (or don't need it), use native Go
	if os.Geteuid() == 0 || !execCtx.ShouldRunAsRoot {
		var entries []FileListEntry
		// WalkDir takes file types from the directory entries instead of
		// an lstat per file; like Walk it never follows symlinks.
		err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(outputDir, path)
			if err != nil {
				return nil
			}
			if rel == "." {
				return nil
			}

			// Filter out charset.alias noise from generated manifests.
			if strings.HasSuffix(rel, "charset.alias") {
				return nil
			}

			entry := FileListEntry{}
			if d.IsDir() {
				entry.Path = "/" + rel + "/"
				entry.FileType = "d"
			} else if d.Type()&fs.ModeSymlink != 0 {
				entry.Path = "/" + rel
				entry.FileType = "l"
			} else if d.Type().IsRegular() {
				entry.Path = "/" + rel
				entry.FileType = "f"
			} else {
				entry.Path = "/" + rel
				entry.FileType = "o"
			}
			entries = append(entries, entry)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list output files natively: %v", err)
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Path < entries[j].Path
		})
		return entries, nil
	}

	// Privileged path: Use 'find' with -printf for massive speedup
	// %y returns type (f=file, d=dir, l=link)
	// %p returns full path
	// Output format: type path
	var entries []FileListEntry
	cmd := exec.Command("find", outputDir, "-printf", "%y %p\\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	// Only capture stderr if debug is on
	if !Debug {
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = os.Stderr
	}

	if err := execCtx.Run(cmd); err != nil {
		return nil, fmt.Errorf("failed to list output files via find: %v", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		// Parse "type path"
		// First char is type (f, d, l); find also reports p, s, b and c
		// for FIFOs, sockets and devices, which have no content to hash.
		ftype := string(line[0])
		if ftype != "f" && ftype != "d" && ftype != "l" {
			ftype = "o"
		}
		path := strings.TrimSpace(line[2:])

		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			continue
		}
		if rel == "." {
			continue
		}

		// Filter out charset.alias noise from generated manifests.
		if strings.HasSuffix(rel, "charset.alias") {
			continue
		}

		entry := FileListEntry{FileType: ftype}
		if ftype == "d" {
			entry.Path = "/" + rel + "/"
		} else {
			entry.Path = "/" + rel
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %v", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
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

// readXattrs returns every extended attribute set on path. These carry things
// the file mode cannot express -- most importantly security.capability, which
// is how file capabilities such as cap_sys_nice are stored.
func readXattrs(path string) map[string]string {
	sz, err := unix.Llistxattr(path, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = unix.Llistxattr(path, buf)
	if err != nil || sz <= 0 {
		return nil
	}
	out := map[string]string{}
	for _, name := range strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		vsz, err := unix.Lgetxattr(path, name, nil)
		if err != nil || vsz < 0 {
			continue
		}
		val := make([]byte, vsz)
		if _, err := unix.Lgetxattr(path, name, val); err != nil {
			continue
		}
		out[name] = string(val)
	}
	return out
}

// applyXattrs restores attributes carried in the tar header's PAX records.
// Best effort: security.* needs privileges, and a filesystem may not support
// xattrs at all, neither of which should abort an install.
func applyXattrs(target string, hdr *tar.Header) {
	for k, v := range hdr.PAXRecords {
		name, ok := strings.CutPrefix(k, "SCHILY.xattr.")
		if !ok {
			continue
		}
		if err := unix.Lsetxattr(target, name, []byte(v), 0); err != nil {
			debugf("Could not restore xattr %s on %s: %v\n", name, target, err)
		}
	}
}

func copyTreeWithTar(src, dst string, execCtx *Executor) error {
	// Create an in-memory tar archive of the source
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// A file with several names must be stored once and relinked on extraction,
	// the way rsync -H does, or a package that hard links its binaries is
	// silently duplicated on disk.
	seenInodes := make(map[uint64]string)

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
			if os.Geteuid() == 0 {
				linkTarget, err = os.Readlink(path)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s natively: %w", path, err)
				}
			} else {
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
		}

		// Create tar header
		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}

		// Set the name to the relative path
		hdr.Name = rel

		// Second and later names for one inode become hard links.
		isLink := false
		if info.Mode().IsRegular() {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
				if first, seen := seenInodes[uint64(st.Ino)]; seen {
					hdr.Typeflag = tar.TypeLink
					hdr.Linkname = first
					hdr.Size = 0
					isLink = true
				} else {
					seenInodes[uint64(st.Ino)] = rel
				}
			}
		}

		// Carry extended attributes (file capabilities, ACLs) across.
		if xs := readXattrs(path); len(xs) > 0 {
			if hdr.PAXRecords == nil {
				hdr.PAXRecords = make(map[string]string, len(xs))
			}
			for k, v := range xs {
				hdr.PAXRecords["SCHILY.xattr."+k] = v
			}
		}

		// Write header
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// For regular files, write the content
		if !isLink && info.Mode().IsRegular() {
			if os.Geteuid() == 0 {
				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open file %s natively: %w", path, err)
				}
				if _, err := io.Copy(tw, f); err != nil {
					f.Close()
					return err
				}
				f.Close()
			} else if execCtx.ShouldRunAsRoot {
				cmd := exec.Command("cat", path)
				var out bytes.Buffer
				cmd.Stdout = &out
				if Debug {
					cmd.Stderr = os.Stderr
				} else {
					cmd.Stderr = io.Discard
				}
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
				if os.Geteuid() == 0 {
					return fmt.Errorf("failed to create dir %s natively: %w", target, err)
				}
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
			if os.Geteuid() == 0 {
				_ = os.Chown(target, hdr.Uid, hdr.Gid)
			} else if execCtx.ShouldRunAsRoot {
				chownCmd := exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), target)
				execCtx.Run(chownCmd) // best effort
			}
			os.Chtimes(target, hdr.AccessTime, hdr.ModTime) // best effort

		case tar.TypeReg:
			if err := placeTarRegularFile(tr, hdr, target, execCtx); err != nil {
				return err
			}
			// Ownership, mode and xattrs were set before the rename.
			continue

		case tar.TypeSymlink:
			err := replaceAtomically(target, func(tmp string) error {
				if err := os.Symlink(hdr.Linkname, tmp); err != nil {
					return err
				}
				_ = unix.Lchown(tmp, hdr.Uid, hdr.Gid) // best effort when unprivileged
				return nil
			})
			if err != nil {
				if os.Geteuid() == 0 || !execCtx.ShouldRunAsRoot {
					return fmt.Errorf("failed to create symlink %s: %w", target, err)
				}
				tmp := target + placementTmpSuffix
				if err := execCtx.Run(exec.Command("ln", "-sfn", "--", hdr.Linkname, tmp)); err != nil {
					return fmt.Errorf("failed to create symlink %s: %w", target, err)
				}
				execCtx.Run(exec.Command("chown", "-h", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), tmp)) // best effort
				if err := execCtx.Run(exec.Command("mv", "-Tf", "--", tmp, target)); err != nil {
					return fmt.Errorf("failed to place symlink %s: %w", target, err)
				}
			}

		case tar.TypeLink:
			// Hard link to a file placed earlier in this archive.
			linkTarget := filepath.Join(dst, hdr.Linkname)
			err := replaceAtomically(target, func(tmp string) error {
				return os.Link(linkTarget, tmp)
			})
			if err != nil {
				if os.Geteuid() == 0 || !execCtx.ShouldRunAsRoot {
					return fmt.Errorf("failed to create hard link %s: %w", target, err)
				}
				tmp := target + placementTmpSuffix
				execCtx.Run(exec.Command("rm", "-f", "--", tmp)) // leftover from an interrupted install
				if err := execCtx.Run(exec.Command("ln", "--", linkTarget, tmp)); err != nil {
					return fmt.Errorf("failed to create hard link %s: %w", target, err)
				}
				if err := execCtx.Run(exec.Command("mv", "-Tf", "--", tmp, target)); err != nil {
					return fmt.Errorf("failed to place hard link %s: %w", target, err)
				}
			}

		default:
			debugf("Skipping unsupported tar entry type %c: %s\n", hdr.Typeflag, hdr.Name)
		}

		// Restore extended attributes last: writing content or chowning a file
		// clears security.capability, so this has to come after both.
		if len(hdr.PAXRecords) > 0 {
			applyXattrs(target, hdr)
		}
	}

	return nil
}

// placeTarRegularFile writes one regular file from the tar stream beside target
// under a temporary name and renames it into place. Writing into the existing
// file instead would change it underneath every process that has it mapped,
// and a program started mid-write would load a half-written library: this is
// how a sudo waiting for a placement segfaulted in the build container.
// Ownership, then the full mode (setuid and setgid included, which chown
// clears), timestamps and xattrs are applied before the rename, so the new
// file is never visible without them.
func placeTarRegularFile(r io.Reader, hdr *tar.Header, target string, execCtx *Executor) error {
	mode := placementMode(hdr.FileInfo())
	mtime := hdr.ModTime
	atime := hdr.AccessTime
	if atime.IsZero() {
		atime = mtime
	}
	started := false
	err := replaceAtomically(target, func(tmp string) error {
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		started = true
		if _, err := io.Copy(out, r); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		_ = os.Lchown(tmp, hdr.Uid, hdr.Gid) // best effort when unprivileged
		if err := os.Chmod(tmp, mode); err != nil {
			return err
		}
		_ = os.Chtimes(tmp, atime, mtime)
		applyXattrs(tmp, hdr)
		return nil
	})
	if err == nil {
		return nil
	}
	// Without write access to the directory, escalate; only possible while
	// nothing of the stream has been consumed yet.
	if started || os.Geteuid() == 0 || execCtx == nil || !execCtx.ShouldRunAsRoot || !errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("failed to write file %s: %w", target, err)
	}
	tmp := target + placementTmpSuffix
	dd := exec.Command("dd", "of="+tmp, "status=none")
	dd.Stdin = r
	if err := execCtx.Run(dd); err != nil {
		return fmt.Errorf("failed to write file %s with privileges: %w", target, err)
	}
	execCtx.Run(exec.Command("chown", fmt.Sprintf("%d:%d", hdr.Uid, hdr.Gid), tmp)) // best effort
	if err := execCtx.Run(exec.Command("chmod", fmt.Sprintf("%o", hdr.Mode&0o7777), tmp)); err != nil {
		return fmt.Errorf("failed to set mode of %s: %w", target, err)
	}
	if err := execCtx.Run(exec.Command("mv", "-f", "--", tmp, target)); err != nil {
		return fmt.Errorf("failed to place file %s: %w", target, err)
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
		entry, ok, parseErr := parseManifestLine(scanner.Text())
		if parseErr != nil {
			return nil, fmt.Errorf("invalid manifest: %w", parseErr)
		}
		if !ok || strings.HasSuffix(entry.Path, "/") {
			continue
		}
		path := entry.Path
		checksum := entry.Checksum

		// Skip all metadata files under var/db/hokuto (internal package metadata)
		// Handles both "var/db/hokuto/..." and "/var/db/hokuto/..." paths
		cleanSlash := strings.TrimPrefix(filepath.ToSlash(path), "/")
		if strings.HasPrefix(cleanSlash, "var/db/hokuto/") {
			continue
		}

		absPath := filepath.Join(rootDir, path)

		// Skip entries with 000000 hash (symlinks)
		if checksum == "000000" {
			continue
		}

		filesToCheck = append(filesToCheck, absPath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	// Compute checksums using the unified optimized path
	checksums, err := ComputeChecksums(filesToCheck, execCtx)
	if err != nil {
		// Preserve successful batch results and retry only failed paths. A
		// permission failure must escape this function so install.go can retry
		// with the root executor; silently omitting it would make a modified
		// protected configuration file look unmodified.
		debugf("ComputeChecksums failed in getModifiedFiles: %v\n", err)
		for _, absPath := range filesToCheck {
			if _, ok := checksums[absPath]; ok {
				continue
			}
			sum, err := ComputeChecksum(absPath, execCtx)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue // Missing files will be restored by the package update.
				}
				return nil, fmt.Errorf("failed to checksum installed file %s: %w", absPath, err)
			}
			checksums[absPath] = sum
		}
	}

	// Second pass: compare checksums and find modified files
	var modified []string
	var alternativesDB *GlobalAlternativesDB
	alternativesLoaded := false
	scanner = bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		entry, ok, parseErr := parseManifestLine(scanner.Text())
		if parseErr != nil {
			return nil, fmt.Errorf("invalid manifest: %w", parseErr)
		}
		if !ok || strings.HasSuffix(entry.Path, "/") {
			continue
		}
		relPath := entry.Path
		expectedSum := entry.Checksum

		// Skip all metadata files under var/db/hokuto
		cleanSlash := strings.TrimPrefix(filepath.ToSlash(relPath), "/")
		if strings.HasPrefix(cleanSlash, "var/db/hokuto/") {
			continue
		}

		// Skip entries with 000000 hash (symlinks)
		if expectedSum == "000000" {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)
		currentSum, exists := checksums[absPath]
		if !exists {
			continue // file doesn't exist or checksum failed
		}

		if expectedSum == currentSum {
			continue
		}

		if !alternativesLoaded {
			alternativesDB, err = loadAlternativesDB(rootDir)
			if err != nil {
				return nil, fmt.Errorf("failed to load alternatives DB: %w", err)
			}
			alternativesLoaded = true
		}
		alternativePath := canonicalizePath(rootDir, relPath)
		if isRegisteredActiveAlternative(alternativesDB, pkgName, alternativePath, expectedSum, currentSum) {
			continue
		}

		modified = append(modified, relPath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	return modified, nil
}

func isRegisteredActiveAlternative(db *GlobalAlternativesDB, pkgName, path, expectedSum, currentSum string) bool {
	if db == nil {
		return false
	}
	entry := db.Files[path]
	if entry == nil {
		return false
	}

	expectedProvider := false
	activeMatchesDisk := false
	for _, alternative := range entry.Alternatives {
		if alternative == nil {
			continue
		}
		if alternative.B3Sum == expectedSum {
			for _, owner := range alternative.Owners {
				if owner == pkgName {
					expectedProvider = true
					break
				}
			}
		}
		if alternative.State == StateActive && alternative.B3Sum == currentSum {
			activeMatchesDisk = true
		}
	}
	return expectedProvider && activeMatchesDisk
}

func isDirectoryPrivileged(path string, execCtx *Executor) (bool, error) {
	if os.Geteuid() == 0 || !execCtx.ShouldRunAsRoot {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		return info.IsDir(), nil
	}

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
	// Try native read first
	data, err := os.ReadFile(path)
	if err == nil {
		return data, nil
	}
	// Only force sudo/run0 when the direct read failed because of permissions.
	if os.Geteuid() != 0 && os.IsPermission(err) {
		if RootExec != nil {
			cmd := exec.Command("cat", path)
			var out bytes.Buffer
			cmd.Stdout = &out
			if Debug {
				cmd.Stderr = os.Stderr
			} else {
				cmd.Stderr = io.Discard
			}
			if err := RootExec.Run(cmd); err == nil {
				return out.Bytes(), nil
			}
		}
	}
	return nil, err
}

func writeFileAsRoot(path string, data []byte, perm os.FileMode, execCtx *Executor) error {
	// Try native write first
	err := os.WriteFile(path, data, perm)
	if err == nil {
		return nil
	}

	if os.Geteuid() == 0 {
		return err // Should have worked if we are root
	}
	if execCtx == nil {
		return err
	}

	// Write to temp file first
	tmpFile, err := os.CreateTemp("", "hokuto-write-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	tmpFile.Close()

	// Move via the privileged executor to preserve content, then chmod.
	cpCmd := exec.Command("cp", tmpName, path)
	if err := execCtx.Run(cpCmd); err != nil {
		return fmt.Errorf("failed to write file %s as root: %w", path, err)
	}

	// Set permissions
	chmodCmd := exec.Command("chmod", fmt.Sprintf("%o", perm), path)
	if err := execCtx.Run(chmodCmd); err != nil {
		return fmt.Errorf("failed to chmod file %s as root: %w", path, err)
	}

	return nil
}

// copyFileAsRoot copies a file using the executor (wrapper around logic or sudo cp)
func copyFileAsRoot(src, dst string, execCtx *Executor) error {
	// Try native copy first
	if err := copyFile(src, dst); err == nil {
		return nil
	}

	if os.Geteuid() == 0 {
		return copyFile(src, dst)
	}

	// Use the privileged executor to preserve attributes if possible.
	cmd := exec.Command("cp", "-a", src, dst)
	return execCtx.Run(cmd)
}

// removeFileAsRoot removes a file using the executor
func removeFileAsRoot(path string, execCtx *Executor) error {
	// Try native remove first
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}

	if os.Geteuid() == 0 {
		return err
	}

	cmd := exec.Command("rm", "-f", path)
	return execCtx.Run(cmd)
}

// canonicalizePath joins rootDir and path, resolves symlinks, and returns the path relative to rootDir
func canonicalizePath(rootDir, path string) string {
	cleanPath := filepath.Clean(path)
	if cleanPath == "/" {
		if strings.HasPrefix(path, "/") {
			return "/"
		}
		return ""
	}
	absPath := filepath.Join(rootDir, strings.TrimPrefix(cleanPath, "/"))

	// Resolve symlinks of the parent directory only, to preserve the final component if it's a symlink.
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	resolvedDir, err := filepath.EvalSymlinks(dir)
	var resolved string
	if err == nil {
		resolved = filepath.Join(resolvedDir, base)
	} else {
		resolved = absPath
	}

	rel, err := filepath.Rel(rootDir, resolved)
	if err != nil {
		return cleanPath
	}

	if strings.HasPrefix(path, "/") {
		return "/" + strings.TrimPrefix(rel, "/")
	}
	return strings.TrimPrefix(rel, "/")
}
