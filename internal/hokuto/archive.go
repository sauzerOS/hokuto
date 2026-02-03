package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

func unzipGo(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	dest, err = filepath.Abs(dest)
	if err != nil {
		return err
	}

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		// Security Check: Prevent Zip Slip path traversal attacks.
		// Ensure the file path is within the destination directory.
		if !strings.HasPrefix(fpath, dest+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path in archive: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)

		// Close files inside the loop to avoid holding too many file descriptors.
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

// prepareSources copies and extracts sources into the build directory

func shouldStripTar(archive string) (bool, error) {
	debugf("Running strip check for tar extraction")

	// Only list first 51 entries - much faster for large archives
	cmd := exec.Command("sh", "-c", fmt.Sprintf("tar tf %s | head -n 51", archive))

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		// Tar failed to read or list the file.
		return false, fmt.Errorf("tar tf failed: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) == 0 || lines[0] == "" {
		// Archive is empty
		return false, nil
	}

	firstEntry := lines[0]

	// Find the first slash position
	slashIdx := strings.IndexByte(firstEntry, '/')
	if slashIdx == -1 {
		// No slash means a file/folder is at the root, so don't strip
		return false, nil
	}

	// The assumed top-level directory (including the slash)
	topDir := firstEntry[:slashIdx+1]

	// Check all entries to ensure they start with topDir
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, topDir) {
			// Found an entry not in the top directory
			return false, nil
		}
	}

	// All checked entries start with the same top directory prefix
	return true, nil
}

// extractTar extracts a tar archive (with possible compression) to targetDir,
// stripping the top-level directory while handling PAX headers and preserving timestamps.

func extractTar(realPath, dest string) error {
	// Open the archive file
	f, err := os.Open(realPath)
	if err != nil {
		return fmt.Errorf("failed to open archive %s: %w", realPath, err)
	}
	// Try system tar first
	//Inspect the tarball to see if it has a single top-level directory

	strip, err := shouldStripTar(realPath)
	if err != nil {
		// Non-fatal: record debug info so the variable 'err' is actually used.
		debugf("shouldStripTar(%s) failed: %v\n", realPath, err)
	}
	debugf("strip check done \n")
	args := []string{"xf", realPath, "-C", dest}

	if strip {
		args = append(args, "--strip-components=1")
	}
	debugf("extracting archive \n")
	if err := exec.Command("tar", args...).Run(); err == nil {
		// Close the opened file before returning early.
		_ = f.Close()
		debugf("Used system tar \n")
		return nil
	}
	defer f.Close()

	// Determine the compression type based on file extension
	var r io.Reader = f
	switch {
	case strings.HasSuffix(realPath, ".tar.gz") || strings.HasSuffix(realPath, ".tgz"):
		gz, err := pgzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader for %s: %w", realPath, err)
		}
		defer gz.Close()
		r = gz
	case strings.HasSuffix(realPath, ".tar.bz2"):
		r = bzip2.NewReader(f)
	case strings.HasSuffix(realPath, ".tar.xz"):
		xz, err := xz.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create xz reader for %s: %w", realPath, err)
		}
		r = xz
	case strings.HasSuffix(realPath, ".tar.zst"):
		zst, err := zstd.NewReader(f)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader for %s: %w", realPath, err)
		}
		defer zst.Close()
		r = zst
	case strings.HasSuffix(realPath, ".tar"):
		// No compression
	default:
		return fmt.Errorf("unsupported archive format: %s", realPath)
	}

	// Create tar reader
	tr := tar.NewReader(r)

	// Track the prefix for stripping (e.g., "linux-6.17.3/")
	var prefix string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar header in %s: %w", realPath, err)
		}

		// Skip PAX headers (global or per-file)
		if hdr.Typeflag == tar.TypeXHeader || hdr.Typeflag == tar.TypeXGlobalHeader {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return fmt.Errorf("error skipping extended header data in %s: %w", realPath, err)
			}
			continue
		}

		// Set prefix on the first non-extended content entry (dir or regular file)
		if prefix == "" && (hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeReg) {
			slashIdx := strings.Index(hdr.Name, "/")
			if slashIdx != -1 {
				prefix = hdr.Name[:slashIdx+1] // e.g., "linux-6.17.3/"
				debugf("Detected tar prefix for stripping: %s\n", prefix)
			}
		}

		// Apply stripping if prefix is set and matches
		targetName := hdr.Name
		if prefix != "" && strings.HasPrefix(targetName, prefix) {
			targetName = strings.TrimPrefix(targetName, prefix)
		}

		// If the stripped name is empty (e.g., the top dir itself), skip it
		if targetName == "" {
			continue
		}

		// Compute full output path
		targetPath := filepath.Join(dest, targetName)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent dir for %s: %w", targetPath, err)
		}

		// Handle based on entry type
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("failed to create dir %s: %w", targetPath, err)
			}
			// Set timestamp for directory
			if err := os.Chtimes(targetPath, hdr.AccessTime, hdr.ModTime); err != nil {
				return fmt.Errorf("failed to set times for dir %s: %w", targetPath, err)
			}
			// Restore ownership if running as root
			if os.Geteuid() == 0 {
				_ = os.Chown(targetPath, hdr.Uid, hdr.Gid)
			}
		case tar.TypeReg:
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close()
			// Set timestamp for file
			if err := os.Chtimes(targetPath, hdr.AccessTime, hdr.ModTime); err != nil {
				return fmt.Errorf("failed to set times for file %s: %w", targetPath, err)
			}
			// Restore ownership if running as root
			if os.Geteuid() == 0 {
				_ = os.Chown(targetPath, hdr.Uid, hdr.Gid)
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, targetPath); err != nil && !os.IsExist(err) {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, hdr.Linkname, err)
			}
			// Restore ownership (don't chase link) if running as root
			if os.Geteuid() == 0 {
				_ = unix.Lchown(targetPath, hdr.Uid, hdr.Gid)
			}
			// Set timestamp for symlink using unix.Lutimes with Timeval
			atime := unix.Timeval{
				Sec:  hdr.AccessTime.Unix(),
				Usec: int64(hdr.AccessTime.Nanosecond() / 1000), // Convert nanoseconds to microseconds
			}
			mtime := unix.Timeval{
				Sec:  hdr.ModTime.Unix(),
				Usec: int64(hdr.ModTime.Nanosecond() / 1000), // Convert nanoseconds to microseconds
			}
			if err := unix.Lutimes(targetPath, []unix.Timeval{atime, mtime}); err != nil {
				debugf("Warning: failed to set times for symlink %s: %v (continuing)\n", targetPath, err)
				// Don't fail on symlink time errors, as they may not be critical
			}
		default:
			debugf("Skipping unsupported tar entry type %c: %s\n", hdr.Typeflag, hdr.Name)
		}
	}

	// If no prefix was found, warn but don't fail (archive might not have a top dir)
	if prefix == "" {
		debugf("No top-level directory prefix found in %s; extracted without stripping\n", realPath)
	}

	return nil
}

// unpackTarballFallback extracts a .tar.zst into dest using pure-Go.
func unpackTarballFallback(tarballPath, dest string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {

		return fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		target := filepath.Join(dest, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
			if os.Geteuid() == 0 {
				_ = os.Chown(target, hdr.Uid, hdr.Gid)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
			if os.Geteuid() == 0 {
				_ = os.Chown(target, hdr.Uid, hdr.Gid)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil && !os.IsExist(err) {
				return err
			}
			if os.Geteuid() == 0 {
				_ = unix.Lchown(target, hdr.Uid, hdr.Gid)
			}
		}
	}
	return nil
}

// createPackageTarball creates a .tar.zst archive of outputDir into BinDir.
// It uses system tar if available, otherwise falls back to pure-Go tar+zstd.
// createPackageTarball creates a .tar.zst archive of outputDir into BinDir.
// It uses system tar if available, otherwise falls back to pure-Go tar+zstd.
func createPackageTarball(pkgName, pkgVer, pkgRev, arch, variant, outputDir string, execCtx *Executor, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	// Ensure BinDir exists
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create BinDir: %v", err)
	}

	tarballName := StandardizeRemoteName(pkgName, pkgVer, pkgRev, arch, variant)
	tarballPath := filepath.Join(BinDir, tarballName)

	// --- Try system tar first ---
	if _, err := exec.LookPath("tar"); err == nil {
		// FIX: Correct ownership AND permissions of the root directory '.' in the archive.
		// If we are building as root, the outputDir itself might still be owned by the user who started the build.
		// We must ensure the root of the package is owned by root:root and has 0755 permissions.
		if os.Geteuid() == 0 {
			if err := os.Chown(outputDir, 0, 0); err != nil {
				return fmt.Errorf("failed to chown outputDir to root natively: %v", err)
			}
			if err := os.Chmod(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to chmod outputDir to 0755 natively: %v", err)
			}
		} else if execCtx.ShouldRunAsRoot {
			chownCmd := exec.Command("chown", "0:0", outputDir)
			if err := execCtx.Run(chownCmd); err != nil {
				return fmt.Errorf("failed to chown outputDir to root: %v", err)
			}
			chmodCmd := exec.Command("chmod", "755", outputDir)
			if err := execCtx.Run(chmodCmd); err != nil {
				return fmt.Errorf("failed to chmod outputDir to 0755: %v", err)
			}
		} else {
			// Even if running as user, we should attempt to sanitize permissions.
			// The user likely owns the directory (created by pkgBuild), so this should succeed.
			// If it fails (e.g. not owner), we warn but continue, hoping strict mode isn't required.
			if err := os.Chmod(outputDir, 0755); err != nil {
				debugf("Warning: failed to chmod outputDir to 0755 as user: %v\n", err)
			}
		}

		args := []string{"--zstd", "-cf", tarballPath, "-C", outputDir, "."}
		if !execCtx.ShouldRunAsRoot {
			args = append(args, "--owner=0", "--group=0", "--numeric-owner")
		}
		tarCmd := exec.Command("tar", args...)
		debugf("Creating package tarball with system tar: %s\n", tarballPath)
		if err := execCtx.Run(tarCmd); err == nil {
			fmt.Fprint(logger, colArrow.Sprint("-> "))
			fmt.Fprintln(logger, colSuccess.Sprint("Package tarball created successfully"))
			return nil
		}
		// fall through to internal if tar fails
	}

	// --- Fallback: internal tar+zstd ---
	debugf("System tar not available, falling back to internal tar+zstd for %s\n", tarballPath)

	outFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball file: %v", err)
	}
	defer outFile.Close()

	// Create zstd writer
	zw, err := zstd.NewWriter(outFile)
	if err != nil {
		return fmt.Errorf("failed to create zstd writer: %v", err)
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	// Walk outputDir and add files
	err = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}

		var linkTarget string
		if info.Mode()&os.ModeSymlink != 0 {
			// Read the symlink target so we can store it in the tar header
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}
		}

		hdr, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}

		if rel == "." {
			hdr.Name = "./"
			hdr.Mode = 0755 // Force standard permissions for root
		} else {
			hdr.Name = rel
		}

		// Binary packages must be PORTABLY root-owned.
		// Always force numeric root ownership for all entries.
		hdr.Uid, hdr.Gid = 0, 0
		hdr.Uname, hdr.Gname = "root", "root"

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		if rel == "." {
			return nil
		}

		// Only copy file contents for regular files
		if info.Mode().IsRegular() {
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
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to add files to tarball: %v", err)
	}
	fmt.Fprint(logger, colArrow.Sprint("-> "))
	fmt.Fprintf(logger, "%s", colSuccess.Sprintf("Package tarball created successfully: %s\n", tarballPath))
	return nil
}

// compressXZ compresses a file using XZ
func compressXZ(srcPath, destPath string, execCtx *Executor) error {
	// Ensure destination directory exists using executor if needed
	destDir := filepath.Dir(destPath)
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory natively: %w", err)
		}
	} else if execCtx != nil && execCtx.ShouldRunAsRoot {
		mkdirCmd := exec.Command("mkdir", "-p", destDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}
	} else {
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	// Use executor to write file if running as root is needed
	if execCtx != nil && execCtx.ShouldRunAsRoot {
		// Write to a temp file first, then copy it using executor
		tmpFile, err := os.CreateTemp("", "hokuto-log-*.xz")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)

		xzWriter, err := xz.NewWriter(tmpFile)
		if err != nil {
			tmpFile.Close()
			return err
		}

		_, err = io.Copy(xzWriter, src)
		xzWriter.Close()
		tmpFile.Close()
		if err != nil {
			return fmt.Errorf("failed to compress to temp file: %w", err)
		}

		// Copy temp file to destination using executor or native if root
		if os.Geteuid() == 0 {
			if err := copyFile(tmpPath, destPath); err != nil {
				return fmt.Errorf("failed to copy compressed file natively: %w", err)
			}
			if err := os.Chmod(destPath, 0644); err != nil {
				return fmt.Errorf("failed to set file permissions natively: %w", err)
			}
		} else {
			// Copy temp file to destination using executor
			cpCmd := exec.Command("cp", tmpPath, destPath)
			if err := execCtx.Run(cpCmd); err != nil {
				return fmt.Errorf("failed to copy compressed file: %w", err)
			}
			chmodCmd := exec.Command("chmod", "644", destPath)
			if err := execCtx.Run(chmodCmd); err != nil {
				return fmt.Errorf("failed to set file permissions: %w", err)
			}
		}
		return nil
	}

	// Normal path: create and write directly
	dest, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer dest.Close()

	xzWriter, err := xz.NewWriter(dest)
	if err != nil {
		return err
	}
	defer xzWriter.Close()

	_, err = io.Copy(xzWriter, src)
	return err
}
