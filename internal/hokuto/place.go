package hokuto

// Same-filesystem placement of a staging tree into the target root.
//
// The install pipeline unpacks a package into a staging directory and then has
// to move that tree into rootDir. Historically this was always an rsync, which
// copies every byte a second time. When staging and rootDir live on the same
// filesystem -- the normal case, since HOKUTO_TMPDIR defaults next to the root
// -- the same result can be reached by hard linking, which touches metadata
// only.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// noHardlinkPlacementEnv disables the hard link fast path and forces placement
// back onto rsync. Kept as an escape hatch for filesystems that accept link()
// but behave oddly afterwards.
const noHardlinkPlacementEnv = "HOKUTO_NO_HARDLINK_INSTALL"

// placementTmpSuffix marks the transient name a new entry is created under
// before it is renamed over its final path.
const placementTmpSuffix = ".hokuto-place-tmp"

// sameFilesystem reports whether the two paths live on the same device.
func sameFilesystem(a, b string) (bool, error) {
	sa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	statA, okA := sa.Sys().(*syscall.Stat_t)
	statB, okB := sb.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return false, nil
	}
	return statA.Dev == statB.Dev, nil
}

// canPlaceByHardlink decides whether the hard link fast path applies.
// installStagingBase picks a directory for install staging that sits on the
// same filesystem as rootDir, so a package can be hard-linked into place rather
// than copied byte for byte.
//
// This deliberately does not use TMPDIR. TMPDIR is commonly aimed at a tmpfs or
// zram disk so that *builds* happen in RAM, and that is a different filesystem
// from the root -- which silently disables hard-link placement and turns every
// install into a second full copy of every byte. Build temp and install staging
// want opposite things, so they no longer share a setting.
//
// The candidates are tried in order and the first one that lands on rootDir's
// filesystem wins. If none does, the caller's fallback (historically TMPDIR) is
// returned and placement degrades to a copy, exactly as before.
func installStagingBase(rootDir, fallback string, cfg *Config) string {
	if cfg != nil {
		if v := strings.TrimSpace(cfg.Values["STAGINGDIR"]); v != "" {
			if err := os.MkdirAll(v, 0o755); err == nil {
				return v
			}
			debugf("STAGINGDIR %s is unusable, falling back to autodetection\n", v)
		}
	}

	for _, candidate := range []string{
		filepath.Join(rootDir, "var/cache/hokuto/staging"),
		filepath.Join(rootDir, "var/lib/hokuto/staging"),
		filepath.Join(rootDir, ".hokuto-staging"),
	} {
		if err := os.MkdirAll(candidate, 0o755); err != nil {
			debugf("Staging candidate %s not creatable: %v\n", candidate, err)
			continue
		}
		same, err := sameFilesystem(candidate, rootDir)
		if err != nil {
			debugf("Cannot compare %s with root %s: %v\n", candidate, rootDir, err)
			continue
		}
		if same {
			return candidate
		}
		debugf("Staging candidate %s is on a different filesystem than %s\n", candidate, rootDir)
	}

	debugf("No same-filesystem staging location found; using %s\n", fallback)
	return fallback
}

func canPlaceByHardlink(stagingDir, rootDir string) bool {
	if os.Getenv(noHardlinkPlacementEnv) == "1" {
		debugf("Hard link placement disabled by %s\n", noHardlinkPlacementEnv)
		return false
	}
	same, err := sameFilesystem(stagingDir, rootDir)
	if err != nil {
		debugf("Cannot compare filesystems of %s and %s: %v\n", stagingDir, rootDir, err)
		return false
	}
	if !same {
		debugf("Staging %s and root %s are on different filesystems; copying instead of linking\n", stagingDir, rootDir)
	}
	return same
}

// placeStagingByHardlink populates rootDir from stagingDir using hard links.
//
// A hard link shares the inode, so mode, ownership, timestamps, xattrs and ACLs
// carry over exactly, and files that are hard linked to each other inside the
// package stay linked in the root. No file content is read or written.
//
// The semantics deliberately match the rsync invocation this replaces:
//
//   - --keep-dirlinks: a destination path that is a symlink to a directory is
//     left alone and written through. sauzerOS depends on this for /bin, /lib,
//     /lib32, /lib64 and /sbin, which are symlinks into usr/.
//
//   - entries are created under a temporary name and renamed into place rather
//     than written through, so a process already running from a file keeps the
//     inode it started with instead of seeing it change underneath.
func placeStagingByHardlink(stagingDir, rootDir string) error {
	stagingDir = filepath.Clean(stagingDir)
	rootDir = filepath.Clean(rootDir)

	// Fail here rather than part-way through the walk with a confusing mkdir
	// error, since the subcommand form can be invoked with anything.
	if fi, err := os.Stat(rootDir); err != nil {
		return fmt.Errorf("root %s is not usable: %w", rootDir, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("root %s is not a directory", rootDir)
	}

	type dirTimes struct {
		path         string
		atime, mtime time.Time
	}
	var dirs []dirTimes

	walkErr := filepath.WalkDir(stagingDir, func(srcPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(stagingDir, srcPath)
		if err != nil {
			return err
		}
		if rel == "." {
			// The root itself is never created or re-owned.
			return nil
		}
		dstPath := filepath.Join(rootDir, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}

		switch {
		case d.IsDir():
			if err := ensurePlacementDir(dstPath, info); err != nil {
				return fmt.Errorf("%s: %w", dstPath, err)
			}
			atime, mtime := fileTimes(info)
			dirs = append(dirs, dirTimes{path: dstPath, atime: atime, mtime: mtime})
			return nil

		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(srcPath)
			if err != nil {
				return err
			}
			err = replaceAtomically(dstPath, func(tmp string) error {
				if err := os.Symlink(target, tmp); err != nil {
					return err
				}
				return lchownFromInfo(tmp, info)
			})
			if err != nil {
				return fmt.Errorf("%s: %w", dstPath, err)
			}
			return nil

		default:
			// Regular files, devices, fifos and sockets all have an inode that
			// link() accepts, so every one of them is placed the same way.
			err = replaceAtomically(dstPath, func(tmp string) error {
				return os.Link(srcPath, tmp)
			})
			if err != nil {
				// A package can write below a nested mount: linux-rpi4 puts the
				// kernel and dtbs in /boot, which on a Pi is a separate vfat
				// partition. link() cannot cross a device, and vfat has no hard
				// links at all, so fall back to copying just this entry rather
				// than failing the whole placement.
				if isCrossDeviceLinkError(err) {
					debugf("Hard link not possible for %s (%v); copying instead\n", dstPath, err)
					if cerr := copyFilePreservingMetadata(srcPath, dstPath, info); cerr != nil {
						return fmt.Errorf("%s: %w", dstPath, cerr)
					}
					return nil
				}
				return fmt.Errorf("%s: %w", dstPath, err)
			}
			return nil
		}
	})
	if walkErr != nil {
		return walkErr
	}

	// Creating entries inside a directory bumps its mtime, so restore the
	// packaged timestamps once the tree is complete. WalkDir is top-down, so
	// walking the record in reverse handles children before their parents.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chtimes(dirs[i].path, dirs[i].atime, dirs[i].mtime); err != nil {
			debugf("Could not restore timestamps on %s: %v\n", dirs[i].path, err)
		}
	}
	return nil
}

// ensurePlacementDir makes dstPath a directory matching src, honouring the
// --keep-dirlinks rule for destinations that are symlinks to directories.
func ensurePlacementDir(dstPath string, src fs.FileInfo) error {
	existing, err := os.Lstat(dstPath)
	switch {
	case err == nil:
		switch {
		case existing.Mode()&fs.ModeSymlink != 0:
			if target, terr := os.Stat(dstPath); terr == nil && target.IsDir() {
				// Keep the link and place the contents through it.
				return nil
			}
			if err := os.Remove(dstPath); err != nil {
				return err
			}
		case existing.IsDir():
			if err := os.Chmod(dstPath, placementMode(src)); err != nil {
				return err
			}
			return lchownFromInfo(dstPath, src)
		default:
			if err := os.Remove(dstPath); err != nil {
				return err
			}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}

	if err := os.Mkdir(dstPath, placementMode(src)); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	// Mkdir is subject to the umask, so set the packaged mode explicitly.
	if err := os.Chmod(dstPath, placementMode(src)); err != nil {
		return err
	}
	return lchownFromInfo(dstPath, src)
}

// isCrossDeviceLinkError reports whether a link() failure was caused by the
// source and destination living on different filesystems, or by a filesystem
// that has no hard links at all. Both are ordinary situations when a package
// writes below a nested mount, and neither should abort the placement.
func isCrossDeviceLinkError(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EOPNOTSUPP)
}

// copyFilePreservingMetadata places a single entry by copying its contents,
// used when the destination cannot be hard linked to.
func copyFilePreservingMetadata(srcPath, dstPath string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		// Devices, fifos and sockets carry no contents to copy, so recreate the
		// node itself. A filesystem that refused the link often cannot hold one
		// of these either, so a failure here is reported rather than ignored.
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read device numbers for %s", srcPath)
		}
		return replaceAtomically(dstPath, func(tmp string) error {
			if err := syscall.Mknod(tmp, uint32(st.Mode), int(st.Rdev)); err != nil {
				return err
			}
			return lchownFromInfo(tmp, info)
		})
	}
	return replaceAtomically(dstPath, func(tmp string) error {
		in, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		// Ownership and timestamps are best effort: a vfat destination cannot
		// represent either, and failing there would be worse than losing them.
		_ = lchownFromInfo(tmp, info)
		atime, mtime := fileTimes(info)
		_ = os.Chtimes(tmp, atime, mtime)
		return nil
	})
}

// replaceAtomically builds the new entry beside dstPath and renames it over the
// destination, so dstPath is never observed half-installed.
func replaceAtomically(dstPath string, create func(tmp string) error) error {
	dir := filepath.Dir(dstPath)
	base := filepath.Base(dstPath)
	// A component may not exceed NAME_MAX, so leave room for the suffix.
	if max := 255 - len(placementTmpSuffix); len(base) > max {
		base = base[:max]
	}
	tmp := filepath.Join(dir, base+placementTmpSuffix)

	// Clear a leftover from an interrupted install.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := create(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// placementMode returns the permission bits to apply, including setuid, setgid
// and the sticky bit.
func placementMode(info fs.FileInfo) os.FileMode {
	return info.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
}

// lchownFromInfo copies ownership from info onto path without following a
// symlink. Lack of privilege is not fatal: an unprivileged install simply keeps
// the invoking user as the owner, which is what the rsync path does too.
func lchownFromInfo(path string, info fs.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Lchown(path, int(st.Uid), int(st.Gid)); err != nil {
		if errors.Is(err, syscall.EPERM) && os.Geteuid() != 0 {
			return nil
		}
		return err
	}
	return nil
}

// fileTimes extracts the access and modification times recorded for info.
func fileTimes(info fs.FileInfo) (atime, mtime time.Time) {
	mtime = info.ModTime()
	atime = mtime
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		atime = time.Unix(st.Atim.Sec, st.Atim.Nsec)
	}
	return atime, mtime
}
