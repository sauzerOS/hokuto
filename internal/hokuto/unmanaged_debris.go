package hokuto

// Debris among files that belong to no package.
//
// An existing file no package owns is normally kept as an "unmanaged"
// alternative when a package installs over it: it may be something the user
// put there. A power cut in the build container left a whole python and
// tzdata tree of empty files behind; every install of python stashed them,
// every uninstall put them back, and the container never got rid of them. A
// file that is empty, or identical to the one the package installs, holds
// nothing to keep, so the package simply takes it over.

import (
	"bytes"
	"io"
	"os"
)

// unmanagedFileIsDebris reports whether targetFile, which no package owns,
// can be replaced by incomingFile without losing anything: it is an empty
// regular file, or the same symlink or the same contents as incomingFile.
func unmanagedFileIsDebris(targetFile, incomingFile string) bool {
	target, err := os.Lstat(targetFile)
	if err != nil {
		return false
	}
	incoming, err := os.Lstat(incomingFile)
	if err != nil || incoming.IsDir() {
		return false
	}
	switch {
	case target.Mode().IsRegular() && target.Size() == 0:
		return true
	case target.Mode()&os.ModeSymlink != 0 && incoming.Mode()&os.ModeSymlink != 0:
		a, errA := os.Readlink(targetFile)
		b, errB := os.Readlink(incomingFile)
		return errA == nil && errB == nil && a == b
	case target.Mode().IsRegular() && incoming.Mode().IsRegular():
		return target.Size() == incoming.Size() && sameFileContents(targetFile, incomingFile)
	}
	return false
}

// sameFileContents compares two files byte for byte.
func sameFileContents(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()

	bufA := make([]byte, 64*1024)
	bufB := make([]byte, 64*1024)
	for {
		na, errA := io.ReadFull(fa, bufA)
		nb, errB := io.ReadFull(fb, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false
		}
		endA := errA == io.EOF || errA == io.ErrUnexpectedEOF
		endB := errB == io.EOF || errB == io.ErrUnexpectedEOF
		if endA || endB {
			return endA && endB
		}
		if errA != nil || errB != nil {
			return false
		}
	}
}

// forgetUnmanagedAlternatives drops the alternatives entries of paths whose
// every alternative belongs to "unmanaged" alone: what an earlier install
// recorded for debris that a package now takes over. Left in place, they would
// keep uninstall from removing the file.
func forgetUnmanagedAlternatives(hRoot string, paths []string, execCtx *Executor) error {
	if len(paths) == 0 {
		return nil
	}
	db, err := loadAlternativesDB(hRoot)
	if err != nil {
		return err
	}
	modified := false
	for _, p := range paths {
		key := canonicalizePath(hRoot, p)
		entry := db.Files[key]
		if entry == nil {
			continue
		}
		onlyUnmanaged := true
		for _, alt := range entry.Alternatives {
			if len(alt.Owners) != 1 || alt.Owners[0] != "unmanaged" {
				onlyUnmanaged = false
				break
			}
		}
		if onlyUnmanaged {
			delete(db.Files, key)
			modified = true
		}
	}
	if !modified {
		return nil
	}
	return saveAlternativesDB(hRoot, db, execCtx)
}
