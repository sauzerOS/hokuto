package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// As pacman does before a transaction: an install or update that does not
// fit is refused before anything is downloaded, instead of failing on a
// full disk halfway through (possibly in the middle of glibc or gcc).

// freeSpaceMargin is kept free on top of what a plan needs: the package
// databases, logs and staging of the package being placed also take room.
const freeSpaceMargin = 32 << 20

// freeSpaceOf reports the filesystem holding path (its device) and the
// bytes available to it. A variable so tests can stand in for statfs.
var freeSpaceOf = func(path string) (uint64, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("no device for %s", path)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), int64(fs.Bavail) * int64(fs.Bsize), nil
}

// existingParent is path, or its nearest existing parent directory.
func existingParent(path string) string {
	for {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}

// checkFreeSpace reports whether download bytes fit in the binary cache and
// grow bytes (what installing adds; 0 or less when an update shrinks) fit in
// the target root, counting both against one filesystem when they share it.
// The root is checked at /usr, where nearly all package files go. When free
// space cannot be read, nothing is refused.
func checkFreeSpace(download, grow int64) error {
	type need struct {
		path  string
		bytes int64
		avail int64
	}
	byDevice := make(map[uint64]*need)
	var order []uint64
	add := func(path string, bytes int64) {
		if bytes <= 0 {
			return
		}
		path = existingParent(path)
		dev, avail, err := freeSpaceOf(path)
		if err != nil {
			debugf("free space check: %s: %v\n", path, err)
			return
		}
		if n, ok := byDevice[dev]; ok {
			n.bytes += bytes
			return
		}
		byDevice[dev] = &need{path: path, bytes: bytes, avail: avail}
		order = append(order, dev)
	}
	add(BinDir, download)
	add(filepath.Join(rootDir, "usr"), grow)

	var problems []string
	for _, dev := range order {
		n := byDevice[dev]
		if n.avail < n.bytes+freeSpaceMargin {
			problems = append(problems, fmt.Sprintf("%s needs %s, %s free", n.path, humanReadableSize(n.bytes), humanReadableSize(n.avail)))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("not enough free space: %s", strings.Join(problems, "; "))
	}
	return nil
}

// reportFreeSpace prints a checkFreeSpace refusal and reports whether the
// plan fits.
func reportFreeSpace(download, grow int64) bool {
	err := checkFreeSpace(download, grow)
	if err == nil {
		return true
	}
	colArrow.Print("-> ")
	colError.Print("ERROR: ")
	colSuccess.Println(err)
	return false
}
