package hokuto

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// The transaction log, as pacman keeps /var/log/pacman.log: one line per
// package installed, upgraded, downgraded, reinstalled or removed, so
// "what changed before this broke?" has an answer.
//
//	[2026-10-06T14:02:11+0200] [HOKUTO] upgraded glibc (2.44-1 -> 2.44-2)
//
// The log is zstd-compressed (/var/log/hokuto.log.zst; read it with zstdcat
// or zstdless). Lines are queued and appended as one frame every few
// seconds and when hokuto exits: a frame per line would compress poorly,
// and a normal user installing through sudo needs a sudo process per
// append. Every MiB the frames are recompressed into one.

// transactionLogFlushInterval is how long queued lines wait for a
// privileged append.
const transactionLogFlushInterval = 5 * time.Second

var transactionLog struct {
	mu        sync.Mutex
	pending   []string
	lastFlush time.Time
}

func transactionLogPath() string {
	return filepath.Join(rootDir, "/var/log/hokuto.log.zst")
}

// installedRelease is the installed "version-revision" of pkgName.
func installedRelease(pkgName string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(Installed, pkgName, "version"))
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(data))
	switch len(fields) {
	case 0:
		return "", false
	case 1:
		return fields[0], true
	default:
		return fields[0] + "-" + fields[1], true
	}
}

// logPackageInstall records the install of pkgName, which was oldRelease
// before (wasInstalled), as installed, upgraded, downgraded or reinstalled.
func logPackageInstall(pkgName, oldRelease string, wasInstalled bool) {
	newRelease, ok := installedRelease(pkgName)
	if !ok {
		newRelease = "unknown"
	}
	switch {
	case !wasInstalled:
		logTransaction("installed %s (%s)", pkgName, newRelease)
	case oldRelease == newRelease:
		logTransaction("reinstalled %s (%s)", pkgName, newRelease)
	case compareReleases(newRelease, oldRelease) < 0:
		logTransaction("downgraded %s (%s -> %s)", pkgName, oldRelease, newRelease)
	default:
		logTransaction("upgraded %s (%s -> %s)", pkgName, oldRelease, newRelease)
	}
}

// compareReleases orders two "version-revision" strings.
func compareReleases(a, b string) int {
	av, ar := splitRelease(a)
	bv, br := splitRelease(b)
	if c := compareVersions(av, bv); c != 0 {
		return c
	}
	return compareVersions(ar, br)
}

func splitRelease(release string) (string, string) {
	if dash := strings.LastIndex(release, "-"); dash != -1 && isNumericVersionLine(release[dash+1:]) {
		return release[:dash], release[dash+1:]
	}
	return release, "0"
}

func logTransaction(format string, args ...any) {
	line := fmt.Sprintf("[%s] [HOKUTO] %s\n", time.Now().Format("2006-01-02T15:04:05-0700"), fmt.Sprintf(format, args...))
	transactionLog.mu.Lock()
	defer transactionLog.mu.Unlock()
	transactionLog.pending = append(transactionLog.pending, line)
	if transactionLog.lastFlush.IsZero() {
		transactionLog.lastFlush = time.Now()
		return
	}
	if time.Since(transactionLog.lastFlush) >= transactionLogFlushInterval {
		flushTransactionLogLocked()
	}
}

// flushTransactionLog appends every queued line; hokuto calls it on exit.
func flushTransactionLog() {
	transactionLog.mu.Lock()
	defer transactionLog.mu.Unlock()
	flushTransactionLogLocked()
}

// transactionLogCompactEvery: each time the log grows past another multiple
// of it, the many small frames are recompressed into one.
var transactionLogCompactEvery int64 = 1 << 20

// flushTransactionLogLocked appends the queued lines to the log as one zstd
// frame (a file of concatenated frames is what zstdcat reads as one), or,
// when the log crosses a compaction boundary, rewrites it as a single frame.
// Called with transactionLog.mu held; a failure keeps the lines queued.
func flushTransactionLogLocked() {
	transactionLog.lastFlush = time.Now()
	if len(transactionLog.pending) == 0 {
		return
	}
	// Another hokuto may be appending or compacting.
	defer lockInstalledState()()

	text := []byte(strings.Join(transactionLog.pending, ""))
	path := transactionLogPath()
	content := zstdCompressLog(text, false)
	replace := false
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		oldSize := info.Size()
		if oldSize/transactionLogCompactEvery != (oldSize+int64(len(content)))/transactionLogCompactEvery {
			if old, err := os.ReadFile(path); err == nil {
				if decoded, err := zstdDecompressLog(old); err == nil {
					content = zstdCompressLog(append(decoded, text...), true)
					replace = true
				}
			}
		}
	}

	if err := writeTransactionLog(path, content, replace); err != nil {
		debugf("transaction log: %v\n", err)
		return
	}
	transactionLog.pending = nil
}

// zstdCompressLog compresses text into one frame; best is for compaction,
// worth its setup cost only on the whole log.
func zstdCompressLog(text []byte, best bool) []byte {
	level := zstd.SpeedDefault
	if best {
		level = zstd.SpeedBestCompression
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(level), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil
	}
	defer enc.Close()
	return enc.EncodeAll(text, nil)
}

func zstdDecompressLog(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(data, nil)
}

// writeTransactionLog appends content to the log, or replaces the log with
// it, directly when this process may write there (root, a run0 session, a
// HOKUTO_ROOT owned by the user) and through RootExec otherwise.
func writeTransactionLog(path string, content []byte, replace bool) error {
	if len(content) == 0 {
		return fmt.Errorf("nothing to write")
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if replace {
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, content, 0o644); err == nil {
			if err := os.Rename(tmp, path); err == nil {
				return nil
			}
			os.Remove(tmp)
		}
	} else if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		_, werr := f.Write(content)
		cerr := f.Close()
		if werr != nil {
			return werr
		}
		return cerr
	}

	if RootExec == nil {
		return fmt.Errorf("cannot write %s", path)
	}
	script := `mkdir -p "$(dirname "$1")" && cat >> "$1"`
	if replace {
		script = `cat > "$1.tmp" && chmod 644 "$1.tmp" && mv -f "$1.tmp" "$1"`
	}
	cmd := exec.Command("sh", "-c", script, "sh", path)
	cmd.Stdin = bytes.NewReader(content)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return RootExec.Run(cmd)
}
