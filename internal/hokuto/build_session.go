package hokuto

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func hokutoBuildSessionDir() string {
	root := rootDir
	if root == "" {
		root = "/"
	}
	sum := sha1.Sum([]byte(filepath.Clean(root)))
	return filepath.Join(os.TempDir(), "hokuto-build-sessions", hex.EncodeToString(sum[:8]))
}

func registerHokutoBuildSession() func() {
	sessionDir := hokutoBuildSessionDir()
	parent := filepath.Dir(sessionDir)
	if err := os.MkdirAll(parent, 0o777); err == nil {
		_ = os.Chmod(parent, 0o1777)
	}
	if err := os.MkdirAll(sessionDir, 0o777); err != nil {
		debugf("Warning: failed to create build session directory %s: %v\n", sessionDir, err)
		return func() {}
	}
	_ = os.Chmod(sessionDir, 0o1777)

	sessionPath := filepath.Join(sessionDir, fmt.Sprintf("%d-%d.session", os.Getpid(), time.Now().UnixNano()))
	content := fmt.Sprintf("pid=%d\nstarted=%s\nroot=%s\n", os.Getpid(), time.Now().Format(time.RFC3339), rootDir)
	if err := os.WriteFile(sessionPath, []byte(content), 0o644); err != nil {
		debugf("Warning: failed to create build session marker %s: %v\n", sessionPath, err)
		return func() {}
	}

	return func() {
		if err := os.Remove(sessionPath); err != nil && !os.IsNotExist(err) {
			debugf("Warning: failed to remove build session marker %s: %v\n", sessionPath, err)
		}
	}
}

func parseBuildSessionPID(name string) (int, bool) {
	pidText, _, ok := strings.Cut(name, "-")
	if !ok {
		pidText = strings.TrimSuffix(name, ".session")
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

func processIsAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func otherActiveHokutoBuildSessions() []int {
	entries, err := os.ReadDir(hokutoBuildSessionDir())
	if err != nil {
		return nil
	}

	currentPID := os.Getpid()
	var active []int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		pid, ok := parseBuildSessionPID(entry.Name())
		if !ok {
			continue
		}
		if !processIsAlive(pid) {
			_ = os.Remove(filepath.Join(hokutoBuildSessionDir(), entry.Name()))
			continue
		}
		if pid != currentPID {
			active = append(active, pid)
		}
	}
	return active
}

func joinPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, pid := range pids {
		parts = append(parts, strconv.Itoa(pid))
	}
	return strings.Join(parts, ", ")
}
