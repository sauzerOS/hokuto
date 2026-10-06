package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTransactionLogRoot(t *testing.T) string {
	t.Helper()
	oldRoot, oldInstalled, oldCompact := rootDir, Installed, transactionLogCompactEvery
	rootDir = t.TempDir()
	Installed = filepath.Join(rootDir, "var/db/hokuto/installed")
	if err := os.MkdirAll(Installed, 0o755); err != nil {
		t.Fatal(err)
	}
	transactionLog.mu.Lock()
	transactionLog.pending, transactionLog.lastFlush = nil, time.Time{}
	transactionLog.mu.Unlock()
	t.Cleanup(func() {
		rootDir, Installed, transactionLogCompactEvery = oldRoot, oldInstalled, oldCompact
		transactionLog.mu.Lock()
		transactionLog.pending, transactionLog.lastFlush = nil, time.Time{}
		transactionLog.mu.Unlock()
	})
	return transactionLogPath()
}

func readTransactionLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text, err := zstdDecompressLog(data)
	if err != nil {
		t.Fatalf("log is not valid zstd: %v", err)
	}
	return string(text)
}

func TestTransactionLogRecordsReleasesCompressed(t *testing.T) {
	path := withTransactionLogRoot(t)
	setVersion := func(name, version string) {
		dir := filepath.Join(Installed, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "version"), []byte(version+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	setVersion("foo", "1.0 1")
	logPackageInstall("foo", "", false)
	setVersion("foo", "1.10 1")
	logPackageInstall("foo", "1.9-2", true)
	logPackageInstall("foo", "1.10-1", true)
	logPackageInstall("foo", "2.0-1", true)
	flushTransactionLog()
	logTransaction("removed foo (1.10-1)")
	flushTransactionLog()

	text := readTransactionLog(t, path)
	for _, want := range []string{
		"[HOKUTO] installed foo (1.0-1)",
		"[HOKUTO] upgraded foo (1.9-2 -> 1.10-1)",
		"[HOKUTO] reinstalled foo (1.10-1)",
		"[HOKUTO] downgraded foo (2.0-1 -> 1.10-1)",
		"[HOKUTO] removed foo (1.10-1)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "\n") != 5 {
		t.Errorf("want 5 lines, got:\n%s", text)
	}
}

func TestTransactionLogCompactsFrames(t *testing.T) {
	path := withTransactionLogRoot(t)
	transactionLogCompactEvery = 512
	for i := 0; i < 60; i++ {
		logTransaction("installed pkg%d (1.0-1)", i)
		flushTransactionLog()
	}
	text := readTransactionLog(t, path)
	if strings.Count(text, "\n") != 60 || !strings.Contains(text, "pkg0 ") || !strings.Contains(text, "pkg59 ") {
		t.Fatalf("lines lost by compaction:\n%s", text)
	}
	data, _ := os.ReadFile(path)
	// 60 separate frames would take far more than one compacted frame
	// plus the frames appended since.
	if len(data) > 1200 {
		t.Errorf("log was not compacted: %d bytes", len(data))
	}
}
