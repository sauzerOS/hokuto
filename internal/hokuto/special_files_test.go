package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// withTimeout runs fn and fails instead of hanging when it blocks, which is
// what a FIFO being opened for hashing used to do.
func withTimeout(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("blocked: a special file was opened for hashing")
	}
}

func TestGenerateManifestHandlesFIFO(t *testing.T) {
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(out, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(out, "run", "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, "run", "file"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(out, "var", "db", "hokuto", "installed", "demo")

	withTimeout(t, func() {
		if err := generateManifest(out, installed, &Executor{Context: context.Background()}); err != nil {
			t.Errorf("generateManifest: %v", err)
		}
	})

	data, err := os.ReadFile(filepath.Join(installed, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(data)
	if !strings.Contains(manifest, "/run/pipe 000000\n") {
		t.Errorf("FIFO must be listed with the placeholder checksum:\n%s", manifest)
	}
	if !strings.Contains(manifest, "/run/file  ") || strings.Contains(manifest, "/run/file  000000") {
		t.Errorf("regular file must still be hashed:\n%s", manifest)
	}
}

func TestComputeChecksumRejectsFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	withTimeout(t, func() {
		if _, err := ComputeChecksum(fifo, nil); err == nil {
			t.Error("hashing a FIFO must fail, not succeed")
		}
	})
}
