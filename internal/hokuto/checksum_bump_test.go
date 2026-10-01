package hokuto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A version bump re-downloads the source, so its hash will not match the one
// recorded for the previous release. That is expected, not suspicious, and it
// must not stop to ask -- see checksumAdoptDownloaded.
//
// It only shows up when the filename carries no version ("source.tar.gz" from
// an untagged release); a versioned filename has no recorded checksum at all
// and never reaches the mismatch branch.
func TestChecksumAdoptDownloadedSkipsMismatchPrompt(t *testing.T) {
	pkgDir := t.TempDir()

	origSourcesDir := SourcesDir
	SourcesDir = t.TempDir()
	t.Cleanup(func() { SourcesDir = origSourcesDir })

	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("version", "0.12.17 1\n")
	write("sources", "https://example.invalid/uv/source.tar.gz\n")
	// A checksum left over from the previous release.
	write("checksums", "0000000000000000000000000000000000000000000000000000000000000000  source.tar.gz\n")

	// The file fetchSources just downloaded for the new version.
	srcDir := filepath.Join(SourcesDir, "uv")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	downloaded := filepath.Join(srcDir, "source.tar.gz")
	if err := os.WriteFile(downloaded, []byte("contents of the 0.12.17 tarball"), 0o644); err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	if err := verifyOrCreateChecksumsWithPolicy("uv", pkgDir, false, checksumAdoptDownloaded, &log); err != nil {
		t.Fatalf("verifyOrCreateChecksumsWithPolicy: %v", err)
	}

	if got := log.String(); !strings.Contains(got, "Updated (version bump)") {
		t.Errorf("expected the bump path to report adopting the download, got:\n%s", got)
	}

	want, err := ComputeChecksum(downloaded, UserExec)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(filepath.Join(pkgDir, "checksums"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(recorded), want+"  source.tar.gz") {
		t.Errorf("checksums file did not take the downloaded file's hash %s:\n%s", want, recorded)
	}
	if strings.Contains(string(recorded), "0000000000000000") {
		t.Errorf("stale checksum from the previous release survived:\n%s", recorded)
	}
}

// "nochecksum" marks a source whose upstream file changes in place (a "latest"
// release asset). It is never verified, so a fresh download never prompts,
// and it gets no line in the checksums file.
func TestNochecksumSourceIsNotVerified(t *testing.T) {
	pkgDir := t.TempDir()
	origSourcesDir := SourcesDir
	SourcesDir = t.TempDir()
	t.Cleanup(func() { SourcesDir = origSourcesDir })

	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	srcDir := filepath.Join(SourcesDir, "duckstation")
	write(filepath.Join(pkgDir, "version"), "0.1-11826 2\n")
	write(filepath.Join(pkgDir, "sources"), "https://example.invalid/latest/cheats.zip noextract nochecksum\n"+
		"https://example.invalid/latest/patches.zip -> extra.zip nochecksum\n"+
		"https://example.invalid/libpng.patch\n")
	write(filepath.Join(srcDir, "cheats.zip"), "today's cheats")
	write(filepath.Join(srcDir, "extra.zip"), "today's patches")
	write(filepath.Join(srcDir, "libpng.patch"), "patch")
	patchSum, err := ComputeChecksum(filepath.Join(srcDir, "libpng.patch"), UserExec)
	if err != nil {
		t.Fatal(err)
	}
	// Stale sums for the unchecked files: verifying them would prompt.
	write(filepath.Join(pkgDir, "checksums"), "0000  cheats.zip\n0000  extra.zip\n"+patchSum+"  libpng.patch\n")

	var log bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- verifyOrCreateChecksums("duckstation", pkgDir, false, &log) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("verification stopped at a prompt for a nochecksum source")
	}

	recorded, err := os.ReadFile(filepath.Join(pkgDir, "checksums"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(recorded); got != patchSum+"  libpng.patch\n" {
		t.Fatalf("checksums should only list the verified source, got:\n%s", got)
	}
	for _, want := range []string{"cheats.zip: skipped (nochecksum)", "extra.zip: skipped (nochecksum)", "libpng.patch: ok"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("summary is missing %q:\n%s", want, log.String())
		}
	}
}
