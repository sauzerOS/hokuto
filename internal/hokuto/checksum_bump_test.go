package hokuto

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
