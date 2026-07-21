package hokuto

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
)

func TestNewHttpClientDoesNotSetGlobalTimeout(t *testing.T) {
	client, err := newHttpClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.Timeout != 0 {
		t.Fatalf("download client should not use a global timeout, got %s", client.Timeout)
	}
}

func TestThroughputTimeoutReaderAllowsCompletedTransfer(t *testing.T) {
	canceled := false
	reader := newThroughputTimeoutReader(
		io.NopCloser(strings.NewReader("complete")),
		20*time.Millisecond,
		minDownloadBytesForWindow(100, 20*time.Millisecond),
		func() { canceled = true },
	)

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if string(data) != "complete" {
		t.Fatalf("unexpected data: %q", data)
	}
	if canceled {
		t.Fatal("reader canceled a completed transfer")
	}
	if err := reader.Err(); err != nil {
		t.Fatalf("unexpected stall error: %v", err)
	}
}

func TestThroughputTimeoutReaderCancelsSlowTransfer(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	canceled := make(chan struct{})
	reader := newThroughputTimeoutReader(
		pr,
		20*time.Millisecond,
		minDownloadBytesForWindow(100, 20*time.Millisecond),
		func() {
			close(canceled)
			_ = pw.CloseWithError(context.Canceled)
		},
	)

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, reader)
		done <- err
	}()

	if _, err := pw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("reader did not cancel slow transfer")
	}
	if err := <-done; err == nil {
		t.Fatal("expected copy error after slow transfer cancellation")
	}
	if err := reader.Err(); err == nil {
		t.Fatal("expected stall error")
	}
}

func TestGoGitRefCandidatesIncludeTagForRawVersionRef(t *testing.T) {
	candidates := goGitRefCandidates("v10.0.5")

	found := false
	for _, candidate := range candidates {
		if candidate.revision.String() == "refs/tags/v10.0.5" &&
			candidate.remote.String() == "refs/tags/v10.0.5" &&
			candidate.local.String() == "refs/tags/v10.0.5" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected raw version ref to include tag candidate, got %#v", candidates)
	}
}

func TestGoGitRefCandidatesSupportTagPrefix(t *testing.T) {
	candidates := goGitRefCandidates("tag=v10.0.5")
	if len(candidates) != 1 {
		t.Fatalf("expected one tag candidate, got %#v", candidates)
	}
	if candidates[0].revision.String() != "refs/tags/v10.0.5" {
		t.Fatalf("unexpected tag revision candidate: %#v", candidates[0])
	}
}

func TestMatchGoGitSuffixTagRef(t *testing.T) {
	refs := []*plumbing.Reference{
		plumbing.NewHashReference("refs/tags/setuptools-scm-v10.0.5", plumbing.NewHash("1111111111111111111111111111111111111111")),
		plumbing.NewHashReference("refs/tags/vcs-versioning-v1.1.0", plumbing.NewHash("2222222222222222222222222222222222222222")),
	}

	got, err := matchGoGitSuffixTagRef("v10.0.5", refs)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "refs/tags/setuptools-scm-v10.0.5" {
		t.Fatalf("unexpected suffix tag match: %s", got)
	}
}

func TestMatchGoGitSuffixTagRefRejectsAmbiguousTags(t *testing.T) {
	refs := []*plumbing.Reference{
		plumbing.NewHashReference("refs/tags/foo-v10.0.5", plumbing.NewHash("1111111111111111111111111111111111111111")),
		plumbing.NewHashReference("refs/tags/bar-v10.0.5", plumbing.NewHash("2222222222222222222222222222222222222222")),
	}

	if _, err := matchGoGitSuffixTagRef("v10.0.5", refs); err == nil {
		t.Fatal("expected ambiguous suffix tag match to fail")
	}
}

func TestGoGitArchivalDescribeNameUsesParseableDescribeShape(t *testing.T) {
	hash := plumbing.NewHash("fa1c6e29dce8f490d34cdf69b87e730dc11d6077")
	got := goGitArchivalDescribeName("setuptools-scm-v10.0.5", hash)
	want := "setuptools-scm-v10.0.5-0-gfa1c6e2"
	if got != want {
		t.Fatalf("unexpected archival describe-name: got %q want %q", got, want)
	}
}

func TestDownloadFilePublishesFinalPathAtomically(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial-"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(started)
		<-release
		_, _ = w.Write([]byte("complete"))
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "source.tar.xz")
	done := make(chan error, 1)
	go func() {
		done <- downloadFileWithOptions(server.URL+"/source.tar.xz", server.URL+"/source.tar.xz", dest, downloadOptions{Quiet: true})
	}()

	<-started
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		close(release)
		t.Fatalf("final download path should not exist before publish, stat err: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "partial-complete" {
		t.Fatalf("unexpected downloaded content: %q", data)
	}
	if _, err := os.Stat(dest + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("download lock should be removed after publish, stat err: %v", err)
	}
}

func TestDownloadRefusesLockDestination(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "pkg.tar.zst.lock")
	if err := downloadFileWithOptions("http://127.0.0.1/pkg.tar.zst", "http://127.0.0.1/pkg.tar.zst", dest, downloadOptions{Quiet: true}); err == nil {
		t.Fatal("expected lock destination to be rejected")
	}
}

func TestDownloadAllowsSourceNamedLock(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Cargo.lock" {
			t.Fatalf("unexpected request path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("cargo lock payload"))
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "df0609ec84e383cf60d8c2f63f3700b0219a3a6e66929ae2527746be9cf23ea4-Cargo.lock")
	if err := downloadFileWithOptions(server.URL+"/Cargo.lock", server.URL+"/Cargo.lock", dest, downloadOptions{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "cargo lock payload" {
		t.Fatalf("unexpected downloaded content: %q", data)
	}
	if _, err := os.Stat(dest + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("download lock should be removed after publish, stat err: %v", err)
	}
}

func TestDownloadViaWgetCanDisableCertificateCheck(t *testing.T) {
	tmp := t.TempDir()
	wgetPath := filepath.Join(tmp, "wget")
	argsPath := filepath.Join(tmp, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HOKUTO_TEST_WGET_ARGS\"\n: > \"$2\"\n"
	if err := os.WriteFile(wgetPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+oldPath)
	t.Setenv("HOKUTO_TEST_WGET_ARGS", argsPath)

	dest := filepath.Join(tmp, "download")
	if err := downloadViaWget("https://example.invalid/source.tar.xz", dest, true, true); err != nil {
		t.Fatal(err)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--no-check-certificate\n") {
		t.Fatalf("expected wget args to include --no-check-certificate, got %q", string(args))
	}
}

func TestSharedDownloadLocksWaitForExclusiveDownloader(t *testing.T) {
	lockBase := filepath.Join(t.TempDir(), "source.tar.xz")
	release := make(chan struct{})
	exclusiveStarted := make(chan struct{})
	exclusiveDone := make(chan error, 1)

	go func() {
		exclusiveDone <- withExclusiveDownloadLock(lockBase, func() error {
			close(exclusiveStarted)
			<-release
			return nil
		})
	}()
	<-exclusiveStarted

	sharedDone := make(chan error, 1)
	go func() {
		sharedDone <- withSharedDownloadLocks([]string{lockBase}, func() error {
			return nil
		})
	}()

	select {
	case err := <-sharedDone:
		close(release)
		t.Fatalf("shared lock should wait for exclusive lock, got err: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	if err := <-exclusiveDone; err != nil {
		t.Fatal(err)
	}
	if err := <-sharedDone; err != nil {
		t.Fatal(err)
	}
}
