package hokuto

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// withMirrorAuthTest serves a mirror that wants user "dbz", password "s3cret",
// and points BinaryMirror and the target root at it.
func withMirrorAuthTest(t *testing.T) (root string, sawAuth func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "dbz" || p != "s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("index"))
	}))
	t.Cleanup(srv.Close)

	root = t.TempDir()
	oldMirror, oldRoot := BinaryMirror, rootDir
	BinaryMirror = srv.URL + "/sauzeros"
	rootDir = root
	mirrorAuth.Lock()
	mirrorAuth.user, mirrorAuth.pass, mirrorAuth.loaded, mirrorAuth.prompts, mirrorAuth.unsaved = "", "", false, 0, false
	mirrorAuth.Unlock()
	t.Cleanup(func() {
		BinaryMirror, rootDir = oldMirror, oldRoot
		mirrorAuth.Lock()
		mirrorAuth.user, mirrorAuth.pass, mirrorAuth.loaded, mirrorAuth.prompts, mirrorAuth.unsaved = "", "", false, 0, false
		mirrorAuth.Unlock()
	})
	return root, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func fetchFromMirror(t *testing.T, name string) error {
	t.Helper()
	u := BinaryMirror + "/" + name
	return downloadFileWithOptions(u, u, filepath.Join(t.TempDir(), name), downloadOptions{Quiet: true, NativeAttempts: 1, NativeOnly: true})
}

func TestMirrorDownloadUsesSavedLogin(t *testing.T) {
	root, _ := withMirrorAuthTest(t)
	path := filepath.Join(root, mirrorAuthRelPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("dbz:s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fetchFromMirror(t, "repo-index.json"); err != nil {
		t.Fatalf("download with the saved login: %v", err)
	}
}

func TestMirrorDownloadWithoutLoginAndTerminalExplains(t *testing.T) {
	withMirrorAuthTest(t)
	err := fetchFromMirror(t, "repo-index.json")
	if err == nil || !strings.Contains(err.Error(), "requires a login") || !strings.Contains(err.Error(), mirrorAuthRelPath) {
		t.Fatalf("expected the mirror login error, got %v", err)
	}
}

func TestMirrorLoginEnteredInThisRunIsSavedAfterSuccess(t *testing.T) {
	root, _ := withMirrorAuthTest(t)
	// What promptMirrorLogin leaves behind once the user typed the login.
	mirrorAuth.Lock()
	mirrorAuth.user, mirrorAuth.pass, mirrorAuth.loaded, mirrorAuth.unsaved = "dbz", "s3cret", true, true
	mirrorAuth.Unlock()

	if err := fetchFromMirror(t, "repo-index.json"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, mirrorAuthRelPath)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "dbz:s3cret\n" {
		t.Fatalf("login not saved to the target root: %q %v", data, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("mirror-auth mode %v, want 0644", info.Mode().Perm())
	}
}

func TestMirrorLoginNotSentElsewhere(t *testing.T) {
	_, _ = withMirrorAuthTest(t)
	mirrorAuth.Lock()
	mirrorAuth.user, mirrorAuth.pass, mirrorAuth.loaded = "dbz", "s3cret", true
	mirrorAuth.Unlock()

	var got string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte("source"))
	}))
	defer other.Close()
	u := other.URL + "/foo-1.0.tar.gz"
	if err := downloadFileWithOptions(u, u, filepath.Join(t.TempDir(), "foo"), downloadOptions{Quiet: true, NativeAttempts: 1, NativeOnly: true}); err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("the mirror login leaked to another server: %q", got)
	}
}
