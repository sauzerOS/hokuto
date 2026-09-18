package hokuto

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SourceForge answers the same download URL two different ways depending on
// whether a Referer is present: with one it serves the "your download will
// start shortly" HTML page, without one it serves the 302 to the CDN holding
// the file. Go attaches a Referer on every redirect it follows, so the client
// has to strip it or every SourceForge source downloads as a web page.
func TestDownloadClientDropsRefererOnRedirect(t *testing.T) {
	var sawReferer string
	var reachedFinal bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			reachedFinal = true
			sawReferer = r.Header.Get("Referer")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("payload"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := newHttpClient()
	if err != nil {
		t.Fatalf("newHttpClient: %v", err)
	}
	req, err := http.NewRequest("GET", srv.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", downloadUserAgents[0])
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if !reachedFinal {
		t.Fatal("redirect was not followed")
	}
	if sawReferer != "" {
		t.Fatalf("redirected request carried Referer %q; SourceForge serves an HTML interstitial when it sees one", sawReferer)
	}
}

// The User-Agent must still survive the redirect: some mirrors return HTML
// instead of the file when it goes missing.
func TestDownloadClientKeepsUserAgentOnRedirect(t *testing.T) {
	var sawUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		sawUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	client, err := newHttpClient()
	if err != nil {
		t.Fatalf("newHttpClient: %v", err)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/start", nil)
	req.Header.Set("User-Agent", downloadUserAgents[0])
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if sawUA != downloadUserAgents[0] {
		t.Fatalf("User-Agent after redirect = %q, want %q", sawUA, downloadUserAgents[0])
	}
}
