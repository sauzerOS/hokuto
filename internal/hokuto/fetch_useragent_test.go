package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplySourceForgeDirect(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.xz",
			"https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.xz/download",
		},
		{ // already direct: left alone
			"https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.xz/download",
			"https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.xz/download",
		},
		{ // query string: packager knows best, left alone
			"https://sourceforge.net/projects/x/files/y.tar.gz?use_mirror=auto",
			"https://sourceforge.net/projects/x/files/y.tar.gz?use_mirror=auto",
		},
		{ // the mirror host is already a direct endpoint
			"https://downloads.sourceforge.net/project/libpng/libpng16/1.6.58/libpng-1.6.58.tar.xz",
			"https://downloads.sourceforge.net/project/libpng/libpng16/1.6.58/libpng-1.6.58.tar.xz",
		},
		{ // unrelated hosts untouched
			"https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz",
			"https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz",
		},
	}
	for _, c := range cases {
		if got := applySourceForgeDirect(c.in); got != c.want {
			t.Errorf("applySourceForgeDirect(%q)\n got  %q\n want %q", c.in, got, c.want)
		}
	}
}

// TestNativeDownloadHandlesBotChecks exercises the native HTTP path alone
// (NativeOnly disables the wget fallback) against hosts that are picky about
// who is asking. SourceForge serves an HTML interstitial to non-browser agents
// and 403s browser ones; ftp.gnu.org rejects a request with no User-Agent.
func TestNativeDownloadHandlesBotChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	cases := []struct{ name, url string }{
		{"sourceforge", "https://sourceforge.net/projects/libpng/files/libpng16/1.6.58/libpng-1.6.58.tar.xz"},
		{"gnu", "https://ftp.gnu.org/gnu/grep/grep-3.12.tar.xz"},
		{"github", "https://github.com/scop/bash-completion/releases/download/2.16.0/bash-completion-2.16.0.tar.xz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "out.tar.xz")
			url := rewriteSourceURL(tc.url)
			if err := downloadFileWithOptions(tc.url, url, dest, downloadOptions{
				Quiet: true, Force: true, NativeOnly: true,
			}); err != nil {
				// A slow mirror trips hokuto's minimum-throughput guard. That is a
				// property of the network at the time, not of the code under test,
				// so it must not be reported as a failure.
				if strings.Contains(err.Error(), "download stalled") {
					t.Skipf("mirror too slow to judge: %v", err)
				}
				t.Fatalf("native download failed: %v", err)
			}
			fi, err := os.Stat(dest)
			if err != nil {
				t.Fatalf("no file written: %v", err)
			}
			if fi.Size() < 100*1024 {
				t.Fatalf("suspiciously small (%d bytes) - likely a bot-check page", fi.Size())
			}
			t.Logf("%s: %d bytes via native client", tc.name, fi.Size())
		})
	}
}
