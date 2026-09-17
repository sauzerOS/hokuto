package hokuto

import "testing"

func TestArchReleaseTag(t *testing.T) {
	tests := []struct {
		name   string
		epoch  int
		pkgver string
		pkgrel string
		want   string
	}{
		// Arch spells the epoch with a trailing dash because a git ref cannot
		// contain a colon. zlib is the case that exposed this.
		{"epoch one", 1, "1.3.2", "3", "1-1.3.2-3"},
		{"epoch above one", 2, "4.5", "1", "2-4.5-1"},
		{"no epoch", 0, "5.3.15", "1", "5.3.15-1"},
		{"no epoch, dotted rel", 0, "3.12", "2", "3.12-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := archReleaseTag(tc.epoch, tc.pkgver, tc.pkgrel); got != tc.want {
				t.Errorf("archReleaseTag(%d, %q, %q) = %q, want %q", tc.epoch, tc.pkgver, tc.pkgrel, got, tc.want)
			}
		})
	}
}

func TestArchPackageFileURLAtRefUsesTheGivenRef(t *testing.T) {
	got, err := archPackageFileURLAtRef("zlib", "Arch", "PKGBUILD", "1-1.3.2-3")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://gitlab.archlinux.org/archlinux/packaging/packages/zlib/-/raw/1-1.3.2-3/PKGBUILD"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestArchPackageFileURLAtRefRejectsEscapingPaths(t *testing.T) {
	for _, bad := range []string{"../etc/passwd", "/etc/passwd", ".", ""} {
		if _, err := archPackageFileURLAtRef("zlib", "Arch", bad, "main"); err == nil {
			t.Errorf("path %q was accepted, want rejection", bad)
		}
	}
}

func TestExtractBashArraySkipsComments(t *testing.T) {
	// Arch groups long source arrays with comments. Every word of those used to
	// become a source, and the first of them ('#') was then fetched as a local
	// file, which is what broke importing electron44.
	pkgbuild := `
source=("git+https://github.com/electron/electron.git#tag=v$pkgver"
        # Chromium
        chromium-138-nodejs-version-check.patch
        trailing.patch  # explains the patch
        # BEGIN managed sources
        chromium-mirror::git+https://github.com/chromium/chromium.git#tag=152.0.7977.78
        nan::git+https://github.com/nodejs/nan.git#commit=675cefeb
        # END managed sources
)
`
	got := extractBashArray(pkgbuild, "source")
	want := []string{
		"git+https://github.com/electron/electron.git#tag=v$pkgver",
		"chromium-138-nodejs-version-check.patch",
		"trailing.patch",
		"chromium-mirror::git+https://github.com/chromium/chromium.git#tag=152.0.7977.78",
		"nan::git+https://github.com/nodejs/nan.git#commit=675cefeb",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sources %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("source %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractBashArrayKeepsHashInsideWords(t *testing.T) {
	// '#' is only a comment at the start of a word. Mid-word it is a URL
	// fragment, which is how every versioned git source is written.
	for _, tc := range []struct{ in, want string }{
		{"source=(git+https://e.org/x.git#tag=v1)", "git+https://e.org/x.git#tag=v1"},
		{"source=('git+https://e.org/x.git#commit=abc')", "git+https://e.org/x.git#commit=abc"},
		{`source=("https://e.org/a.tar.gz#fragment")`, "https://e.org/a.tar.gz#fragment"},
	} {
		got := extractBashArray(tc.in, "source")
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("extractBashArray(%q) = %v, want [%q]", tc.in, got, tc.want)
		}
	}
}

func TestExtractBashArrayCommentOnlyArrayIsEmpty(t *testing.T) {
	if got := extractBashArray("source=(\n  # nothing here\n)", "source"); len(got) != 0 {
		t.Errorf("got %v, want no sources", got)
	}
}
