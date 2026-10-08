package hokuto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRevisionBumpLine(t *testing.T) {
	for _, tc := range []struct{ bumped, note, want string }{
		{"1.5.4 3", "links libdav1d.so.7", "dav1d: 1.5.4: 2 → 3 (links libdav1d.so.7)"},
		{"1.5.4 3", "", "dav1d: 1.5.4: 2 → 3"},
		{"1.5.4", "", "dav1d: 1.5.4"},
	} {
		if got := revisionBumpLine("dav1d", tc.bumped, tc.note); got != tc.want {
			t.Errorf("revisionBumpLine(%q, %q) = %q, want %q", tc.bumped, tc.note, got, tc.want)
		}
	}
}

// The prepare-commit-msg hook of hokuto init-repos puts version lines in front
// of a message; a rebuild's reason must stay the subject.
func TestCommitRevisionBumpsKeepsTheReasonAsSubject(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@t"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	git("init", "-q")
	version := filepath.Join(repo, "extra", "dav1d", "version")
	if err := os.MkdirAll(filepath.Dir(version), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(version, []byte("1.5.4 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	hook, err := embeddedAssets.ReadFile("assets/git-hook-prepare-commit-msg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "hooks", "prepare-commit-msg"), hook, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(version, []byte("1.5.4 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@t")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@t")
	subject := "rebuild for dav1d (libdav1d.so.7) ABI change"
	line := revisionBumpLine("dav1d", "1.5.4 3", "links libdav1d.so.7")
	if err := commitRevisionBumps(repo, subject, []string{line}, []string{version}); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(git("log", "-1", "--format=%B"))
	want := subject + "\n\n" + line
	if got != want {
		t.Fatalf("commit message:\n%s\nwant:\n%s", got, want)
	}
}
