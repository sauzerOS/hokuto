package hokuto

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gunzipFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s is not gzip: %v", path, err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// The site's package-index workflow pushes repo.json on its own. A build
// status published after it must rebase onto that commit instead of failing.
func TestUpdateWebsiteStatusRebasesOntoIndexCommits(t *testing.T) {
	tmp := t.TempDir()
	remote := filepath.Join(tmp, "remote.git")
	local := filepath.Join(tmp, "site")
	workflow := filepath.Join(tmp, "workflow")
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "master", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, dir := range []string{local, workflow} {
		if out, err := exec.Command("git", "clone", "-q", remote, dir).CombinedOutput(); err != nil {
			t.Fatalf("git clone: %v\n%s", err, out)
		}
		gitIn(t, dir, "config", "user.name", "Hokuto Test")
		gitIn(t, dir, "config", "user.email", "test@sauzeros.invalid")
	}
	if err := os.WriteFile(filepath.Join(local, "packages.json"), []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, local, "add", ".")
	gitIn(t, local, "commit", "-q", "-m", "initial")
	gitIn(t, local, "push", "-q", "origin", "master")

	// The workflow commits an index update the local checkout has not seen.
	gitIn(t, workflow, "pull", "-q", "origin", "master")
	if err := os.WriteFile(filepath.Join(workflow, "repo.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, workflow, "add", "repo.json")
	gitIn(t, workflow, "commit", "-q", "-m", "Update package index")
	gitIn(t, workflow, "push", "-q", "origin", "master")

	old := WebsiteRepo
	WebsiteRepo = local
	t.Cleanup(func() { WebsiteRepo = old })
	log := filepath.Join(tmp, "build.log")
	if err := os.WriteFile(log, []byte("build output\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateWebsiteStatus("imagemagick", "7.1.2-32-1", "success", log); err != nil {
		t.Fatalf("publishing after an index commit must succeed: %v", err)
	}

	subjects := gitIn(t, remote, "log", "--format=%s", "master")
	if !strings.Contains(subjects, "Update package index") || !strings.Contains(subjects, "Update status for imagemagick 7.1.2-32-1 (success)") {
		t.Fatalf("remote history is missing a commit:\n%s", subjects)
	}
	var status []PackageStatus
	if err := json.Unmarshal([]byte(gitIn(t, remote, "show", "master:packages.json")), &status); err != nil {
		t.Fatal(err)
	}
	if len(status) != 1 || status[0].Log != "logs/imagemagick-7.1.2-32-1.txt.gz" {
		t.Fatalf("unexpected published status %+v", status)
	}
	if built, err := time.Parse(time.RFC3339, status[0].Built); err != nil || time.Since(built) > time.Minute {
		t.Fatalf("status has no current build time: %q (%v)", status[0].Built, err)
	}
	if got := gunzipFile(t, filepath.Join(local, "logs", "imagemagick-7.1.2-32-1.txt.gz")); got != "build output\n" {
		t.Fatalf("published log %q", got)
	}
}

func TestUpdateWebsiteStatusSkipsMissingCheckout(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-a-checkout")
	old := WebsiteRepo
	WebsiteRepo = missing
	t.Cleanup(func() { WebsiteRepo = old })
	if err := UpdateWebsiteStatus("imagemagick", "7.1.2-32-1", "success", ""); err != nil {
		t.Fatalf("a missing checkout must be skipped: %v", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("nothing may be created at a missing checkout path: %v", err)
	}
}

// Only the newest websiteLogsKept logs per package stay on the site; older
// ones are deleted in the same commit. Logs are stored gzip-compressed.
func TestUpdateWebsiteStatusKeepsLastThreeLogs(t *testing.T) {
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz not installed")
	}
	tmp := t.TempDir()
	remote := filepath.Join(tmp, "remote.git")
	local := filepath.Join(tmp, "site")
	if out, err := exec.Command("git", "init", "--bare", "-q", "-b", "master", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if out, err := exec.Command("git", "clone", "-q", remote, local).CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	gitIn(t, local, "config", "user.name", "Hokuto Test")
	gitIn(t, local, "config", "user.email", "test@sauzeros.invalid")
	// An entry from before the history existed, with its plain-text log.
	legacy := `[{"pkgname":"foo","version":"1.0-1","status":"success","log":"logs/foo-1.0-1.txt"}]`
	if err := os.MkdirAll(filepath.Join(local, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"packages.json": legacy, "logs/foo-1.0-1.txt": "old\n"} {
		if err := os.WriteFile(filepath.Join(local, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitIn(t, local, "add", ".")
	gitIn(t, local, "commit", "-q", "-m", "initial")
	gitIn(t, local, "push", "-q", "origin", "master")

	old := WebsiteRepo
	WebsiteRepo = local
	t.Cleanup(func() { WebsiteRepo = old })

	publish := func(version string) {
		t.Helper()
		src := filepath.Join(tmp, "build-"+version+".log")
		if err := os.WriteFile(src, []byte("log of "+version+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// hokuto's own build logs are xz files.
		if out, err := exec.Command("xz", "-f", src).CombinedOutput(); err != nil {
			t.Fatalf("xz: %v\n%s", err, out)
		}
		if err := UpdateWebsiteStatus("foo", version, "success", src+".xz"); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{"2.0-1", "3.0-1", "4.0-1"} {
		publish(v)
	}
	publish("4.0-1") // a rebuild of the same version replaces its log

	var status []PackageStatus
	data, err := os.ReadFile(filepath.Join(local, "packages.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	want := []string{"logs/foo-4.0-1.txt.gz", "logs/foo-3.0-1.txt.gz", "logs/foo-2.0-1.txt.gz"}
	if len(status) != 1 || status[0].Log != want[0] || strings.Join(status[0].Logs, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected status %+v", status)
	}
	if got := gunzipFile(t, filepath.Join(local, want[0])); got != "log of 4.0-1\n" {
		t.Fatalf("newest log decompresses to %q", got)
	}
	tracked := gitIn(t, remote, "ls-tree", "--name-only", "master", "logs/")
	if strings.Join(strings.Fields(tracked), " ") != "logs/foo-2.0-1.txt.gz logs/foo-3.0-1.txt.gz logs/foo-4.0-1.txt.gz" {
		t.Fatalf("the oldest log must be deleted on the site too, remote has:\n%s", tracked)
	}
}
