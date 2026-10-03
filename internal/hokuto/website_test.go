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
	if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "imagemagick", Arch: "x86_64", Version: "7.1.2-32-1", Status: "success", LogPath: log}); err != nil {
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
	if len(status) != 1 || status[0].Builds["x86_64"] == nil || status[0].Builds["x86_64"].Log != "logs/imagemagick-7.1.2-32-1.txt.gz" {
		t.Fatalf("unexpected published status %+v", status)
	}
	if built, err := time.Parse(time.RFC3339, status[0].Builds["x86_64"].Built); err != nil || time.Since(built) > time.Minute {
		t.Fatalf("status has no current build time: %q (%v)", status[0].Builds["x86_64"].Built, err)
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
	if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "imagemagick", Arch: "x86_64", Version: "7.1.2-32-1", Status: "success"}); err != nil {
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
		if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "foo", Arch: "x86_64", Version: version, Status: "success", LogPath: src + ".xz"}); err != nil {
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
	// The legacy entry became the x86_64 build; its own fields are gone.
	if len(status) != 1 || status[0].Version != "" || status[0].Log != "" {
		t.Fatalf("legacy fields kept: %+v", status)
	}
	build := status[0].Builds["x86_64"]
	if build == nil || build.Log != want[0] || strings.Join(build.Logs, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected status %+v", build)
	}
	if got := gunzipFile(t, filepath.Join(local, want[0])); got != "log of 4.0-1\n" {
		t.Fatalf("newest log decompresses to %q", got)
	}
	tracked := gitIn(t, remote, "ls-tree", "--name-only", "master", "logs/")
	if strings.Join(strings.Fields(tracked), " ") != "logs/foo-2.0-1.txt.gz logs/foo-3.0-1.txt.gz logs/foo-4.0-1.txt.gz" {
		t.Fatalf("the oldest log must be deleted on the site too, remote has:\n%s", tracked)
	}
}

// withWebsiteCheckout points WebsiteRepo at a fresh checkout with a remote,
// so UpdateWebsiteStatus can commit and push.
func withWebsiteCheckout(t *testing.T) string {
	t.Helper()
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
	if err := os.WriteFile(filepath.Join(local, "packages.json"), []byte("[]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, local, "add", ".")
	gitIn(t, local, "commit", "-q", "-m", "initial")
	gitIn(t, local, "push", "-q", "origin", "master")
	old := WebsiteRepo
	WebsiteRepo = local
	t.Cleanup(func() { WebsiteRepo = old })
	return local
}

func readWebsiteStatus(t *testing.T, site string) map[string]PackageStatus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(site, "packages.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list []PackageStatus
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]PackageStatus)
	for _, p := range list {
		byName[p.PkgName] = p
	}
	return byName
}

// A package's x86_64 and arm64 builds of one version are separate entries
// with separate logs; neither replaces the other.
func TestUpdateWebsiteStatusKeepsArchitecturesApart(t *testing.T) {
	site := withWebsiteCheckout(t)
	tmp := t.TempDir()
	for _, arch := range []string{"x86_64", "aarch64"} {
		log := filepath.Join(tmp, arch+".log")
		if err := os.WriteFile(log, []byte(arch+" build\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		status := "success"
		if arch == "aarch64" {
			status = "failed"
		}
		if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "cups", Arch: arch, Version: "2.4.19-3", Status: status, LogPath: log, BuildTime: 95 * time.Second}); err != nil {
			t.Fatal(err)
		}
	}
	cups := readWebsiteStatus(t, site)["cups"]
	native, arm := cups.Builds["x86_64"], cups.Builds["aarch64"]
	if native == nil || arm == nil || native.Status != "success" || arm.Status != "failed" {
		t.Fatalf("builds = %+v", cups.Builds)
	}
	if native.Log != "logs/cups-2.4.19-3.txt.gz" || arm.Log != "logs/cups-2.4.19-3-aarch64.txt.gz" {
		t.Fatalf("logs = %q, %q", native.Log, arm.Log)
	}
	if native.BuildTime != 95 {
		t.Fatalf("buildtime = %d, want 95", native.BuildTime)
	}
	if got := gunzipFile(t, filepath.Join(site, native.Log)); got != "x86_64 build\n" {
		t.Fatalf("native log was overwritten: %q", got)
	}

	// Not listed at all: no entry, no commit.
	if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "zlib", Version: "1-1", Status: "success"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := readWebsiteStatus(t, site)["zlib"]; ok {
		t.Fatal("a build without a listed architecture was recorded")
	}
}

// A successful build lists each package it made with its sizes and a link
// to its file list; a failed one keeps the last successful build's.
func TestUpdateWebsiteStatusRecordsOutputs(t *testing.T) {
	site := withWebsiteCheckout(t)
	tmp := t.TempDir()
	stage := func(name string, files map[string]string) string {
		t.Helper()
		dir := filepath.Join(tmp, name)
		var manifest []string
		for path, data := range files {
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			manifest = append(manifest, "/"+path+"  0000")
		}
		manifest = append(manifest, "/usr/")
		meta := filepath.Join(dir, "var", "db", "hokuto", "installed", name)
		if err := os.MkdirAll(meta, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(meta, "manifest"), []byte(strings.Join(manifest, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	parent := stage("foo", map[string]string{"usr/bin/foo": "12345", "usr/lib/libfoo.so": "123"})
	split := stage("foo-doc", map[string]string{"usr/share/doc/foo.txt": "1234567890"})
	tarball := filepath.Join(tmp, "foo.tar.zst")
	if err := os.WriteFile(tarball, make([]byte, 42), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "foo", Arch: "aarch64", Version: "1.0-1", Status: "success", Outputs: []WebsiteOutputSource{
		{Name: "foo", OutputDir: parent, Tarball: tarball},
		{Name: "foo-doc", OutputDir: split, Tarball: filepath.Join(tmp, "missing.tar.zst")},
	}}); err != nil {
		t.Fatal(err)
	}
	outputs := readWebsiteStatus(t, site)["foo"].Builds["aarch64"].Outputs
	if len(outputs) != 2 {
		t.Fatalf("outputs = %+v", outputs)
	}
	foo := outputs[0]
	// The installed size counts the manifest too: it is installed.
	if foo.Name != "foo" || foo.Version != "1.0-1" || foo.Size != 42 || foo.Files != 2 || foo.Installed < 8 {
		t.Fatalf("foo = %+v", foo)
	}
	if foo.Manifest != "manifests/aarch64/foo.txt.gz" {
		t.Fatalf("manifest = %q", foo.Manifest)
	}
	if got := gunzipFile(t, filepath.Join(site, foo.Manifest)); got != "/usr/bin/foo\n/usr/lib/libfoo.so\n" && got != "/usr/lib/libfoo.so\n/usr/bin/foo\n" {
		t.Fatalf("manifest lists %q", got)
	}
	if tracked := gitIn(t, site, "ls-files", "manifests"); !strings.Contains(tracked, "manifests/aarch64/foo-doc.txt.gz") {
		t.Fatalf("manifests were not committed: %q", tracked)
	}

	if err := UpdateWebsiteStatus(WebsiteBuildResult{PkgName: "foo", Arch: "aarch64", Version: "1.1-1", Status: "failed"}); err != nil {
		t.Fatal(err)
	}
	build := readWebsiteStatus(t, site)["foo"].Builds["aarch64"]
	if build.Version != "1.1-1" || len(build.Outputs) != 2 || build.Outputs[0].Version != "1.0-1" {
		t.Fatalf("a failed build must keep the last packages: %+v", build)
	}
}

func TestWebsiteBuildArch(t *testing.T) {
	optimized := &Config{Values: map[string]string{}}
	generic := &Config{Values: map[string]string{"HOKUTO_GENERIC": "1"}}
	for _, tc := range []struct {
		name, arch string
		cfg        *Config
		want       string
	}{
		{"cups", "x86_64", optimized, "x86_64"},
		{"cups", "x86_64", generic, ""},
		{"cups", "aarch64", optimized, "aarch64"},
		{"cups", "aarch64", generic, "aarch64"},
		{"aarch64-cups", "aarch64", optimized, ""},
		{"aarch64-gcc", "x86_64", optimized, ""},
	} {
		if got := websiteBuildArch(tc.name, tc.arch, tc.cfg); got != tc.want {
			t.Errorf("websiteBuildArch(%s, %s, generic=%v) = %q, want %q", tc.name, tc.arch, tc.cfg == generic, got, tc.want)
		}
	}
}
