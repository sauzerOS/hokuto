package hokuto

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const testRoundFile = "round\t1791460800\t6060\n" +
	"step\tbump\t0\t4320\n" +
	"pkg\t2026-10-08T15:00:00Z\tsuccess\ttmux\t3.8-1\tx86_64\t190\t\n" +
	"pkg\t2026-10-08T15:01:00Z\tfailed\tbaz\t2.0-1\tx86_64\t62\tbuild script exited with code 2\n" +
	"step\tgeneric rebuild\t0\t300\n" +
	"pkg\t2026-10-08T15:05:00Z\tsuccess\ttmux\t3.8-1\tx86_64\t200\t\n" +
	"step\tcross-sync\t1\t1510\n" +
	"cleanup\tremoved 3 leftover item(s)\n"

func TestParseWebsiteRound(t *testing.T) {
	round, err := parseWebsiteRound(testRoundFile)
	if err != nil {
		t.Fatal(err)
	}
	if round.Started != "2026-10-08T12:00:00Z" || round.Duration != 6060 || round.Cleanup != "removed 3 leftover item(s)" {
		t.Fatalf("round = %+v", round)
	}
	if len(round.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(round.Steps))
	}
	bump, cross := round.Steps[0], round.Steps[2]
	if bump.Status != "ok" || len(bump.Packages) != 2 || bump.Packages[1].Reason != "build script exited with code 2" {
		t.Fatalf("bump step = %+v", bump)
	}
	if cross.Status != "failed" || cross.Exit != 1 || len(cross.Packages) != 0 {
		t.Fatalf("cross-sync step = %+v", cross)
	}
	if built, failed := roundCounts(round); built != 2 || failed != 1 {
		t.Fatalf("roundCounts = %d, %d; want 2, 1", built, failed)
	}
}

func TestParseWebsiteRoundRejectsPackageBeforeStep(t *testing.T) {
	if _, err := parseWebsiteRound("round\t1\t1\npkg\tx\tsuccess\tfoo\t1-1\tx86_64\t1\t\n"); err == nil {
		t.Fatal("a package outside a step was accepted")
	}
}

func TestPublishWebsiteRoundCommitsAndLinksLogs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote.git")
	site := filepath.Join(dir, "site")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "--bare", remote)
	git("clone", "-q", remote, site)
	git("-C", site, "config", "user.name", "t")
	git("-C", site, "config", "user.email", "t@t")
	if err := os.MkdirAll(filepath.Join(site, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The tmux build published its log; baz's did not.
	if err := os.WriteFile(filepath.Join(site, "logs", "tmux-3.8-1.txt.gz"), []byte("log"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("-C", site, "add", "-A")
	git("-C", site, "commit", "-q", "-m", "init")
	git("-C", site, "push", "-q", "-u", "origin", "HEAD")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")

	round, err := parseWebsiteRound(testRoundFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := publishWebsiteRound(site, round); err != nil {
			t.Fatal(err)
		}
	}

	data, err := os.ReadFile(filepath.Join(site, "rounds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rounds []WebsiteRound
	if err := json.Unmarshal(data, &rounds); err != nil {
		t.Fatal(err)
	}
	if len(rounds) != 2 {
		t.Fatalf("rounds.json has %d rounds, want 2", len(rounds))
	}
	pkgs := rounds[0].Steps[0].Packages
	if pkgs[0].Log != "logs/tmux-3.8-1.txt.gz" || pkgs[1].Log != "" {
		t.Fatalf("logs = %q, %q", pkgs[0].Log, pkgs[1].Log)
	}
	// The generic tmux build does not get the optimized build's log.
	if generic := rounds[0].Steps[1].Packages[0]; generic.Log != "" {
		t.Fatalf("generic build linked to %q", generic.Log)
	}
	out, err := exec.Command("git", "-C", remote, "log", "--format=%s", "-1").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got == "" || got[:11] != "Build round" {
		t.Fatalf("remote head = %q, want the round commit", got)
	}
}
