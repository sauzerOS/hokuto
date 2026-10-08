package hokuto

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildResultLineKeepsOneLine(t *testing.T) {
	when := time.Date(2026, 10, 8, 15, 4, 5, 0, time.UTC)
	got := buildResultLine(when, "failed", "foo", "1.2-1", "x86_64", 75*time.Second, "build failed:\n  exit\tstatus 2")
	want := "2026-10-08T15:04:05Z\tfailed\tfoo\t1.2-1\tx86_64\t75\tbuild failed: exit status 2\n"
	if got != want {
		t.Fatalf("buildResultLine() = %q, want %q", got, want)
	}
}

func TestRecordBuildResultsOnlyWhenRequested(t *testing.T) {
	oldRecorded := buildResultsRecorded
	buildResultsRecorded = make(map[string]bool)
	t.Cleanup(func() { buildResultsRecorded = oldRecorded })
	cfg := &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}}

	t.Setenv(buildResultsEnv, "")
	recordBuildResult("nothere", cfg, nil, time.Second)
	if buildResultsRecorded["nothere"] {
		t.Fatal("a result was recorded without HOKUTO_BUILD_RESULTS")
	}

	path := filepath.Join(t.TempDir(), "results")
	t.Setenv(buildResultsEnv, path)
	recordBuildResult("built", cfg, nil, 3*time.Second)
	// Already recorded by its build: the summary does not add it again.
	recordUnbuiltFailures(map[string]error{
		"built":   errors.New("post-build installation failed"),
		"blocked": errors.New("dependency failed"),
	}, cfg)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d result lines, want 2:\n%s", len(lines), data)
	}
	if f := strings.Split(lines[0], "\t"); f[1] != "success" || f[2] != "built" || f[4] != "aarch64" || f[5] != "3" {
		t.Errorf("first result = %q", lines[0])
	}
	if f := strings.Split(lines[1], "\t"); f[1] != "failed" || f[2] != "blocked" || f[6] != "dependency failed" {
		t.Errorf("second result = %q", lines[1])
	}
}
