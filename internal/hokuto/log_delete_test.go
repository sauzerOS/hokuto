package hokuto

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildLogDeletableOnlyAfterFailedStatus(t *testing.T) {
	buildDir := t.TempDir()
	logPath := filepath.Join(buildDir, "build-log.txt")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	appendStatus := func(status string) {
		t.Helper()
		if err := appendBuildLogStatus(logPath, "foo", status, time.Now(), nil); err != nil {
			t.Fatal(err)
		}
	}
	deletable := func() bool {
		t.Helper()
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		ok, _ := canDeleteBuildDir(buildDir, string(data))
		return ok
	}

	// A running build, however long it has been quiet, is never deletable.
	write("Script started\r\nlinking libfoo.so\r\n")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(logPath, old, old); err != nil {
		t.Fatal(err)
	}
	if deletable() {
		t.Fatal("a quiet build without a failed status must not be deletable")
	}

	appendStatus("failed")
	if !deletable() {
		t.Fatal("a build hokuto marked failed must be deletable")
	}

	// Packaging that fails after the complete status marks the log failed again.
	write("Script done [COMMAND_EXIT_CODE=\"0\"]\r\n")
	appendStatus("complete")
	if deletable() {
		t.Fatal("a completed build must not be deletable")
	}
	appendStatus("failed")
	if !deletable() {
		t.Fatal("a build failed after its complete status must be deletable")
	}

	// Output after a failure line is not hokuto's status.
	write("make: Build failed at line 3\r\nstill running\r\n")
	if deletable() {
		t.Fatal("build output must not be read as hokuto's status")
	}

	if ok, _ := canDeleteBuildDir(filepath.Join(buildDir, "missing"), ">>> foo: Build failed at now"); ok {
		t.Fatal("a missing build tree must not be deletable")
	}
}

func TestTUISelectLogKeepsTheShownLog(t *testing.T) {
	now := time.Now()
	logs := []logInfo{
		{path: "/var/tmp/hokuto/a-01/log/build-log.txt", modTime: now.Add(-time.Minute)},
		{path: "/var/tmp/hokuto/b-01/log/build-log.txt", modTime: now},
		{path: "/var/tmp/hokuto/c-01/log/build-log.txt", modTime: now.Add(-time.Hour)},
	}
	if got := tuiSelectLog(logs, ""); got != 1 {
		t.Fatalf("at start the log written last is shown, got %d", got)
	}
	// Another build writing more recently does not take over.
	if got := tuiSelectLog(logs, logs[2].path); got != 2 {
		t.Fatalf("the shown log must stay shown, got %d", got)
	}
	// A new build's log lands before it: the shown log is followed by path.
	withNew := append([]logInfo{{path: "/var/tmp/hokuto/0-01/log/build-log.txt", modTime: now.Add(time.Second)}}, logs...)
	if got := tuiSelectLog(withNew, logs[2].path); got != 3 {
		t.Fatalf("the shown log must be followed to its new place, got %d", got)
	}
	// Its build tree removed, the log written last is shown.
	if got := tuiSelectLog(logs[:2], logs[2].path); got != 1 {
		t.Fatalf("a removed log gives way to the log written last, got %d", got)
	}
}
