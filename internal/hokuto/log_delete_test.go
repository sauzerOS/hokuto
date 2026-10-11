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
