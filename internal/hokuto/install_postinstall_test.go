package hokuto

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledPostInstallDependencyIsPreserved(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	if err := os.MkdirAll(Installed, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Values["HOKUTO_ROOT"] = root

	writeInstalledTestPackageWithDepends(t, "linux", "dracut post-install\n")
	writeInstalledTestPackageWithDepends(t, "dracut", "")

	var log bytes.Buffer
	execCtx := &Executor{Context: context.Background()}
	newlyInstalled, err := installPostInstallDependencies("linux", cfg, execCtx, &log, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(newlyInstalled) != 0 {
		t.Fatalf("preinstalled dependency must not be scheduled for cleanup, got %v", newlyInstalled)
	}
	if !isPackageInstalled("dracut") {
		t.Fatal("preinstalled post-install dependency was removed")
	}
}

func TestCleanupPostInstallDependencyIgnoresParentTag(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	if err := os.MkdirAll(Installed, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Values["HOKUTO_ROOT"] = root

	writeInstalledTestPackageWithDepends(t, "linux", "dracut post-install\n")
	writeInstalledTestPackageWithDepends(t, "dracut", "")
	if err := os.WriteFile(filepath.Join(Installed, "dracut", "manifest"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	execCtx := &Executor{Context: context.Background()}
	if err := cleanupPostInstallDependencies([]string{"dracut"}, cfg, execCtx, &log, true); err != nil {
		t.Fatal(err)
	}
	if isPackageInstalled("dracut") {
		t.Fatal("temporary post-install dependency was not removed")
	}
	if !isPackageInstalled("linux") {
		t.Fatal("parent package was unexpectedly removed")
	}
}
