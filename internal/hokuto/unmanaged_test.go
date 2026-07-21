package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanModifiedManifestFilesFindsChangedOwnedFile(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	rootDir = root
	Installed = filepath.Join(root, "var", "db", "hokuto", "installed")
	cfg.Values["HOKUTO_ROOT"] = root

	filePath := filepath.Join(root, "etc", "foo.conf")
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := ComputeChecksum(filePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	pkgDir := filepath.Join(Installed, "owner")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "manifest"), []byte("/etc/foo.conf  "+sum+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filePath, []byte("modified\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	modified, err := scanModifiedManifestFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(modified) != 1 || modified[0].Path != "/etc/foo.conf" || modified[0].Reason != "modified:owner" {
		t.Fatalf("unexpected modified entries: %+v", modified)
	}
}

func TestUnmanagedBackupArchiveRoundTripSelectedFiles(t *testing.T) {
	root := t.TempDir()
	etcFile := filepath.Join(root, "etc", "foo.conf")
	homeFile := filepath.Join(root, "home", "dbz", "foo")
	for _, p := range []string{etcFile, homeFile} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(etcFile, []byte("etc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homeFile, []byte("home\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "backup.tar.zst")
	entries := []unmanagedEntry{
		{Path: "/etc/foo.conf", Reason: "unmanaged"},
		{Path: "/home/dbz/foo", Reason: "extra"},
	}
	if err := writeBackupArchive(root, archivePath, entries); err != nil {
		t.Fatal(err)
	}

	listed, err := listBackupArchive(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected two archive entries, got %+v", listed)
	}

	if err := os.WriteFile(etcFile, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homeFile, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreBackupArchive(root, archivePath, map[string]bool{"/etc/foo.conf": true}); err != nil {
		t.Fatal(err)
	}

	etcData, err := os.ReadFile(etcFile)
	if err != nil {
		t.Fatal(err)
	}
	homeData, err := os.ReadFile(homeFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(etcData) != "etc\n" {
		t.Fatalf("expected selected etc file to be restored, got %q", etcData)
	}
	if string(homeData) != "changed\n" {
		t.Fatalf("expected unselected home file to remain changed, got %q", homeData)
	}
}

func TestSelectableEntryMatchesPathCaseInsensitively(t *testing.T) {
	entry := selectableEntry{Primary: "/usr/share/icons/Breeze-Dark/icon.svg", Meta: "unmanaged"}
	if !selectableEntryMatches(entry, "breeze-dark") {
		t.Fatal("expected path substring to match")
	}
	if !selectableEntryMatches(entry, "ICON.SVG") {
		t.Fatal("expected search to be case-insensitive")
	}
	if selectableEntryMatches(entry, "modified") {
		t.Fatal("search should filter by the displayed path like uninstall --list filters by package name")
	}
}

func TestDeleteUnmanagedEntriesRemovesOnlySelectedFiles(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "etc", "selected.conf")
	remaining := filepath.Join(root, "etc", "remaining.conf")
	if err := os.MkdirAll(filepath.Dir(selected), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{selected, remaining} {
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := deleteUnmanagedEntries(root, []unmanagedEntry{{Path: "/etc/selected.conf"}}, &Executor{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(selected); !os.IsNotExist(err) {
		t.Fatalf("selected file was not deleted: %v", err)
	}
	if _, err := os.Lstat(remaining); err != nil {
		t.Fatalf("unselected file should remain: %v", err)
	}
}
