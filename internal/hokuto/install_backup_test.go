package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatBackupFileName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"etc/hokuto/hokuto.conf", "etc_hokuto-hokuto.conf"},
		{"/etc/hokuto/hokuto.conf", "etc_hokuto-hokuto.conf"},
		{"etc/fstab", "etc-fstab"},
		{"/etc/fstab", "etc-fstab"},
		{"usr/share/doc/sample.txt", "usr_share_doc-sample.txt"},
		{"sample.txt", "sample.txt"},
		{"/sample.txt", "sample.txt"},
		{"etc/nested/dir/path/config.yaml", "etc_nested_dir_path-config.yaml"},
	}

	for _, tc := range tests {
		result := formatBackupFileName(tc.input)
		if result != tc.expected {
			t.Errorf("formatBackupFileName(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestBackupModifiedFile(t *testing.T) {
	tmp := t.TempDir()
	origSaveDir := SaveDir
	t.Cleanup(func() {
		SaveDir = origSaveDir
	})
	SaveDir = filepath.Join(tmp, "var/db/hokuto/save")

	// Create test modified file
	currentDir := filepath.Join(tmp, "etc/hokuto")
	if err := os.MkdirAll(currentDir, 0755); err != nil {
		t.Fatal(err)
	}
	currentFile := filepath.Join(currentDir, "hokuto.conf")
	expectedContent := "test_config_content = true\n"
	if err := os.WriteFile(currentFile, []byte(expectedContent), 0644); err != nil {
		t.Fatal(err)
	}

	execCtx := &Executor{Context: context.Background(), ShouldRunAsRoot: false}

	// Run backup
	relPath := "etc/hokuto/hokuto.conf"
	if err := backupModifiedFile(currentFile, relPath, execCtx, nil); err != nil {
		t.Fatalf("backupModifiedFile failed: %v", err)
	}

	// Verify backup file exists and matches content
	expectedBackupPath := filepath.Join(SaveDir, "etc_hokuto-hokuto.conf")
	data, err := os.ReadFile(expectedBackupPath)
	if err != nil {
		t.Fatalf("failed to read expected backup file %s: %v", expectedBackupPath, err)
	}
	if string(data) != expectedContent {
		t.Errorf("backup content mismatch: got %q, want %q", string(data), expectedContent)
	}
}
