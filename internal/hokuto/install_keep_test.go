package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestKeepCurrentFileInStaging(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	current := filepath.Join(root, "passwd")
	staged := filepath.Join(staging, "passwd")
	if err := os.WriteFile(current, []byte("root:x:0:0::/root:/bin/bash\ndbz:x:1000:1000::/home/dbz:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := keepCurrentFileInStaging(current, staged, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := os.ReadFile(current); string(got) != string(want) {
		t.Fatalf("staging holds %q, want the installed file %q", got, want)
	}
}

func TestKeepCurrentSymlinkInStaging(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	current := filepath.Join(root, "localtime")
	staged := filepath.Join(staging, "localtime")
	if err := os.Symlink("/usr/share/zoneinfo/Asia/Bangkok", current); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/share/zoneinfo/UTC", staged); err != nil {
		t.Fatal(err)
	}

	if err := keepCurrentFileInStaging(current, staged, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(staged); err != nil || target != "/usr/share/zoneinfo/Asia/Bangkok" {
		t.Fatalf("staging symlink = %q, %v; want the installed target", target, err)
	}
}

func TestCopyRemovedFileIntoStaging(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	current := filepath.Join(root, "etc", "app.conf")
	staged := filepath.Join(staging, "etc", "app.conf")
	if err := os.MkdirAll(filepath.Dir(current), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyRemovedFileIntoStaging(current, staged, &Executor{Context: context.Background()}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(staged); string(got) != "edited\n" || info.Mode().Perm() != 0o600 {
		t.Fatalf("staging holds %q mode %v, want the installed file and its mode", got, info.Mode().Perm())
	}
}

func TestMoveRemovedFileToBackup(t *testing.T) {
	origSaveDir := SaveDir
	t.Cleanup(func() { SaveDir = origSaveDir })
	SaveDir = filepath.Join(t.TempDir(), "var/db/hokuto/save")

	root := t.TempDir()
	current := filepath.Join(root, "etc", "app.conf")
	if err := os.MkdirAll(filepath.Dir(current), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	backup, err := moveRemovedFileToBackup(current, "etc/app.conf", &Executor{Context: context.Background()})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(SaveDir, "etc-app.conf"); backup != want {
		t.Fatalf("backup path = %q, want %q", backup, want)
	}
	if got, err := os.ReadFile(backup); err != nil || string(got) != "edited\n" {
		t.Fatalf("backup holds %q, %v; want the modified file", got, err)
	}
	if _, err := os.Lstat(current); !os.IsNotExist(err) {
		t.Fatalf("%s still exists after the move (err %v)", current, err)
	}
}
