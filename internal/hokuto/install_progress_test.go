package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootOnlyReadable(t *testing.T) {
	dir := t.TempDir()
	shadow := filepath.Join(dir, "shadow")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(shadow, []byte("root:!:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("root:x:0:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !rootOnlyReadable(shadow) {
		t.Error("a 0600 file is readable by root only: its diff must not be shown")
	}
	if rootOnlyReadable(group) {
		t.Error("a 0644 file is readable by everyone: its diff is shown")
	}
	if rootOnlyReadable(filepath.Join(dir, "missing")) {
		t.Error("a missing file is not root-only")
	}
}

func TestInstallProgressNilIsNoOp(t *testing.T) {
	var p *installProgress
	p.start("bash")
	p.advance()
	p.endLine()
	p.finish(true)
	if newInstallProgress(0) != nil {
		t.Fatal("no bar for an empty plan")
	}
}
