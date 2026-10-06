package hokuto

import (
	"bytes"
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

// A kernel's post-install hook (depmod, initramfs, boot entry) printed under
// the install bar and left it half drawn. The hook's output now takes the
// bar's line: the bar is suspended once, before the first output.
func TestPostInstallOutputSuspendsInstallBar(t *testing.T) {
	bar := newInstallProgress(2)
	if currentInstallProgress() != bar {
		t.Fatal("an active install bar must be registered")
	}
	suspends := 0
	var out bytes.Buffer
	w := &postInstallOutputWriter{destination: &out, startOnNewLine: true, beforeOutput: func() {
		suspends++
		bar.suspend()
	}}
	w.Write([]byte("Running depmod -a 7.2.9-sauzerOS\n"))
	w.Write([]byte("Generating initramfs for 7.2.9-sauzerOS\n"))
	if suspends != 1 {
		t.Fatalf("bar suspended %d times, want once", suspends)
	}
	if bar.lineActive {
		t.Fatal("the bar's line must be free after the hook's output")
	}
	if out.String() != "Running depmod -a 7.2.9-sauzerOS\nGenerating initramfs for 7.2.9-sauzerOS\n" {
		t.Fatalf("hook output changed: %q", out.String())
	}
	bar.advance()
	if !bar.lineActive {
		t.Fatal("the next update must draw the bar again")
	}
	bar.finish(true)
	if currentInstallProgress() != nil {
		t.Fatal("a finished bar must be unregistered")
	}
}
