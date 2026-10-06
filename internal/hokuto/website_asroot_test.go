package hokuto

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// An asroot build's output can hold directories only root may enter
// (cups: etc/cups/ssl); describing it must not need to walk them.
func TestDescribeWebsiteOutputUsesArchiveSize(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	meta := filepath.Join(output, "var/db/hokuto/installed/cups")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "manifest"), []byte("/usr/bin/lp  abc\n/etc/cups/ssl/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(output, "etc/cups/ssl")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(locked, 0)
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	tarball := filepath.Join(dir, "cups-2.5-1-x86_64-optimized.tar.zst")
	f, _ := os.Create(tarball)
	zw, _ := zstd.NewWriter(f)
	tw := tar.NewWriter(zw)
	for name, body := range map[string]string{
		"var/db/hokuto/installed/cups/pkginfo": "name=cups\n",
		"usr/bin/lp":                           "0123456789",
	} {
		tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	f.Close()

	out, err := describeWebsiteOutput(filepath.Join(dir, "site"), "x86_64", "2.5-1",
		WebsiteOutputSource{Name: "cups", OutputDir: output, Tarball: tarball})
	if err != nil {
		t.Fatalf("describe failed on an asroot output: %v", err)
	}
	if out.Installed != int64(len("name=cups\n")+10) || out.Files != 1 || out.Manifest == "" {
		t.Fatalf("incomplete description: %+v", out)
	}
}
