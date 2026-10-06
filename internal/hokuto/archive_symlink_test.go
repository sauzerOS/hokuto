package hokuto

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestUnpackFallbackDoesNotWriteThroughArchiveSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "evil.tar.zst")
	f, _ := os.Create(archive)
	zw, _ := zstd.NewWriter(f)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: outside})
	tw.WriteHeader(&tar.Header{Name: "lib64", Typeflag: tar.TypeSymlink, Linkname: "../lib"})
	tw.WriteHeader(&tar.Header{Name: "a/pwned", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	zw.Close()
	f.Close()

	dest := filepath.Join(dir, "dest")
	os.MkdirAll(dest, 0o755)
	_ = unpackTarballFallback(archive, dest)
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("a file was written outside dest through an archive symlink")
	}
	if link, err := os.Readlink(filepath.Join(dest, "lib64")); err != nil || link != "../lib" {
		t.Fatalf("relative package symlink not created: %q, %v", link, err)
	}
}
