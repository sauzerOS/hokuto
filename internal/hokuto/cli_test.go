package hokuto

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func writeTestBinaryTarball(t *testing.T, path, name, version, revision string) {
	writeTestBinaryTarballWithDepends(t, path, name, version, revision, "")
}

func writeTestBinaryTarballWithDepends(t *testing.T, path, name, version, revision, depends string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	metadataDir := filepath.Join("var", "db", "hokuto", "installed", name)
	pkginfo := "name=" + name + "\nversion=" + version + "\nrevision=" + revision + "\narch=x86_64\ngeneric=0\nmultilib=0\n"
	if err := tw.WriteHeader(&tar.Header{
		Name: filepath.Join(metadataDir, "pkginfo"),
		Mode: 0o644,
		Size: int64(len(pkginfo)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(pkginfo)); err != nil {
		t.Fatal(err)
	}
	if depends != "" {
		if err := tw.WriteHeader(&tar.Header{
			Name: filepath.Join(metadataDir, "depends"),
			Mode: 0o644,
			Size: int64(len(depends)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(depends)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFindNewestTarballSkipsPrefixMatchedSubpackage(t *testing.T) {
	oldBinDir := BinDir
	BinDir = t.TempDir()
	t.Cleanup(func() { BinDir = oldBinDir })

	subpackage := filepath.Join(BinDir, StandardizeRemoteName("qt-multimedia-gstreamer", "6.11.1", "1", "x86_64", "optimized"))
	parent := filepath.Join(BinDir, StandardizeRemoteName("qt-multimedia", "6.11.1", "1", "x86_64", "optimized"))

	writeTestBinaryTarball(t, subpackage, "qt-multimedia-gstreamer", "6.11.1", "1")
	writeTestBinaryTarball(t, parent, "qt-multimedia", "6.11.1", "1")

	newer := time.Now().Add(time.Hour)
	if err := os.Chtimes(subpackage, newer, newer); err != nil {
		t.Fatal(err)
	}

	got, version, revision := findNewestTarball("qt-multimedia", "optimized")
	if got != parent {
		t.Fatalf("expected parent tarball %s, got %s", parent, got)
	}
	if version != "6.11.1" || revision != "1" {
		t.Fatalf("expected version 6.11.1-1, got %s-%s", version, revision)
	}
}
