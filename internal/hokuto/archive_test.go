package hokuto

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestSafeTarPathAllowsDotSlashEntriesAtRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("root path semantics are Unix-specific")
	}
	target, err := safeTarPath("/", "./usr/")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/usr" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestSafeTarPathRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../etc/passwd", "/etc/passwd", "usr/../../etc/passwd"} {
		if _, err := safeTarPath("/", name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func TestUnpackTarballFallbackCreatesHardlinks(t *testing.T) {
	tmp := t.TempDir()
	tarballPath := filepath.Join(tmp, "pkg.tar.zst")

	f, err := os.Create(tarballPath)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)

	content := []byte("binutils")
	if err := tw.WriteHeader(&tar.Header{
		Name: "usr/x86_64-lfs-linux-gnu/bin/objdump",
		Mode: 0o755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name:     "usr/bin/objdump",
		Mode:     0o755,
		Typeflag: tar.TypeLink,
		Linkname: "usr/x86_64-lfs-linux-gnu/bin/objdump",
	}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(tmp, "staging")
	if err := unpackTarballFallback(tarballPath, dest); err != nil {
		t.Fatal(err)
	}

	realPath := filepath.Join(dest, "usr/x86_64-lfs-linux-gnu/bin/objdump")
	linkPath := filepath.Join(dest, "usr/bin/objdump")
	realInfo, err := os.Stat(realPath)
	if err != nil {
		t.Fatal(err)
	}
	linkInfo, err := os.Stat(linkPath)
	if err != nil {
		t.Fatal(err)
	}

	realStat := realInfo.Sys().(*syscall.Stat_t)
	linkStat := linkInfo.Sys().(*syscall.Stat_t)
	if realStat.Ino != linkStat.Ino {
		t.Fatalf("expected %s and %s to be hardlinks to the same inode", realPath, linkPath)
	}
}

func TestCreatePackageTarballUsesHighCompressionZstd(t *testing.T) {
	tmp := t.TempDir()
	outputDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "file"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	fakeBin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(tmp, "tar.args")
	fakeTar := filepath.Join(fakeBin, "tar")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HOKUTO_TEST_TAR_ARGS\"\nout=''\nprev=''\nfor arg in \"$@\"; do\n  if [ \"$prev\" = '-cf' ]; then out=\"$arg\"; break; fi\n  prev=\"$arg\"\ndone\n[ -n \"$out\" ] || exit 2\n: > \"$out\"\n"
	if err := os.WriteFile(fakeTar, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	oldBinDir := BinDir
	BinDir = filepath.Join(tmp, "packages")
	t.Cleanup(func() { BinDir = oldBinDir })
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOKUTO_TEST_TAR_ARGS", argsPath)

	execCtx := &Executor{Context: context.Background(), Stdout: io.Discard, Stderr: io.Discard}
	if err := createPackageTarball("pkg", "1.0", "1", "x86_64", "optimized", outputDir, execCtx, io.Discard); err != nil {
		t.Fatal(err)
	}

	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--use-compress-program=zstd -T0 -19 --long=25\n") {
		t.Fatalf("expected high-compression zstd tar args with a 32 MiB window, got %q", string(args))
	}
}
