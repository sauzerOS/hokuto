package hokuto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireZstd(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd binary not available")
	}
}

// compressibleBytes builds data that actually compresses, so frames end up with
// a realistic mix of block types rather than a single raw block.
func compressibleBytes(n int) []byte {
	rng := rand.New(rand.NewSource(1))
	words := [][]byte{[]byte("hokuto "), []byte("package "), []byte("sauzeros "), []byte("aarch64 ")}
	var buf bytes.Buffer
	for buf.Len() < n {
		buf.Write(words[rng.Intn(len(words))])
	}
	return buf.Bytes()[:n]
}

func TestScanZstdFramesSingleFrame(t *testing.T) {
	requireZstd(t)
	data := compressibleBytes(200 << 10)
	path := filepath.Join(t.TempDir(), "one.zst")

	var out bytes.Buffer
	if err := compressMultiFrame(bytes.NewReader(data), &out, int64(len(data))*2, 2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	frames, err := packageFrames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(frames))
	}
	if frames[0].Offset != 0 || frames[0].Length != int64(out.Len()) {
		t.Errorf("frame = %+v, want the whole %d byte file", frames[0], out.Len())
	}
	if frames[0].ContentSize != int64(len(data)) {
		t.Errorf("ContentSize = %d, want %d", frames[0].ContentSize, len(data))
	}
}

func TestScanZstdFramesMultiFrame(t *testing.T) {
	requireZstd(t)
	const chunk = 64 << 10
	data := compressibleBytes(chunk*4 + 1234)
	path := filepath.Join(t.TempDir(), "many.zst")

	var out bytes.Buffer
	if err := compressMultiFrame(bytes.NewReader(data), &out, chunk, 3); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	frames, err := packageFrames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 5 {
		t.Fatalf("frames = %d, want 5", len(frames))
	}

	var offset, content int64
	for i, fr := range frames {
		if fr.Offset != offset {
			t.Errorf("frame %d starts at %d, want %d", i, fr.Offset, offset)
		}
		offset += fr.Length
		content += fr.ContentSize
		want := int64(chunk)
		if i == len(frames)-1 {
			want = 1234
		}
		if fr.ContentSize != want {
			t.Errorf("frame %d ContentSize = %d, want %d", i, fr.ContentSize, want)
		}
	}
	if offset != int64(out.Len()) {
		t.Errorf("frames cover %d bytes, file is %d", offset, out.Len())
	}
	if content != int64(len(data)) {
		t.Errorf("frames decode to %d bytes, input was %d", content, len(data))
	}

	// The whole point of the format: the system zstd must still read it.
	plain, err := exec.Command("zstd", "-dc", "-q", path).Output()
	if err != nil {
		t.Fatalf("system zstd could not read the multi-frame archive: %v", err)
	}
	if !bytes.Equal(plain, data) {
		t.Error("system zstd produced different bytes")
	}
}

func TestMultiFrameRoundTrip(t *testing.T) {
	requireZstd(t)
	const chunk = 32 << 10
	for _, size := range []int{0, 1, chunk - 1, chunk, chunk + 1, chunk * 7} {
		data := compressibleBytes(size)
		path := filepath.Join(t.TempDir(), "rt.zst")

		var packed bytes.Buffer
		if err := compressMultiFrame(bytes.NewReader(data), &packed, chunk, 4); err != nil {
			t.Fatalf("size %d: compress: %v", size, err)
		}
		if err := os.WriteFile(path, packed.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		frames, err := packageFrames(path)
		if err != nil {
			t.Fatalf("size %d: scan: %v", size, err)
		}

		// Every worker count must reassemble the frames in the right order,
		// including counts below and above the frame count.
		for _, workers := range []int{1, 2, 4, 16} {
			var got bytes.Buffer
			if err := decompressMultiFrame(path, frames, &got, workers); err != nil {
				t.Fatalf("size %d workers %d: decompress: %v", size, workers, err)
			}
			if !bytes.Equal(got.Bytes(), data) {
				t.Fatalf("size %d workers %d: round trip mismatch (%d bytes back)", size, workers, got.Len())
			}
		}
	}
}

func TestScanZstdFramesSkippable(t *testing.T) {
	requireZstd(t)
	data := compressibleBytes(4 << 10)
	dir := t.TempDir()

	var body bytes.Buffer
	if err := compressMultiFrame(bytes.NewReader(data), &body, int64(len(data))*2, 1); err != nil {
		t.Fatal(err)
	}

	// A skippable frame carries arbitrary payload and must be walked over, not
	// parsed as a zstd frame.
	var withSkip bytes.Buffer
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header[0:], zstdSkippableMagicMin)
	binary.LittleEndian.PutUint32(header[4:], 16)
	withSkip.Write(header)
	withSkip.Write(make([]byte, 16))
	withSkip.Write(body.Bytes())

	path := filepath.Join(dir, "skip.zst")
	if err := os.WriteFile(path, withSkip.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	frames, err := packageFrames(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2 (skippable + data)", len(frames))
	}
	if frames[0].Length != 24 {
		t.Errorf("skippable frame length = %d, want 24", frames[0].Length)
	}
	if frames[0].ContentSize != -1 {
		t.Errorf("skippable frame ContentSize = %d, want -1", frames[0].ContentSize)
	}
}

func TestScanZstdFramesRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.zst")
	if err := os.WriteFile(path, []byte("this is not a zstd stream at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := packageFrames(path); err == nil {
		t.Error("expected an error for a non-zstd file")
	}
}

func TestZstdWorkersIsBounded(t *testing.T) {
	if n := zstdWorkers(); n < 1 || n > zstdMaxWorkers {
		t.Errorf("zstdWorkers() = %d, want between 1 and %d", n, zstdMaxWorkers)
	}
}

// TestUnpackMultiFramePackageRoundTrip walks the whole install-side path: a real
// tar stream packed into several frames, then decoded concurrently back through
// tar into a staging tree.
func TestUnpackMultiFramePackageRoundTrip(t *testing.T) {
	requireZstd(t)
	if _, err := exec.LookPath("tar"); err != nil {
		t.Skip("tar not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	for _, sub := range []string{"usr/bin", "usr/lib", "usr/share/doc"} {
		if err := os.MkdirAll(filepath.Join(src, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Enough content to span several frames at the chunk size used below.
	const chunk = 64 << 10
	for i, name := range []string{"usr/bin/tool", "usr/lib/libbig.so", "usr/share/doc/readme"} {
		body := compressibleBytes(chunk * (i + 2))
		if err := os.WriteFile(filepath.Join(src, name), body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("libbig.so", filepath.Join(src, "usr/lib/libbig.so.1")); err != nil {
		t.Fatal(err)
	}

	tarCmd := exec.Command("tar", "-cf", "-", "-C", src, ".")
	stream, err := tarCmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := tarCmd.Start(); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(dir, "pkg.tar.zst")
	f, err := os.Create(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := compressMultiFrame(stream, f, chunk, 4); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tarCmd.Wait(); err != nil {
		t.Fatal(err)
	}

	frames, err := packageFrames(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("frames = %d, want the archive split across several", len(frames))
	}

	staging := filepath.Join(dir, "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	execCtx := &Executor{Context: context.Background()}
	if err := unpackMultiFrame(pkg, staging, execCtx); err != nil {
		t.Fatalf("parallel unpack failed: %v", err)
	}

	if out, err := exec.Command("diff", "-rq", "--no-dereference", src, staging).CombinedOutput(); err != nil {
		t.Fatalf("unpacked tree differs from the source: %v\n%s", err, out)
	}
}

func TestUnpackMultiFrameSkipsSingleFrameArchives(t *testing.T) {
	requireZstd(t)
	dir := t.TempDir()
	pkg := filepath.Join(dir, "one.tar.zst")

	data := compressibleBytes(8 << 10)
	f, err := os.Create(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := compressMultiFrame(bytes.NewReader(data), f, int64(len(data))*4, 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	err = unpackMultiFrame(pkg, dir, &Executor{Context: context.Background()})
	if !errors.Is(err, errSingleFrameArchive) {
		t.Fatalf("err = %v, want errSingleFrameArchive so the caller uses the ordinary path", err)
	}
}
