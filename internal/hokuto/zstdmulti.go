package hokuto

// Multi-frame zstd packaging.
//
// A zstd stream may be a concatenation of independent frames, and every zstd
// implementation reads such a stream transparently, so a package packed this
// way is still an ordinary .tar.zst that `tar --zstd -xf` and `unzstd` handle.
// What the framing buys is parallel decompression: frames share no history, so
// they can be decoded on separate cores and concatenated.
//
// hokuto cuts the tar byte stream into fixed-size pieces when packing and
// decodes the frames concurrently when installing. Both directions drive the
// system zstd binary rather than a Go decoder: measured on a Cortex-A72, the
// pure-Go decoder is about 4x slower per core, enough that spreading it over
// every core still loses to a single C process.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	// Frames are compressed one per process, so the number of frames is what
	// decides how many cores packing can use -- zstd's own -T threading is no
	// help here, because --long=25 makes its internal jobs so large that a
	// 128 MiB frame only ever splits into two of them, and below that into one.
	// The chunk size is therefore derived from the size of the package so that
	// it lands on roughly zstdPackTargetWorkers frames, clamped to this range.
	//
	// The bounds trade ratio against parallelism. Measured on the gcc package:
	// 64 MiB chunks cost +2.07% over a single frame, 128 MiB +0.56%, 256 MiB
	// +0.19%. The floor only comes into play for packages too small to fill
	// that many chunks, where a few percent of a small archive is a few hundred
	// kilobytes.
	zstdMinChunkSize = 32 << 20
	zstdMaxChunkSize = 256 << 20

	// zstdFrameChunkSize is the fallback when the size of the input is not
	// known ahead of time.
	zstdFrameChunkSize = 128 << 20

	// zstdPackLevel and zstdPackWindow mirror what the single-frame packer used.
	// A 32 MiB window materially improves compression of large package members
	// such as Java module and CDS images.
	zstdPackLevel  = "-19"
	zstdPackWindow = "--long=25"

	// zstdMaxUnpackWorkers caps concurrency when installing. Every worker holds
	// a decoded chunk in memory, and past a handful of them the archive is no
	// longer the bottleneck anyway.
	zstdMaxUnpackWorkers = 8
)

const (
	zstdFrameMagic        = 0xFD2FB528
	zstdSkippableMagicMin = 0x184D2A50
	zstdSkippableMagicMax = 0x184D2A5F
)

// zstdFrame is the extent of one frame inside a compressed file.
// ContentSize is the decompressed length the frame header declares, or -1 when
// the header does not carry one.
type zstdFrame struct {
	Offset      int64
	Length      int64
	ContentSize int64
}

// zstdChunkSizeEnv overrides how much input goes into one frame, in MiB. Set it
// to 0 to pack single-frame archives the way hokuto did before.
const zstdChunkSizeEnv = "HOKUTO_ZSTD_CHUNK_MB"

// zstdChunkSizeOverride reports an explicitly configured chunk size.
func zstdChunkSizeOverride() (int64, bool) {
	v := os.Getenv(zstdChunkSizeEnv)
	if v == "" {
		return 0, false
	}
	mb, err := strconv.ParseInt(v, 10, 64)
	if err != nil || mb < 0 {
		debugf("Ignoring invalid %s=%q\n", zstdChunkSizeEnv, v)
		return 0, false
	}
	if mb == 0 {
		// A chunk larger than any package means one frame per archive.
		return 1 << 62, true
	}
	return mb << 20, true
}

// zstdChunkSize returns the frame chunk size to pack with when the size of the
// input is not known.
func zstdChunkSize() int64 {
	return zstdChunkSizeForInput(0)
}

// zstdWorkers returns the concurrency to use when unpacking, capped by core
// count.
func zstdWorkers() int {
	n := runtime.NumCPU()
	if n > zstdMaxUnpackWorkers {
		n = zstdMaxUnpackWorkers
	}
	if n < 1 {
		n = 1
	}
	return n
}

// zstdPackTargetWorkers is how many cores packing aims to occupy: half of them,
// leaving the rest of the machine usable while a package is being compressed.
func zstdPackTargetWorkers() int {
	if n := runtime.NumCPU() / 2; n > 1 {
		return n
	}
	return 1
}

// zstdChunkSizeForInput picks a frame size that splits totalSize across the
// cores packing is allowed to use. totalSize of 0 means the caller does not
// know, in which case the fixed default applies.
func zstdChunkSizeForInput(totalSize int64) int64 {
	if override, ok := zstdChunkSizeOverride(); ok {
		return override
	}
	if totalSize <= 0 {
		return zstdFrameChunkSize
	}

	target := int64(zstdPackTargetWorkers())
	chunk := (totalSize + target - 1) / target

	if chunk < zstdMinChunkSize {
		chunk = zstdMinChunkSize
	}
	if chunk > zstdMaxChunkSize {
		chunk = zstdMaxChunkSize
	}
	return chunk
}

// Rough per-worker footprints, measured with a 32 MiB window: a zstd -19
// compressor holds about 310 MB, a decompressor only its window and buffers.
const (
	zstdPackWorkerOverhead   = 320 << 20
	zstdUnpackWorkerOverhead = 64 << 20
)

// packWorkers is how many frames to compress at once: the target share of the
// cores, reduced if there is not enough memory for that many.
func packWorkers(chunkSize int64) int {
	n := zstdPackTargetWorkers()
	if fits := memoryBoundedWorkers(zstdPackWorkerOverhead + chunkSize); fits < n {
		n = fits
	}
	if n < 1 {
		n = 1
	}
	return n
}

// boundedWorkers caps concurrency so the workers together stay inside about
// half of the memory currently available. Packing in particular runs on the
// same machine as the build that produced the files, and a Pi has no headroom
// to spare.
func boundedWorkers(perWorker int64) int {
	n := zstdWorkers()
	if fits := memoryBoundedWorkers(perWorker); fits < n {
		n = fits
	}
	if n < 1 {
		n = 1
	}
	return n
}

// memoryBoundedWorkers reports how many workers of the given footprint fit in
// about half of the memory currently available, or a very large number when
// that cannot be determined.
func memoryBoundedWorkers(perWorker int64) int {
	avail := availableMemoryBytes()
	if avail <= 0 || perWorker <= 0 {
		return math.MaxInt32
	}
	if fits := int(avail / 2 / perWorker); fits > 0 {
		return fits
	}
	return 1
}

// availableMemoryBytes reports MemAvailable, or 0 when it cannot be read.
func availableMemoryBytes() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// frameScanner reads the few header bytes that describe a frame's layout and
// skips over block payloads without touching them.
type frameScanner struct {
	ra   io.ReaderAt
	size int64
	pos  int64
	buf  [8]byte
}

func (s *frameScanner) read(n int) ([]byte, error) {
	if s.pos+int64(n) > s.size {
		return nil, io.ErrUnexpectedEOF
	}
	if _, err := s.ra.ReadAt(s.buf[:n], s.pos); err != nil {
		return nil, err
	}
	s.pos += int64(n)
	return s.buf[:n], nil
}

func (s *frameScanner) skip(n int64) error {
	if n < 0 || s.pos+n > s.size {
		return io.ErrUnexpectedEOF
	}
	s.pos += n
	return nil
}

// scanZstdFrames returns the extent of every frame in a zstd stream by walking
// frame and block headers only, so the cost tracks the block count rather than
// the size of the data.
func scanZstdFrames(ra io.ReaderAt, size int64) ([]zstdFrame, error) {
	s := &frameScanner{ra: ra, size: size}
	var frames []zstdFrame

	for s.pos < size {
		start := s.pos
		b, err := s.read(4)
		if err != nil {
			return nil, err
		}
		magic := binary.LittleEndian.Uint32(b)

		// A skippable frame carries its payload length directly.
		if magic >= zstdSkippableMagicMin && magic <= zstdSkippableMagicMax {
			b, err = s.read(4)
			if err != nil {
				return nil, err
			}
			if err := s.skip(int64(binary.LittleEndian.Uint32(b))); err != nil {
				return nil, err
			}
			frames = append(frames, zstdFrame{Offset: start, Length: s.pos - start, ContentSize: -1})
			continue
		}
		if magic != zstdFrameMagic {
			return nil, fmt.Errorf("not a zstd frame at offset %d (magic %#08x)", start, magic)
		}

		b, err = s.read(1)
		if err != nil {
			return nil, err
		}
		descriptor := b[0]
		if descriptor&0x08 != 0 {
			return nil, fmt.Errorf("reserved bit set in frame header at offset %d", start)
		}
		contentSizeFlag := descriptor >> 6
		singleSegment := descriptor&0x20 != 0
		hasChecksum := descriptor&0x04 != 0

		if !singleSegment {
			if err := s.skip(1); err != nil { // Window_Descriptor
				return nil, err
			}
		}
		if err := s.skip(int64([]int{0, 1, 2, 4}[descriptor&0x03])); err != nil { // Dictionary_ID
			return nil, err
		}
		contentSizeBytes := 0
		switch contentSizeFlag {
		case 0:
			if singleSegment {
				contentSizeBytes = 1
			}
		case 1:
			contentSizeBytes = 2
		case 2:
			contentSizeBytes = 4
		case 3:
			contentSizeBytes = 8
		}
		contentSize := int64(-1)
		if contentSizeBytes > 0 {
			b, err = s.read(contentSizeBytes)
			if err != nil {
				return nil, err
			}
			switch contentSizeBytes {
			case 1:
				contentSize = int64(b[0])
			case 2:
				// The 2-byte form stores the value less 256.
				contentSize = int64(binary.LittleEndian.Uint16(b)) + 256
			case 4:
				contentSize = int64(binary.LittleEndian.Uint32(b))
			case 8:
				if v := binary.LittleEndian.Uint64(b); v <= 1<<62 {
					contentSize = int64(v)
				}
			}
		}

		for {
			b, err = s.read(3)
			if err != nil {
				return nil, err
			}
			header := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
			last := header&1 != 0
			blockSize := int64(header >> 3)
			switch (header >> 1) & 3 {
			case 0, 2: // Raw_Block and Compressed_Block store Block_Size bytes
				err = s.skip(blockSize)
			case 1: // RLE_Block stores a single byte
				err = s.skip(1)
			default:
				err = fmt.Errorf("reserved block type at offset %d", s.pos-3)
			}
			if err != nil {
				return nil, err
			}
			if last {
				break
			}
		}
		if hasChecksum {
			if err := s.skip(4); err != nil {
				return nil, err
			}
		}
		frames = append(frames, zstdFrame{Offset: start, Length: s.pos - start, ContentSize: contentSize})
	}
	return frames, nil
}

// compressMultiFrame reads r to EOF and writes a zstd stream of independent
// frames to w, cutting the input every chunkSize bytes and compressing the
// pieces concurrently.
//
// Both the chunks waiting to be compressed and the compressed output waiting to
// be written are bounded by the worker count, so peak memory does not track the
// size of the package.
func compressMultiFrame(r io.Reader, w io.Writer, chunkSize int64, workers int) error {
	if chunkSize < 1 {
		chunkSize = zstdFrameChunkSize
	}
	if workers < 1 {
		workers = 1
	}

	type piece struct {
		out  []byte
		err  error
		buf  []byte
		done chan struct{}
	}

	// Input buffers are recycled: a fresh chunk-sized allocation per piece makes
	// the kernel zero a whole package worth of pages. The slots start empty and
	// are filled on demand, so a package that fits in one chunk -- most of the
	// repository -- only ever allocates one.
	free := make(chan []byte, workers+1)
	for i := 0; i <= workers; i++ {
		free <- nil
	}

	// A bounded queue of in-order pieces. Sending blocks once `workers` pieces
	// are outstanding, which is what caps memory.
	queue := make(chan *piece, workers)
	readDone := make(chan error, 1)

	go func() {
		defer close(queue)
		for {
			buf := <-free
			if buf == nil {
				buf = make([]byte, chunkSize)
			}
			n, err := io.ReadFull(r, buf)
			if n > 0 {
				p := &piece{buf: buf, done: make(chan struct{})}
				queue <- p
				go func(p *piece, data []byte) {
					defer close(p.done)
					// --stream-size records the decompressed length in the
					// frame header, letting the installer preallocate exactly.
					cmd := exec.Command("zstd", zstdPackLevel, zstdPackWindow, "-T1", "-c", "-q",
						"--stream-size="+strconv.Itoa(len(data)))
					cmd.Stdin = newByteReader(data)
					cmd.Stderr = os.Stderr
					p.out, p.err = cmd.Output()
				}(p, buf[:n])
			} else {
				free <- buf
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				readDone <- nil
				return
			}
			if err != nil {
				readDone <- err
				return
			}
		}
	}()

	var writeErr error
	for p := range queue {
		<-p.done
		if writeErr == nil {
			if p.err != nil {
				writeErr = fmt.Errorf("zstd compression failed: %w", p.err)
			} else if _, err := w.Write(p.out); err != nil {
				writeErr = err
			}
		}
		p.out = nil
		free <- p.buf
	}
	if err := <-readDone; err != nil && writeErr == nil {
		writeErr = err
	}
	return writeErr
}

// frameBuffer is a reusable pair of buffers for one in-flight frame.
type frameBuffer struct {
	in  []byte
	out []byte
}

// Write appends decoder output, growing only if the frame header understated
// the decompressed size.
func (f *frameBuffer) Write(p []byte) (int, error) {
	f.out = append(f.out, p...)
	return len(p), nil
}

// decompressMultiFrame decodes every frame of the archive at path and writes
// the concatenated result to w.
//
// In-flight decodes are bounded by granting each frame an explicit permit: the
// first `workers` permits are issued up front, and the consumer issues the next
// only once it has written a frame. Handing out permits strictly in frame order
// is what keeps this deadlock free -- with a plain counting semaphore a later
// frame can claim the last slot while the consumer is still waiting on an
// earlier frame that is then never able to start.
//
// Buffers are pooled rather than allocated per frame. That is not a micro
// optimisation: a fresh 64 MiB buffer per frame makes the kernel zero one
// 1.6 GB package worth of pages, which on a Pi 4 costs several times more than
// the parallel decode saves.
func decompressMultiFrame(path string, frames []zstdFrame, w io.Writer, workers int) error {
	if workers < 1 {
		workers = 1
	}
	if workers > len(frames) {
		workers = len(frames)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var maxIn, maxOut int64
	for _, fr := range frames {
		if fr.Length > maxIn {
			maxIn = fr.Length
		}
		if fr.ContentSize > maxOut {
			maxOut = fr.ContentSize
		}
	}
	if maxOut <= 0 {
		// Packed by something that did not record decompressed sizes; start at
		// the chunk size and let the buffer grow if it turns out to be short.
		maxOut = zstdFrameChunkSize
	}

	pool := make(chan *frameBuffer, workers)
	for i := 0; i < workers; i++ {
		pool <- &frameBuffer{in: make([]byte, maxIn), out: make([]byte, 0, maxOut)}
	}

	type result struct {
		buf *frameBuffer
		err error
	}
	results := make([]chan result, len(frames))
	permits := make([]chan struct{}, len(frames))
	for i := range frames {
		results[i] = make(chan result, 1)
		permits[i] = make(chan struct{}, 1)
	}
	for i := 0; i < workers; i++ {
		permits[i] <- struct{}{}
	}

	for i, fr := range frames {
		go func(i int, fr zstdFrame) {
			<-permits[i]
			buf := <-pool
			src := buf.in[:fr.Length]
			if _, err := f.ReadAt(src, fr.Offset); err != nil {
				results[i] <- result{buf: buf, err: err}
				return
			}
			buf.out = buf.out[:0]
			cmd := exec.Command("zstd", "-d", zstdPackWindow, "-c", "-q")
			cmd.Stdin = newByteReader(src)
			cmd.Stdout = buf
			cmd.Stderr = os.Stderr
			results[i] <- result{buf: buf, err: cmd.Run()}
		}(i, fr)
	}

	for i := range frames {
		r := <-results[i]
		if r.err != nil {
			return fmt.Errorf("decompressing frame %d of %s: %w", i, path, r.err)
		}
		_, err := w.Write(r.buf.out)
		pool <- r.buf
		if next := i + workers; next < len(frames) {
			permits[next] <- struct{}{}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// packageFrames returns the frame layout of a package tarball. A package with a
// single frame gains nothing from the parallel path and is reported as such.
func packageFrames(path string) ([]zstdFrame, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return scanZstdFrames(f, st.Size())
}

// zstdFramesProgram returns the `--use-compress-program` string that makes tar
// pack through hokuto's multi-frame compressor, or "" when that is not
// possible. uncompressedSize is how much tar is about to feed it, which decides
// how the stream is cut into frames; pass 0 when it is unknown. tar splits the string on whitespace, so a path containing spaces
// has to fall back to invoking zstd directly.
func zstdFramesProgram(uncompressedSize int64) string {
	self, err := os.Executable()
	if err != nil {
		debugf("Cannot locate the hokuto binary for multi-frame packing: %v\n", err)
		return ""
	}
	if strings.ContainsAny(self, " \t") {
		debugf("Hokuto binary path %q contains whitespace; packing single-frame\n", self)
		return ""
	}
	if _, err := exec.LookPath("zstd"); err != nil {
		debugf("zstd binary unavailable for multi-frame packing: %v\n", err)
		return ""
	}
	// tar splits this on whitespace, so the argument carries no spaces.
	return fmt.Sprintf("%s __zstd-frames --chunk-size=%d", self, zstdChunkSizeForInput(uncompressedSize))
}

// directoryUncompressedSize totals the regular files under root, which is close
// enough to what tar will produce for choosing a frame size.
func directoryUncompressedSize(root string) int64 {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		debugf("Could not size %s for frame selection: %v\n", root, err)
		return 0
	}
	return total
}

// runZstdFramesFilter implements the __zstd-frames subcommand, the filter tar
// invokes through --use-compress-program. tar calls it with no arguments to
// compress and with -d to decompress.
func runZstdFramesFilter(args []string) error {
	chunk := int64(0)
	for _, a := range args {
		if size, ok := strings.CutPrefix(a, "--chunk-size="); ok {
			parsed, err := strconv.ParseInt(size, 10, 64)
			if err != nil || parsed <= 0 {
				return fmt.Errorf("invalid --chunk-size=%s", size)
			}
			chunk = parsed
			continue
		}
		if a == "-d" || a == "--decompress" || a == "--uncompress" {
			// tar only reaches this path when it drives extraction itself; the
			// installer decodes in parallel without going through tar's filter.
			cmd := exec.Command("zstd", "-d", zstdPackWindow, "-c", "-q")
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
	}
	if chunk <= 0 {
		chunk = zstdChunkSize()
	} else if override, ok := zstdChunkSizeOverride(); ok {
		chunk = override
	}
	return compressMultiFrame(os.Stdin, os.Stdout, chunk, packWorkers(chunk))
}

// errSingleFrameArchive reports that an archive has nothing to gain from the
// parallel unpack path, so the caller should use its ordinary one.
var errSingleFrameArchive = errors.New("archive holds a single zstd frame")

// unpackMultiFrame extracts a package by decoding its frames concurrently and
// streaming the result through tar.
func unpackMultiFrame(tarballPath, stagingDir string, execCtx *Executor) error {
	if _, err := exec.LookPath("zstd"); err != nil {
		return errSingleFrameArchive
	}
	frames, err := packageFrames(tarballPath)
	if err != nil {
		return err
	}
	if len(frames) < 2 {
		return errSingleFrameArchive
	}

	var maxContent int64
	for _, fr := range frames {
		if fr.ContentSize > maxContent {
			maxContent = fr.ContentSize
		}
	}
	if maxContent <= 0 {
		maxContent = zstdFrameChunkSize
	}
	workers := boundedWorkers(zstdUnpackWorkerOverhead + maxContent)

	pr, pw := io.Pipe()
	untarCmd := exec.Command("tar", "-xf", "-", "-C", stagingDir)
	untarCmd.Stdin = pr
	if !Debug {
		untarCmd.Stdout = io.Discard
		untarCmd.Stderr = io.Discard
	}

	decoded := make(chan error, 1)
	go func() {
		err := decompressMultiFrame(tarballPath, frames, pw, workers)
		pw.CloseWithError(err)
		decoded <- err
	}()

	tarErr := execCtx.Run(untarCmd)

	// tar stops at the archive's end-of-file marker and leaves the trailing
	// padding unread, so the decoder can still be blocked on a write nobody is
	// going to consume. Closing the read end releases it.
	pr.CloseWithError(io.ErrClosedPipe)
	decodeErr := <-decoded

	if tarErr != nil {
		return fmt.Errorf("tar failed while extracting %s: %w", tarballPath, tarErr)
	}
	// tar exiting cleanly means it saw a complete archive, so a write that was
	// cut short after that point carried nothing it needed.
	if decodeErr != nil && !errors.Is(decodeErr, io.ErrClosedPipe) {
		return decodeErr
	}
	return nil
}

// newByteReader wraps a slice so it can be handed to exec.Cmd.Stdin without the
// copy an intermediate buffer type would add.
func newByteReader(b []byte) io.Reader { return &byteSliceReader{data: b} }

type byteSliceReader struct {
	data []byte
	pos  int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
