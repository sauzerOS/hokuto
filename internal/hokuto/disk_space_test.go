package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withFakeFreeSpace(t *testing.T, devices map[string]uint64, avail map[uint64]int64) {
	t.Helper()
	oldFree, oldBin, oldRoot := freeSpaceOf, BinDir, rootDir
	base := t.TempDir()
	BinDir = filepath.Join(base, "cache", "bin")
	rootDir = filepath.Join(base, "root")
	for _, dir := range []string{BinDir, filepath.Join(rootDir, "usr")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	freeSpaceOf = func(path string) (uint64, int64, error) {
		for prefix, dev := range devices {
			if strings.HasPrefix(path, filepath.Join(base, prefix)) {
				return dev, avail[dev], nil
			}
		}
		return 99, avail[99], nil
	}
	t.Cleanup(func() { freeSpaceOf, BinDir, rootDir = oldFree, oldBin, oldRoot })
}

func TestCheckFreeSpaceSeparateFilesystems(t *testing.T) {
	withFakeFreeSpace(t, map[string]uint64{"cache": 1, "root": 2}, map[uint64]int64{1: 200 << 20, 2: 100 << 20})
	if err := checkFreeSpace(150<<20, 50<<20); err != nil {
		t.Fatalf("plan that fits refused: %v", err)
	}
	err := checkFreeSpace(150<<20, 90<<20)
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root overflow not reported: %v", err)
	}
}

func TestCheckFreeSpaceSharedFilesystemAddsUp(t *testing.T) {
	withFakeFreeSpace(t, map[string]uint64{"cache": 1, "root": 1}, map[uint64]int64{1: 200 << 20})
	if err := checkFreeSpace(100<<20, 60<<20); err != nil {
		t.Fatalf("plan that fits refused: %v", err)
	}
	if err := checkFreeSpace(100<<20, 90<<20); err == nil {
		t.Fatal("download and install on one filesystem were not added up")
	}
}

func TestCheckFreeSpaceShrinkingUpdate(t *testing.T) {
	withFakeFreeSpace(t, map[string]uint64{"cache": 1, "root": 2}, map[uint64]int64{1: 1 << 30, 2: 0})
	if err := checkFreeSpace(10<<20, -50<<20); err != nil {
		t.Fatalf("an update that frees space was refused: %v", err)
	}
}
