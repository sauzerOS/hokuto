package hokuto

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func withFetchedBinariesTestEnv(t *testing.T) (mirrorDir string) {
	t.Helper()
	tmp := t.TempDir()
	mirrorDir = filepath.Join(tmp, "mirror")
	if err := os.MkdirAll(mirrorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(mirrorDir)))
	t.Cleanup(server.Close)

	oldBinDir, oldCacheDir, oldRootDir, oldMirror := BinDir, CacheDir, rootDir, BinaryMirror
	BinDir = filepath.Join(tmp, "bin")
	CacheDir = tmp
	rootDir = filepath.Join(tmp, "root") // no other build sessions
	BinaryMirror = server.URL
	fetchedBinaries.Lock()
	oldPaths, oldKeep := fetchedBinaries.paths, fetchedBinaries.keep
	fetchedBinaries.paths, fetchedBinaries.keep = make(map[string]bool), false
	fetchedBinaries.Unlock()
	t.Cleanup(func() {
		BinDir, CacheDir, rootDir, BinaryMirror = oldBinDir, oldCacheDir, oldRootDir, oldMirror
		fetchedBinaries.Lock()
		fetchedBinaries.paths, fetchedBinaries.keep = oldPaths, oldKeep
		fetchedBinaries.Unlock()
	})
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return mirrorDir
}

func publishTestPackage(t *testing.T, mirrorDir, name string, cfg *Config) (filename, sum string) {
	t.Helper()
	filename = StandardizeRemoteName(name, "1.0", "1", GetSystemArchForPackage(cfg, name), "generic")
	path := filepath.Join(mirrorDir, filename)
	if err := os.WriteFile(path, []byte("package "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := ComputeChecksum(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return filename, sum
}

func TestFetchedBinariesAreRemovedButPreexistingOnesKept(t *testing.T) {
	mirrorDir := withFetchedBinariesTestEnv(t)
	cfg := &Config{Values: map[string]string{"HOKUTO_ARCH": "x86_64"}}

	fetched, fetchedSum := publishTestPackage(t, mirrorDir, "fetched", cfg)
	local, localSum := publishTestPackage(t, mirrorDir, "local", cfg)
	// "local" is already in the binary cache, e.g. a package built here.
	if err := os.WriteFile(filepath.Join(BinDir, local), []byte("package local"), 0o644); err != nil {
		t.Fatal(err)
	}

	for name, sum := range map[string]string{"fetched": fetchedSum, "local": localSum} {
		if err := fetchSpecificBinaryPackage(name, "1.0", "1", "generic", cfg, true, sum, false); err != nil {
			t.Fatalf("fetch %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(BinDir, fetched)); err != nil {
		t.Fatalf("fetched package was not downloaded: %v", err)
	}

	removeFetchedBinaries()
	if _, err := os.Stat(filepath.Join(BinDir, fetched)); !os.IsNotExist(err) {
		t.Errorf("package downloaded by this run should be removed at exit, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(BinDir, local)); err != nil {
		t.Errorf("package that was already in the binary cache must be kept: %v", err)
	}
}

func TestKeepFetchedBinariesLeavesDownloads(t *testing.T) {
	mirrorDir := withFetchedBinariesTestEnv(t)
	cfg := &Config{Values: map[string]string{"HOKUTO_ARCH": "x86_64"}}
	filename, sum := publishTestPackage(t, mirrorDir, "wanted", cfg)

	keepFetchedBinaries()
	if err := fetchSpecificBinaryPackage("wanted", "1.0", "1", "generic", cfg, true, sum, false); err != nil {
		t.Fatal(err)
	}
	removeFetchedBinaries()
	if _, err := os.Stat(filepath.Join(BinDir, filename)); err != nil {
		t.Fatalf("hokuto fetch downloads must be kept: %v", err)
	}
}

// A build dependency can pull the mirror's copy of the very package being
// rebuilt (aarch64-glycin needs aarch64-librsvg, which needs
// aarch64-gdk-pixbuf). The build then writes its package over that download,
// and the new package must survive the cleanup of this run's downloads.
func TestBuiltPackageOverDownloadIsKept(t *testing.T) {
	mirrorDir := withFetchedBinariesTestEnv(t)
	cfg := &Config{Values: map[string]string{"HOKUTO_ARCH": "x86_64"}}
	filename, sum := publishTestPackage(t, mirrorDir, "rebuilt", cfg)
	if err := fetchSpecificBinaryPackage("rebuilt", "1.0", "1", "generic", cfg, true, sum, false); err != nil {
		t.Fatal(err)
	}

	outputDir := filepath.Join(t.TempDir(), "out")
	if err := os.MkdirAll(filepath.Join(outputDir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "usr", "bin", "rebuilt"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Use the built-in tar+zstd rather than this test binary as a filter.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "no-tools"))
	if err := createPackageTarball("rebuilt", "1.0", "1", "x86_64", "generic", outputDir, &Executor{Context: context.Background(), Stdout: io.Discard, Stderr: io.Discard}, io.Discard); err != nil {
		t.Fatal(err)
	}

	removeFetchedBinaries()
	path := filepath.Join(BinDir, filename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the package built over a download was removed: %v", err)
	}
	if got, _ := ComputeChecksum(path, nil); got == sum {
		t.Fatal("the binary cache holds the mirror's copy, not the build")
	}
}
