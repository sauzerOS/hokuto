package hokuto

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestScanLocalBinariesUsesCacheAndKeepsOrder(t *testing.T) {
	dir := t.TempDir()
	var files []string
	cache := make(map[string]uploadCacheEntry)
	for i, name := range []string{"a.tar.zst", "broken.tar.zst", "c.tar.zst"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("not a package"), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
		if name == "broken.tar.zst" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		cache[name] = uploadCacheEntry{
			Size:  info.Size(),
			Mtime: info.ModTime(),
			Entry: RepoEntry{Name: name, Version: "1", Revision: strconv.Itoa(i), MetadataVersion: repoEntryMetadataVersion},
		}
	}

	results := scanLocalBinaries(files, cache)
	if len(results) != len(files) {
		t.Fatalf("got %d results for %d files", len(results), len(files))
	}
	for i, result := range results {
		name := filepath.Base(files[i])
		if result.file != files[i] {
			t.Errorf("result %d is for %s, want %s", i, result.file, files[i])
		}
		if name == "broken.tar.zst" {
			if result.ok {
				t.Errorf("unreadable archive should be skipped, got %+v", result.entry)
			}
			continue
		}
		if !result.ok || result.fresh || result.entry.Name != name {
			t.Errorf("%s: want cached entry, got ok=%v fresh=%v entry=%+v", name, result.ok, result.fresh, result.entry)
		}
	}
}

func TestRemoveUploadedLocalBinariesKeepsPackagesNotOnRemote(t *testing.T) {
	tmp := t.TempDir()
	oldBinDir, oldRootDir, oldCacheDir := BinDir, rootDir, CacheDir
	BinDir = filepath.Join(tmp, "bin")
	CacheDir = tmp
	// Build sessions are tracked per root; a fresh root has none.
	rootDir = filepath.Join(tmp, "root")
	t.Cleanup(func() { BinDir, rootDir, CacheDir = oldBinDir, oldRootDir, oldCacheDir })
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		t.Fatal(err)
	}

	locals := map[string]RepoEntry{
		"uploaded": {Filename: "uploaded.tar.zst", B3Sum: "aaa"},
		"fetched":  {Filename: "fetched.tar.zst", B3Sum: "bbb"},
		"declined": {Filename: "declined.tar.zst", B3Sum: "ccc"},
		"changed":  {Filename: "changed.tar.zst", B3Sum: "ddd"},
	}
	remote := map[string]RepoEntry{
		"uploaded": {Filename: "uploaded.tar.zst", B3Sum: "aaa"},
		"fetched":  {Filename: "fetched.tar.zst", B3Sum: "bbb"},
		// Same package on the remote, but not this exact file.
		"changed": {Filename: "changed.tar.zst", B3Sum: "eee"},
	}
	seed := make(map[string]uploadCacheEntry)
	for _, local := range locals {
		if err := os.WriteFile(filepath.Join(BinDir, local.Filename), []byte("pkg"), 0o644); err != nil {
			t.Fatal(err)
		}
		seed[local.Filename] = uploadCacheEntry{}
	}
	if err := updateUploadCache(seed, nil); err != nil {
		t.Fatal(err)
	}

	removeUploadedLocalBinaries(locals, remote)
	cache := loadUploadCache(uploadCachePath())

	for name, wantKept := range map[string]bool{
		"uploaded.tar.zst": false,
		"fetched.tar.zst":  false,
		"declined.tar.zst": true,
		"changed.tar.zst":  true,
	} {
		_, err := os.Stat(filepath.Join(BinDir, name))
		if kept := err == nil; kept != wantKept {
			t.Errorf("%s kept = %v, want %v", name, kept, wantKept)
		}
		if _, cached := cache[name]; cached != wantKept {
			t.Errorf("%s still in upload cache = %v, want %v", name, cached, wantKept)
		}
	}
}

func TestCreatePackageTarballRecordsSameMetadataAsArchiveScan(t *testing.T) {
	tmp := t.TempDir()
	oldBinDir, oldCacheDir := BinDir, CacheDir
	BinDir = filepath.Join(tmp, "bin")
	CacheDir = tmp
	t.Cleanup(func() { BinDir, CacheDir = oldBinDir, oldCacheDir })

	outputDir := filepath.Join(tmp, "out")
	metaDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", "demo")
	for path, content := range map[string]string{
		filepath.Join(outputDir, "usr", "bin", "demo"): "#!/bin/sh\n",
		filepath.Join(metaDir, "pkginfo"):              "name=demo\nversion=1.2\nrevision=3\narch=x86_64\ngeneric=1\nmultilib=0\n",
		filepath.Join(metaDir, "depends"):              "glibc\nzlib-ng>=2.0\ncmake make\nfoo | bar\nlua optional\n",
		filepath.Join(metaDir, "libdeps"):              "elf64:libc.so.6\nelf64:libz.so.1\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// With tar on PATH, hokuto packs through its own binary as a zstd filter,
	// which under go test is this test binary. Use the built-in tar+zstd.
	t.Setenv("PATH", filepath.Join(tmp, "no-tools"))

	execCtx := &Executor{Context: context.Background()}
	if err := createPackageTarball("demo", "1.2", "3", "x86_64", "generic", outputDir, execCtx, io.Discard); err != nil {
		t.Fatal(err)
	}
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName("demo", "1.2", "3", "x86_64", "generic"))

	cached, ok := loadUploadCache(uploadCachePath())[filepath.Base(tarballPath)]
	if !ok {
		t.Fatal("createPackageTarball did not record the new package for upload")
	}
	scanned, err := ReadPackageMetadata(tarballPath)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(cached.Entry)
	want, _ := json.Marshal(scanned)
	if string(got) != string(want) {
		t.Fatalf("recorded entry differs from the archive scan:\n got %s\nwant %s", got, want)
	}

	// upload must then take it from the cache instead of reading the archive.
	results := scanLocalBinaries([]string{tarballPath}, loadUploadCache(uploadCachePath()))
	if !results[0].ok || results[0].fresh {
		t.Fatalf("expected a cache hit for the new package, got ok=%v fresh=%v", results[0].ok, results[0].fresh)
	}
}

func TestRecordFetchedUploadCacheEntryUsesVerifiedIndexEntry(t *testing.T) {
	tmp := t.TempDir()
	oldCacheDir := CacheDir
	CacheDir = tmp
	GlobalRemoteIndexMu.Lock()
	oldIndex, oldLoaded := GlobalRemoteIndex, GlobalRemoteIndexLoaded
	GlobalRemoteIndexMu.Unlock()
	t.Cleanup(func() {
		CacheDir = oldCacheDir
		GlobalRemoteIndexMu.Lock()
		GlobalRemoteIndex, GlobalRemoteIndexLoaded = oldIndex, oldLoaded
		GlobalRemoteIndexMu.Unlock()
	})

	path := filepath.Join(tmp, "zlib-ng-2.3.3-2-x86_64-optimized.tar.zst")
	if err := os.WriteFile(path, []byte("package"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := RepoEntry{
		Name: "zlib-ng", Version: "2.3.3", Revision: "2", Filename: filepath.Base(path),
		Size: int64(len("package")), B3Sum: "sum", MetadataVersion: repoEntryMetadataVersion,
	}
	GlobalRemoteIndexMu.Lock()
	GlobalRemoteIndex, GlobalRemoteIndexLoaded = []RepoEntry{entry}, true
	GlobalRemoteIndexMu.Unlock()

	recordFetchedUploadCacheEntry(path, "other-sum")
	if _, ok := loadUploadCache(uploadCachePath())[entry.Filename]; ok {
		t.Fatal("an entry whose checksum does not match the fetched file must not be recorded")
	}
	recordFetchedUploadCacheEntry(path, "sum")
	if got := loadUploadCache(uploadCachePath())[entry.Filename]; got.Entry.Name != "zlib-ng" {
		t.Fatalf("fetched package was not recorded, got %+v", got)
	}
}
