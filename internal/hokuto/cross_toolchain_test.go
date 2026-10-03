package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func resetCrossToolchainPairs(t *testing.T) {
	t.Helper()
	clear := func() {
		crossToolchainPairs.Range(func(key, _ any) bool {
			crossToolchainPairs.Delete(key)
			return true
		})
	}
	clear()
	t.Cleanup(clear)
}

func TestNoteCrossToolchainPairs(t *testing.T) {
	resetCrossToolchainPairs(t)
	deps := []DepSpec{
		{Name: "rust", Make: true, Cross: true},
		{Name: "aarch64-rust", Make: true, Cross: true},
		{Name: "cmake", Make: true, Cross: true},
		{Name: "aarch64-glibc", Cross: true},
		// A plain native line is no host tool of the cross build.
		{Name: "glibc"},
	}

	noteCrossToolchainPairs(deps, &Config{Values: map[string]string{}})
	if _, ok := crossToolchainPairs.Load("aarch64-rust"); ok {
		t.Fatal("a native session recorded a cross toolchain pair")
	}

	noteCrossToolchainPairs(deps, &Config{Values: map[string]string{"HOKUTO_CROSS_ARCH": "arm64"}})
	if native, ok := crossToolchainPairs.Load("aarch64-rust"); !ok || native != "rust" {
		t.Fatalf("aarch64-rust pair = %v, %v; want rust", native, ok)
	}
	if _, ok := crossToolchainPairs.Load("aarch64-glibc"); ok {
		t.Fatal("aarch64-glibc paired although glibc is no host tool of this build")
	}
}

// An older binary of a paired package qualifies only at its host tool's
// version (rustc loads only its own standard library). Plain names stand in
// for aarch64-rust and rust here.
func TestOlderBuildDependencyMustMatchPairedHostTool(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	resetCrossToolchainPairs(t)
	writeTestPackage(t, repo, "rust-std", "")
	if err := os.WriteFile(filepath.Join(repo, "rust-std", "version"), []byte("1.99.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(BinDir, StandardizeRemoteName("rust-std", "1.98.1", "1", "x86_64", "optimized"))
	writeTestBinaryTarball(t, older, "rust-std", "1.98.1", "1")
	setNativeVersion := func(version string) {
		t.Helper()
		dir := filepath.Join(Installed, "rustc")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "version"), []byte(version+" 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Unpaired, the newest older binary is used as before.
	if _, got, ok, err := availableBuildDependencyBinaryTarball("rust-std", cfg, true); err != nil || !ok || got != older {
		t.Fatalf("unpaired: got %q, %v, %v; want the older binary", got, ok, err)
	}

	crossToolchainPairs.Store("rust-std", "rustc")
	setNativeVersion("1.99.0")
	if _, got, ok, err := availableBuildDependencyBinaryTarball("rust-std", cfg, true); err != nil || ok {
		t.Fatalf("host tool 1.99.0: got %q, %v, %v; want no binary (build it)", got, ok, err)
	}

	setNativeVersion("1.98.1")
	if _, got, ok, err := availableBuildDependencyBinaryTarball("rust-std", cfg, true); err != nil || !ok || got != older {
		t.Fatalf("host tool 1.98.1: got %q, %v, %v; want the matching older binary", got, ok, err)
	}
}
