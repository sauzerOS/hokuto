package hokuto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCMakeToolchainFile(t *testing.T) {
	dir := t.TempDir()
	path, err := writeCMakeToolchainFile(dir, "aarch64")
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	// The find-root settings are the point: without them CMake searches the
	// build machine and links host libraries into target binaries.
	for _, want := range []string{
		"set(CMAKE_SYSTEM_NAME Linux)",
		"set(CMAKE_SYSTEM_PROCESSOR aarch64)",
		"set(CMAKE_C_COMPILER   aarch64-linux-gnu-gcc)",
		"set(CMAKE_SYSROOT /usr/aarch64-linux-gnu)",
		"set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)",
		"set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)",
		"set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)",
		"set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)",
		"set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)",
		"set(PKG_CONFIG_EXECUTABLE aarch64-linux-gnu-pkg-config)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("toolchain file missing %q", want)
		}
	}
	if filepath.Dir(path) != dir {
		t.Errorf("written outside the helper dir: %s", path)
	}
}

func TestApplyCMakeCrossToolchain(t *testing.T) {
	t.Run("sets the variable for a cross build", func(t *testing.T) {
		dir := t.TempDir()
		env := map[string]string{"HOKUTO_CROSS": "1", "HOKUTO_ARCH": "aarch64"}
		if err := applyCMakeCrossToolchain(env, dir); err != nil {
			t.Fatal(err)
		}
		if env["CMAKE_TOOLCHAIN_FILE"] == "" {
			t.Fatal("CMAKE_TOOLCHAIN_FILE not set")
		}
		if _, err := os.Stat(env["CMAKE_TOOLCHAIN_FILE"]); err != nil {
			t.Fatalf("file not created: %v", err)
		}
	})

	t.Run("native build is untouched", func(t *testing.T) {
		dir := t.TempDir()
		env := map[string]string{"HOKUTO_ARCH": "x86_64"}
		if err := applyCMakeCrossToolchain(env, dir); err != nil {
			t.Fatal(err)
		}
		if env["CMAKE_TOOLCHAIN_FILE"] != "" {
			t.Error("a native build must not get a cross toolchain file")
		}
	})

	t.Run("a recipe's own toolchain file wins", func(t *testing.T) {
		dir := t.TempDir()
		env := map[string]string{
			"HOKUTO_CROSS": "1", "HOKUTO_ARCH": "aarch64",
			"CMAKE_TOOLCHAIN_FILE": "/recipe/own.cmake",
		}
		if err := applyCMakeCrossToolchain(env, dir); err != nil {
			t.Fatal(err)
		}
		if env["CMAKE_TOOLCHAIN_FILE"] != "/recipe/own.cmake" {
			t.Errorf("overrode the recipe's choice: %s", env["CMAKE_TOOLCHAIN_FILE"])
		}
	})
}
