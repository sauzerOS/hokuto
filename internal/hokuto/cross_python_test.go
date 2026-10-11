package hokuto

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetCrossPythonEnvUsesTheTargetSysconfig(t *testing.T) {
	out, err := exec.Command("python3", "-c", "import sys; print(f'python3.{sys.version_info.minor}')").Output()
	if err != nil {
		t.Skip("no host python3")
	}
	pyDir := strings.TrimSpace(string(out))
	sysroot := t.TempDir()
	data := filepath.Join(sysroot, "lib", pyDir, "_sysconfigdata__linux_aarch64-linux-gnu.py")

	buildDir := t.TempDir()
	env := map[string]string{"PYTHONPATH": "/sysroot/site-packages"}
	if err := setCrossPythonEnv(env, "python-protobuf", sysroot, "aarch64", buildDir); err != nil {
		t.Fatal(err)
	}
	if env["_PYTHON_SYSCONFIGDATA_NAME"] != "" {
		t.Fatalf("without the target's sysconfig data nothing changes: %v", env)
	}

	if err := os.MkdirAll(filepath.Dir(data), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(data, []byte("build_time_vars = {'MULTIARCH': 'aarch64-linux-gnu'}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setCrossPythonEnv(env, "python-protobuf", sysroot, "aarch64", buildDir); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(buildDir, ".hokuto-tools", "python")
	if env["_PYTHON_SYSCONFIGDATA_NAME"] != "_sysconfigdata__linux_aarch64-linux-gnu" || env["_PYTHON_HOST_PLATFORM"] != "linux-aarch64" {
		t.Fatalf("the target's sysconfig data must be used: %v", env)
	}
	if env["PYTHONPATH"] != dir+":/sysroot/site-packages" {
		t.Fatalf("the helper directory must come first, keeping the rest: %q", env["PYTHONPATH"])
	}
	if target, err := os.Readlink(filepath.Join(dir, "_sysconfigdata__linux_aarch64-linux-gnu.py")); err != nil || target != data {
		t.Fatalf("the target's sysconfig module must be linked, not its standard library: %q %v", target, err)
	}

	// In the build's python, setuptools names stable-ABI extensions for the
	// target, and the host still imports its own.
	cmd := exec.Command("python3", "-c", `
import importlib.machinery, zlib
print(importlib.machinery.EXTENSION_SUFFIXES[0])
print(next(s for s in importlib.machinery.EXTENSION_SUFFIXES if ".abi3" in s))`)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+env["PYTHONPATH"], "_PYTHON_SYSCONFIGDATA_NAME="+env["_PYTHON_SYSCONFIGDATA_NAME"], "_PYTHON_HOST_PLATFORM="+env["_PYTHON_HOST_PLATFORM"])
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python with the cross environment failed: %v\n%s", err, got)
	}
	if !strings.Contains(string(got), "aarch64-linux-gnu") {
		t.Fatalf("the target's extension suffixes must come first:\n%s", got)
	}

	// Python's own build makes that data.
	pyEnv := map[string]string{}
	if err := setCrossPythonEnv(pyEnv, "aarch64-python", sysroot, "aarch64", t.TempDir()); err != nil || len(pyEnv) != 0 {
		t.Fatalf("python itself must be left alone: %v %v", pyEnv, err)
	}
}
