package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// A cross build compiles Python extensions with the host's python, which
// names them for the host: btrfsutil.cpython-315-x86_64-linux-gnu.so on the
// Pi, where python looks for aarch64 names and finds none. Pointed at the
// target's sysconfig data (shipped by aarch64-python), python reports the
// target's EXT_SUFFIX and SOABI. setuptools takes the stable-ABI suffix from
// the running interpreter instead (importlib.machinery.EXTENSION_SUFFIXES),
// which python 3.15 made per platform (.abi3-x86_64-linux-gnu.so):
// crossPythonSiteCustomize rewrites that list for the target.

// crossPythonSiteCustomize runs in every python of a cross build that is
// pointed at the target's sysconfig data. The target's suffixes go before the
// host's, so setuptools takes them; the import machinery shares the list, so
// the host's stay for python to import its own modules.
const crossPythonSiteCustomize = `# hokuto: name extensions built here for the cross target.
import os

def _hokuto_target_suffixes():
    name = os.environ.get("_PYTHON_SYSCONFIGDATA_NAME")
    if not name or not os.environ.get("_PYTHON_HOST_PLATFORM"):
        return
    import importlib
    import importlib.machinery
    import sys
    target = importlib.import_module(name).build_time_vars.get("MULTIARCH")
    own = getattr(sys.implementation, "_multiarch", "")
    if not target or not own or target == own:
        return
    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    targets = [s.replace(own, target) for s in suffixes if own in s]
    suffixes[:0] = [s for s in targets if s not in suffixes]

try:
    _hokuto_target_suffixes()
except Exception:
    pass
`

// setCrossPythonEnv points the python of a cross build of pkgName at the
// target's sysconfig data, when the sysroot has a python of the host's minor
// release: its module is linked into a directory of the build, rather than
// putting the target's standard library before the host's. Python itself is
// left alone: its build generates that data.
func setCrossPythonEnv(env map[string]string, pkgName, sysrootPrefix, arch, buildDir string) error {
	if strings.TrimPrefix(pkgName, arch+"-") == pythonRecipe {
		return nil
	}
	pyDir := targetPythonDirName(sysrootPrefix)
	module := "_sysconfigdata__linux_" + arch + "-linux-gnu"
	data := filepath.Join(sysrootPrefix, "lib", pyDir, module+".py")
	if _, err := os.Stat(data); err != nil {
		return nil
	}
	out, err := exec.Command("python3", "-c", "import sys; print(f'python3.{sys.version_info.minor}')").Output()
	if err != nil || strings.TrimSpace(string(out)) != pyDir {
		return nil // a host python of another release cannot use that data
	}

	dir := filepath.Join(buildDir, ".hokuto-tools", "python")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "sitecustomize.py"), []byte(crossPythonSiteCustomize), 0o644); err != nil {
		return err
	}
	link := filepath.Join(dir, module+".py")
	_ = os.Remove(link)
	if err := os.Symlink(data, link); err != nil {
		return fmt.Errorf("failed to link the target's sysconfig data: %w", err)
	}

	env["_PYTHON_SYSCONFIGDATA_NAME"] = module
	env["_PYTHON_HOST_PLATFORM"] = "linux-" + arch
	if existing := env["PYTHONPATH"]; existing != "" {
		env["PYTHONPATH"] = dir + ":" + existing
	} else {
		env["PYTHONPATH"] = dir
	}
	return nil
}
