package hokuto

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A Python minor upgrade (3.14 -> 3.15) moves site-packages to a new
// directory and changes the extension ABI, so every package that installs
// Python modules or links libpython has to be rebuilt, and how many of them
// build against the new release is only known by trying. The build server
// therefore holds the upgrade back until they have been tried:
//
//	a publishing build of python with a new minor version records the
//	upgrade (python-upgrade.json in HOKUTO_CACHE_DIR) instead of bumping
//	the libpython consumers, keeps its new package off the mirror, and
//	posts a notice on the website; rebuild and cross-sync leave python
//	alone while the upgrade waits
//
//	hokuto python-rebuild check     in a throwaway copy of the build
//	                                container (hokuto-builder python-rebuild
//	                                --check): build and install the new
//	                                python, build every package that needs
//	                                the rebuild against it, report the result
//	hokuto python-rebuild confirm   once all of them built: bump their
//	                                revisions, commit and push, and release
//	                                python; the next rebuild round publishes
//	                                python together with the rebuilt packages
//
// The test builds are thrown away: they keep the published revision, and
// publishing them would hand new-Python packages to systems that run the old
// Python.

// pythonRebuildOption marks a recipe whose packages install files under a
// versioned lib/python3.X directory or link libpython3.X.
const pythonRebuildOption = "python-rebuild"

// pythonVersionedDir matches a path inside a versioned Python directory,
// native, lib32 or in a cross sysroot: /usr/lib/python3.14/...,
// /usr/aarch64-linux-gnu/lib/python3.14/...
var pythonVersionedDir = regexp.MustCompile(`/lib(?:32)?/python3\.\d+/`)

// pythonBootstrapPackages build every other Python package: build, installer
// and flit-core are what `python -m build` / `python -m installer` run, and
// meson builds the C/C++ packages. After a minor upgrade the new interpreter
// does not see their installed copies, so they are built first, against
// their old copies (see pythonBootstrapPath), and installed.
var pythonBootstrapPackages = []string{
	"python-flit-core", "python-installer", "python-packaging", "python-pyproject-hooks",
	"python-build", "python-wheel", "python-setuptools", "meson",
}

// findPythonVersionedFile returns the first file of a staged package that
// needs a Python rebuild: one under a versioned Python directory, or "" when
// there is none. libdepsFile, when it exists, also counts a libpython link.
func findPythonVersionedFile(outputDir, libdepsFile string) string {
	var patterns []string
	for _, lib := range []string{"usr/lib", "usr/lib32", "usr/*-linux-gnu/lib"} {
		patterns = append(patterns, filepath.Join(outputDir, lib, "python3.*"))
	}
	for _, pattern := range patterns {
		dirs, _ := filepath.Glob(pattern)
		for _, dir := range dirs {
			found := ""
			_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err != nil || found != "" {
					return filepath.SkipAll
				}
				if !d.IsDir() {
					found = "/" + strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(path, outputDir)), "/")
					return filepath.SkipAll
				}
				return nil
			})
			if found != "" {
				return found
			}
		}
	}
	if found := findCPythonExtension(outputDir); found != "" {
		return found
	}
	if data, err := os.ReadFile(libdepsFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "libpython3") {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

// cpythonExtension matches an extension module built for one CPython
// release: _giscanner.cpython-314-x86_64-linux-gnu.so.
var cpythonExtension = regexp.MustCompile(`\.cpython-3\d+-[^/]*\.so$`)

// findCPythonExtension returns the first extension module of a staged
// package tied to a CPython release outside the versioned directories
// (gobject-introspection's giscanner lives in /usr/lib/gobject-introspection).
func findCPythonExtension(outputDir string) string {
	found := ""
	_ = filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found != "" {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Name() == "hokuto" && strings.HasSuffix(filepath.Dir(path), filepath.Join("var", "db")) {
				return filepath.SkipDir
			}
			return nil
		}
		if cpythonExtension.MatchString(d.Name()) {
			found = "/" + strings.TrimPrefix(filepath.ToSlash(strings.TrimPrefix(path, outputDir)), "/")
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// warnMissingPythonRebuildOption points at recipes that install Python
// modules without python-rebuild, which a Python upgrade would miss.
// sourcePkgName is the recipe; the interpreter itself is the upgrade.
func warnMissingPythonRebuildOption(sourcePkgName, pkgName, outputDir string, options map[string]bool, logger io.Writer) {
	// A binary recipe bundles its own Python (sublime-text) and is not rebuilt.
	if options[pythonRebuildOption] || options["binary"] || sourcePkgName == "python" {
		return
	}
	libdeps := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName, "libdeps")
	file := findPythonVersionedFile(outputDir, libdeps)
	if file == "" {
		return
	}
	fmt.Fprintln(logger, colWarn.Sprintf("Warning: %s installs Python modules or links libpython (%s) but the options file of %s lacks %q; hokuto python-rebuild won't include it.",
		pkgName, file, sourcePkgName, pythonRebuildOption))
}

// currentPythonMinor asks the installed interpreter for its version: "3.15".
func currentPythonMinor() (string, error) {
	out, err := exec.Command("python3", "-c", `import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")`).Output()
	if err != nil {
		return "", fmt.Errorf("python3 not usable: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

var sitePackagesEntry = regexp.MustCompile(`^/usr/lib/python(3\.\d+)/site-packages/([^/\s]+)`)

// oldSitePackagesEntries returns, for the installed packages pkgs, the
// top-level site-packages entries they installed for a Python other than
// current, keyed by that Python version.
func oldSitePackagesEntries(pkgs []string, current string) map[string][]string {
	entries := make(map[string][]string)
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		f, err := os.Open(filepath.Join(Installed, pkg, "manifest"))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			m := sitePackagesEntry.FindStringSubmatch(scanner.Text())
			if m == nil || m[1] == current || seen[m[1]+"/"+m[2]] {
				continue
			}
			seen[m[1]+"/"+m[2]] = true
			entries[m[1]] = append(entries[m[1]], m[2])
		}
		f.Close()
	}
	return entries
}

// pythonBootstrapPath builds a directory that links the old-Python copies of
// pkgs' modules, for PYTHONPATH while the new interpreter has none: their
// pure-Python code (build, installer, flit_core, mesonbuild) runs unchanged
// on the next minor release. It returns "" when every package already
// matches current, i.e. no upgrade is in progress.
func pythonBootstrapPath(pkgs []string, current string) (string, error) {
	byVersion := oldSitePackagesEntries(pkgs, current)
	if len(byVersion) == 0 {
		return "", nil
	}
	dir, err := os.MkdirTemp("", "hokuto-python-bootstrap-")
	if err != nil {
		return "", err
	}
	versions := make([]string, 0, len(byVersion))
	for version := range byVersion {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	for _, version := range versions {
		site := filepath.Join(rootDir, "usr", "lib", "python"+version, "site-packages")
		for _, entry := range byVersion[version] {
			link := filepath.Join(dir, entry)
			if _, err := os.Lstat(link); err == nil {
				continue // the same module from two old versions: keep one
			}
			if err := os.Symlink(filepath.Join(site, entry), link); err != nil {
				os.RemoveAll(dir)
				return "", err
			}
		}
	}
	return dir, nil
}

// pythonBootstrapSet returns the marked recipes among pythonBootstrapPackages
// and the marked recipes they need to build, in name order.
func pythonBootstrapSet(marked map[string]string) []string {
	set := make(map[string]bool)
	var visit func(name string)
	visit = func(name string) {
		pkgDir, ok := marked[name]
		if !ok || set[name] {
			return
		}
		set[name] = true
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			return
		}
		for _, dep := range deps {
			if dep.Cross || dep.CrossNative || dep.Suggest || dep.Optional {
				continue
			}
			names := dep.Alternatives
			if len(names) == 0 {
				names = []string{dep.Name}
			}
			for _, n := range names {
				visit(n)
			}
		}
	}
	for _, name := range pythonBootstrapPackages {
		visit(name)
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// builtRecipePackage reports whether dir holds a package of recipe pkgDir at
// its current version, i.e. the recipe built.
func builtRecipePackage(dir, name, pkgDir string) bool {
	data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		fields = append(fields, "1")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, fmt.Sprintf("%s-%s-%s-*.tar.zst", name, fields[0], fields[1])))
	return len(matches) > 0
}

func keysOf(m map[string]string) map[string]bool {
	set := make(map[string]bool, len(m))
	for k := range m {
		set[k] = true
	}
	return set
}
