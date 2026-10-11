package hokuto

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// A package is queued for a rebuild when an update removes a shared library
// its installed libdeps name. Within one update that package is often being
// updated as well -- bump's ABI rebuilds give it a new revision, built against
// the new library -- and once that replacement is installed nothing needs
// rebuilding. So the decision is made again once the update has run, from
// what is installed then.

// libraryRebuildStillNeeded reports whether the installed pkgName links
// against a library that is no longer on the system. A library it cannot find
// in the linker's directories counts as missing, so a package whose libraries
// live somewhere unusual keeps the rebuild it was given rather than losing it.
func libraryRebuildStillNeeded(pkgName string) bool {
	if !isPackageInstalled(pkgName) {
		return false // removed since: nothing left to rebuild
	}
	data, err := os.ReadFile(filepath.Join(Installed, pkgName, "libdeps"))
	if err != nil {
		if data, err = readFileAsRoot(filepath.Join(Installed, pkgName, "libdeps")); err != nil {
			return true
		}
	}
	dirs := append(linkerLibraryDirs(), ownLibraryDirs(pkgName)...)
	for _, line := range strings.Split(string(data), "\n") {
		dep, ok := parseLibDepRef(line)
		if !ok {
			continue
		}
		if !libDepPresent(dep, dirs) {
			debugf("%s still needs %s, which is not installed\n", pkgName, line)
			return true
		}
	}
	return false
}

// ownLibraryDirs lists the directories holding the shared libraries pkgName
// installs. A package's private libraries (samba's /usr/lib/samba, shared
// with its split smbclient) are outside the linker's directories, found
// through its runpath.
func ownLibraryDirs(pkgName string) []string {
	entries, err := parseManifest(filepath.Join(Installed, pkgName, "manifest"))
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var dirs []string
	for path := range entries {
		name := filepath.Base(path)
		if !strings.HasSuffix(name, ".so") && !strings.Contains(name, ".so.") {
			continue
		}
		if dir := filepath.Dir(path); !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	sort.Strings(dirs)
	return dirs
}

// libDepPresent reports whether a libdeps entry resolves to a file under the
// target root.
func libDepPresent(dep libDepRef, dirs []string) bool {
	if strings.HasPrefix(dep.Name, "/") {
		_, err := os.Stat(filepath.Join(rootDir, dep.Name))
		return err == nil
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, dep.Name)
		if !libraryPathMatchesDep(path, dep) {
			continue
		}
		if _, err := os.Stat(filepath.Join(rootDir, path)); err == nil {
			return true
		}
	}
	return false
}

// linkerLibraryDirs lists the directories the dynamic linker searches: the
// defaults plus /etc/ld.so.conf and the files it includes.
func linkerLibraryDirs() []string {
	dirs := []string{"/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/lib32", "/lib32"}
	seen := make(map[string]bool)
	for _, dir := range dirs {
		seen[dir] = true
	}
	var readConf func(path string, depth int)
	readConf = func(path string, depth int) {
		if depth > 4 {
			return
		}
		f, err := os.Open(filepath.Join(rootDir, path))
		if err != nil {
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line == "" {
				continue
			}
			if pattern, ok := strings.CutPrefix(line, "include "); ok {
				matches, _ := filepath.Glob(filepath.Join(rootDir, strings.TrimSpace(pattern)))
				for _, match := range matches {
					rel, err := filepath.Rel(rootDir, match)
					if err == nil {
						readConf("/"+rel, depth+1)
					}
				}
				continue
			}
			if strings.HasPrefix(line, "/") && !seen[line] {
				seen[line] = true
				dirs = append(dirs, line)
			}
		}
	}
	readConf("/etc/ld.so.conf", 0)
	// ld.so.conf usually includes this directory; read it even when not.
	matches, _ := filepath.Glob(filepath.Join(rootDir, "etc", "ld.so.conf.d", "*.conf"))
	for _, match := range matches {
		if rel, err := filepath.Rel(rootDir, match); err == nil {
			readConf("/"+rel, 1)
		}
	}
	return dirs
}

// updateBatch tracks, for a sequential update, the packages that are still to
// be updated in this run. The installer does not offer a library rebuild for
// those: the update is about to replace them. It records them instead, and
// the update checks them once it has finished.
var updateBatch = struct {
	sync.Mutex
	pending  map[string]bool
	deferred map[string][]string // package -> removed libraries that affected it
}{}

func startUpdateBatch(pkgNames []string) {
	updateBatch.Lock()
	defer updateBatch.Unlock()
	updateBatch.pending = make(map[string]bool, len(pkgNames))
	for _, name := range pkgNames {
		updateBatch.pending[name] = true
	}
	updateBatch.deferred = make(map[string][]string)
}

// markUpdateBatchDone records that pkgName's update has been processed.
func markUpdateBatchDone(pkgName string) {
	updateBatch.Lock()
	defer updateBatch.Unlock()
	delete(updateBatch.pending, pkgName)
}

// deferUpdateBatchRebuilds removes from affected the packages this update
// still replaces, and remembers them for finishUpdateBatch.
func deferUpdateBatchRebuilds(affected map[string][]string) {
	updateBatch.Lock()
	defer updateBatch.Unlock()
	if updateBatch.pending == nil {
		return
	}
	for pkg, libs := range affected {
		if updateBatch.pending[pkg] {
			updateBatch.deferred[pkg] = append(updateBatch.deferred[pkg], libs...)
			delete(affected, pkg)
		}
	}
}

// finishUpdateBatch ends the batch and returns the deferred packages that
// still link against a removed library after their own update.
func finishUpdateBatch() map[string][]string {
	updateBatch.Lock()
	deferred := updateBatch.deferred
	updateBatch.pending = nil
	updateBatch.deferred = nil
	updateBatch.Unlock()

	broken := make(map[string][]string)
	for pkg, libs := range deferred {
		if libraryRebuildStillNeeded(pkg) {
			broken[pkg] = libs
		}
	}
	return broken
}

// reportBrokenUpdateBatch ends a sequential update's batch and warns about the
// packages that still link against a library the update removed, even after
// their own update (a replacement built against the old library).
func reportBrokenUpdateBatch() {
	broken := finishUpdateBatch()
	if len(broken) == 0 {
		return
	}
	names := make([]string, 0, len(broken))
	for pkg := range broken {
		names = append(names, pkg)
	}
	sort.Strings(names)
	colArrow.Print("\n-> ")
	cPrintf(colWarn, "These packages still depend on libraries this update removed:\n")
	for _, pkg := range names {
		cPrintf(colWarn, "  %s (needs: %s)\n", pkg, strings.Join(broken[pkg], ", "))
	}
	colArrow.Print("-> ")
	cPrintf(colInfo, "Rebuild them with: hokuto build %s\n", strings.Join(names, " "))
}
