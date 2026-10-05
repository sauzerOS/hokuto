package hokuto

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// installedSizeFile holds a package's installed size, written when it is
// installed: the staged tree counted as installed_size counts it (regular
// files, hard links once). "hokuto list" used to add the size up from every
// manifest entry, stat by stat, for every package: 224k files for 1126
// packages, on every listing.
const installedSizeFile = "size"

// recordStagedInstalledSize writes the size of the staged package into its
// metadata, to be placed with it. A tree that cannot be walked completely is
// left without one; the size is then added up from the manifest.
func recordStagedInstalledSize(stagingDir, pkgName string, execCtx *Executor) {
	size, err := installedSize(stagingDir)
	if err != nil {
		debugf("Not recording the installed size of %s: %v\n", pkgName, err)
		return
	}
	path := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName, installedSizeFile)
	if err := writeFileAsRoot(path, []byte(strconv.FormatInt(size, 10)+"\n"), 0o644, execCtx); err != nil {
		debugf("Not recording the installed size of %s: %v\n", pkgName, err)
	}
}

// installedPackageSizes returns the installed size of each package in
// names: the recorded one, or, for a package installed before sizes were
// recorded, the one added up from its manifest, those in parallel.
func installedPackageSizes(names []string) map[string]int64 {
	sizes := make(map[string]int64, len(names))
	var missing []string
	for _, name := range names {
		if data, err := os.ReadFile(filepath.Join(Installed, name, installedSizeFile)); err == nil {
			if size, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64); err == nil {
				sizes[name] = size
				continue
			}
		}
		missing = append(missing, name)
	}
	if len(missing) == 0 {
		return sizes
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for w := 0; w < min(runtime.NumCPU()*2, len(missing)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				// Counted as the recorded sizes are.
				if total, ok := installedPackageFootprint(name); ok {
					mu.Lock()
					sizes[name] = total
					mu.Unlock()
				}
			}
		}()
	}
	for _, name := range missing {
		jobs <- name
	}
	close(jobs)
	wg.Wait()
	return sizes
}
