package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
)

// installPlanSizes is what an install plan downloads and takes once
// installed, from the remote index (metadata version 4) or, for archives
// already on disk, from the archives themselves.
type installPlanSizes struct {
	download  int64
	installed int64
	// unknownInstalled counts packages whose installed size neither the
	// index (an entry from before version 4) nor a local archive gives.
	unknownInstalled int
}

func computeInstallPlanSizes(plan []string, cfg *Config, remoteIndex []RepoEntry) installPlanSizes {
	var sizes installPlanSizes
	for _, arg := range plan {
		// A tarball named on the command line is already here.
		if strings.HasSuffix(arg, ".tar.zst") {
			sizes.addInstalledFromArchive(arg)
			continue
		}
		var entry *RepoEntry
		if len(remoteIndex) > 0 {
			if e, err := GetRemotePackageEntry(arg, cfg, remoteIndex); err == nil {
				entry = e
			}
		}
		if entry == nil {
			if cached := findCachedBinaryTarball(arg, cfg); cached != "" {
				sizes.addInstalledFromArchive(cached)
			} else {
				sizes.unknownInstalled++
			}
			continue
		}
		cached := ""
		if entry.Filename != "" {
			path := filepath.Join(BinDir, entry.Filename)
			if info, err := os.Stat(path); err == nil && info.Size() == entry.Size {
				cached = path
			}
		}
		if cached == "" {
			sizes.download += entry.Size
		}
		switch {
		case entry.InstalledSize > 0:
			sizes.installed += entry.InstalledSize
		case cached != "":
			sizes.addInstalledFromArchive(cached)
		default:
			sizes.unknownInstalled++
		}
	}
	return sizes
}

func (s *installPlanSizes) addInstalledFromArchive(path string) {
	if scan, err := scanTarballFull(path); err == nil && scan.installedSize > 0 {
		s.installed += scan.installedSize
		return
	}
	s.unknownInstalled++
}

// printInstallPlanSizes prints the totals as pacman does before it asks.
func printInstallPlanSizes(sizes installPlanSizes) {
	colArrow.Print("-> ")
	colSuccess.Print("Total Download Size:  ")
	colNote.Println(humanReadableSize(sizes.download))
	colArrow.Print("-> ")
	colSuccess.Print("Total Installed Size: ")
	colNote.Print(humanReadableSize(sizes.installed))
	if sizes.unknownInstalled > 0 {
		colSuccess.Printf(" (+%d package(s) of unknown size)", sizes.unknownInstalled)
	}
	colSuccess.Println()
}

// installPlanDownloadWorkers is how many packages prefetchInstallPlan
// downloads at once (pacman's ParallelDownloads default is 5).
const installPlanDownloadWorkers = 5

// prefetchInstallPlan downloads, several at a time, every package of plan
// the local cache does not hold, before the first install. Until now each
// package was downloaded just before it was installed, one after another.
// A package that fails here is fetched again, and reported, when the
// install reaches it.
func prefetchInstallPlan(plan []string, cfg *Config, remoteIndex []RepoEntry) {
	if BinaryMirror == "" || len(remoteIndex) == 0 {
		return
	}
	var entries []RepoEntry
	for _, arg := range plan {
		if strings.HasSuffix(arg, ".tar.zst") {
			continue
		}
		if entry, err := GetRemotePackageEntry(arg, cfg, remoteIndex); err == nil {
			entries = append(entries, *entry)
		}
	}
	prefetchRepoEntries(entries, cfg)
}

// prefetchRepoEntries downloads, several at a time, the archives of entries
// the local cache does not hold.
func prefetchRepoEntries(entries []RepoEntry, cfg *Config) {
	if BinaryMirror == "" {
		return
	}
	var todo []RepoEntry
	var total int64
	seen := make(map[string]bool)
	for _, entry := range entries {
		if entry.Filename == "" || seen[entry.Filename] {
			continue
		}
		seen[entry.Filename] = true
		if info, err := os.Stat(filepath.Join(BinDir, entry.Filename)); err == nil && info.Size() == entry.Size {
			continue
		}
		todo = append(todo, entry)
		total += entry.Size
	}
	if len(todo) == 0 {
		return
	}

	colArrow.Print("-> ")
	colSuccess.Print("Downloading ")
	colNote.Printf("%d", len(todo))
	colSuccess.Print(" packages (")
	colNote.Print(humanReadableSize(total))
	colSuccess.Println(")")
	bar := progressbar.NewOptions64(total,
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetWidth(30),
		progressbar.OptionShowBytes(true),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stderr) }),
	)

	jobs := make(chan RepoEntry)
	var wg sync.WaitGroup
	for w := 0; w < min(installPlanDownloadWorkers, len(todo)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, true, entry.B3Sum, false); err != nil {
					debugf("Prefetch of %s failed (retried when it is installed): %v\n", entry.Filename, err)
				}
				bar.Add64(entry.Size)
			}
		}()
	}
	for _, entry := range todo {
		jobs <- entry
	}
	close(jobs)
	wg.Wait()
	bar.Finish()
}

// remoteUpdateSizes is what a remote update downloads and how much the
// installed size changes: pacman's Total Download Size and Net Upgrade Size.
type remoteUpdateSizes struct {
	download int64
	net      int64
	// unknown counts packages whose old or new installed size is not known
	// (an index entry from before metadata version 4, a missing manifest).
	unknown int
	// known counts the packages net includes.
	known int
	// built counts packages an update builds from source, whose size is
	// known only once they are built.
	built int
}

// computeRemoteUpdateSizes adds up the upgrades in pkgNames, which replace
// what is installed, and the new dependencies they bring, which add to it.
func computeRemoteUpdateSizes(pkgNames []string, targets map[string]RepoEntry, cfg *Config, remoteIndex []RepoEntry) remoteUpdateSizes {
	var sizes remoteUpdateSizes
	counted := make(map[string]bool)
	for _, name := range pkgNames {
		counted[name] = true
	}
	for _, name := range pkgNames {
		// New dependencies first, as the update installs them.
		if plan, err := remoteUpdateDependencyPlan(name, cfg, remoteIndex); err == nil {
			for _, dep := range plan {
				if counted[dep] {
					continue
				}
				counted[dep] = true
				entry, err := GetRemotePackageEntry(dep, cfg, remoteIndex)
				if err != nil {
					sizes.unknown++
					continue
				}
				sizes.addNew(entry, "")
			}
		}

		entry, ok := targets[name]
		if !ok {
			sizes.unknown++
			continue
		}
		sizes.addUpgrade(name, &entry, "")
	}
	return sizes
}

// archiveSizes is what installing one archive downloads and takes: from
// its index entry, or from the archive itself when it is cached and has no
// entry (or one without an installed size).
func archiveSizes(entry *RepoEntry, cachedPath string) (download, installed int64) {
	if entry != nil {
		cached := false
		if entry.Filename != "" {
			if info, err := os.Stat(filepath.Join(BinDir, entry.Filename)); err == nil && info.Size() == entry.Size {
				cached = true
				if cachedPath == "" {
					cachedPath = filepath.Join(BinDir, entry.Filename)
				}
			}
		}
		if !cached && cachedPath == "" {
			download = entry.Size
		}
		installed = entry.InstalledSize
	}
	if installed <= 0 && cachedPath != "" {
		if scan, err := scanTarballFull(cachedPath); err == nil {
			installed = scan.installedSize
		}
	}
	return download, installed
}

// addUpgrade counts the archive replacing the installed package name.
func (s *remoteUpdateSizes) addUpgrade(name string, entry *RepoEntry, cachedPath string) {
	download, installed := archiveSizes(entry, cachedPath)
	s.download += download
	oldSize, known := installedPackageFootprint(name)
	if installed > 0 && known {
		s.net += installed - oldSize
		s.known++
	} else {
		s.unknown++
	}
}

// addNew counts an archive that installs a package not installed yet.
func (s *remoteUpdateSizes) addNew(entry *RepoEntry, cachedPath string) {
	download, installed := archiveSizes(entry, cachedPath)
	s.download += download
	if installed > 0 {
		s.net += installed
		s.known++
	} else {
		s.unknown++
	}
}

// installedPackageFootprint is what an installed package takes, from its
// manifest, counted as installed_size counts it when the package is built
// (regular files, hard links once, its own metadata included), so the two
// can be subtracted. installedPackageSize, for "hokuto size", counts the
// way it reports.
func installedPackageFootprint(pkgName string) (int64, bool) {
	entries, err := parseManifest(filepath.Join(Installed, pkgName, "manifest"))
	if err != nil || len(entries) == 0 {
		return 0, false
	}
	var total int64
	seen := make(map[[2]uint64]bool)
	for path := range entries {
		if strings.HasSuffix(path, "/") {
			continue
		}
		info, err := os.Lstat(filepath.Join(rootDir, path))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Nlink > 1 {
			key := [2]uint64{uint64(st.Dev), st.Ino}
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		total += info.Size()
	}
	return total, true
}

// printRemoteUpdateSizes prints the totals as pacman does before it asks.
func printRemoteUpdateSizes(sizes remoteUpdateSizes) {
	colArrow.Print("-> ")
	colSuccess.Print("Total Download Size: ")
	colNote.Println(humanReadableSize(sizes.download))
	colArrow.Print("-> ")
	colSuccess.Print("Total Upgrade Size:  ")
	if sizes.known == 0 && (sizes.unknown > 0 || sizes.built > 0) {
		// Nothing to add up: "0 B" would claim the size does not change.
		colNote.Println("unknown")
		return
	}
	colNote.Print(formatSignedSize(sizes.net))
	if sizes.unknown > 0 {
		colSuccess.Printf(" (+%d package(s) of unknown size)", sizes.unknown)
	}
	if sizes.built > 0 {
		colSuccess.Printf(" (+%d built from source)", sizes.built)
	}
	colSuccess.Println()
}

// formatSignedSize is humanReadableSize with a minus sign for a shrink.
func formatSignedSize(b int64) string {
	if b < 0 {
		return "-" + humanReadableSize(-b)
	}
	return humanReadableSize(b)
}
