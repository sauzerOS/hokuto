package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	var todo []RepoEntry
	var total int64
	for _, arg := range plan {
		if strings.HasSuffix(arg, ".tar.zst") {
			continue
		}
		entry, err := GetRemotePackageEntry(arg, cfg, remoteIndex)
		if err != nil || entry.Filename == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(BinDir, entry.Filename)); err == nil && info.Size() == entry.Size {
			continue
		}
		todo = append(todo, *entry)
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
