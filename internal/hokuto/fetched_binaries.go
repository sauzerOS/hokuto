package hokuto

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// fetchedBinaries are the package archives this process downloaded from the
// mirror into BinDir. They only serve the running command -- the mirror keeps
// them -- so they are removed when hokuto exits. Files that were already in
// BinDir (local builds, or a package another hokuto fetched) are never
// tracked. `hokuto fetch`, whose downloads are the point, keeps them.
var fetchedBinaries = struct {
	sync.Mutex
	paths map[string]bool
	keep  bool
}{paths: make(map[string]bool)}

func trackFetchedBinary(path string) {
	fetchedBinaries.Lock()
	defer fetchedBinaries.Unlock()
	fetchedBinaries.paths[path] = true
}

// untrackFetchedBinary makes path a file hokuto did not download, after a
// build wrote its own package over a download of the same name.
func untrackFetchedBinary(path string) {
	fetchedBinaries.Lock()
	defer fetchedBinaries.Unlock()
	delete(fetchedBinaries.paths, path)
}

// keepFetchedBinaries makes this process leave its downloads in BinDir.
func keepFetchedBinaries() {
	fetchedBinaries.Lock()
	defer fetchedBinaries.Unlock()
	fetchedBinaries.keep = true
}

// removeFetchedBinaries deletes the archives this process downloaded. It runs
// on every exit path (see exitHokuto), so it must be safe to call more than
// once and must never touch a file hokuto did not download itself.
func removeFetchedBinaries() {
	fetchedBinaries.Lock()
	defer fetchedBinaries.Unlock()
	if fetchedBinaries.keep || len(fetchedBinaries.paths) == 0 {
		return
	}
	// Another build may have found one of these files in BinDir and be about
	// to install it; leave them for upload's cleanup in that case.
	if activeSessions := otherActiveHokutoBuildSessions(); len(activeSessions) > 0 {
		debugf("Keeping downloaded packages; another Hokuto build is active (pid %s)\n", joinPIDs(activeSessions))
		return
	}

	paths := make([]string, 0, len(fetchedBinaries.paths))
	for path := range fetchedBinaries.paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var removed []string
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			debugf("Warning: failed to remove downloaded package %s: %v\n", path, err)
			continue
		}
		removed = append(removed, filepath.Base(path))
		delete(fetchedBinaries.paths, path)
	}
	if err := updateUploadCache(nil, removed); err != nil {
		debugf("Warning: failed to update upload scanning cache: %v\n", err)
	}
	debugf("Removed %d package(s) downloaded from the mirror\n", len(removed))
}

// exitHokuto is os.Exit for hokuto's command paths: it first removes the
// packages this process downloaded, which a deferred call would miss.
func exitHokuto(code int) {
	flushTransactionLog()
	removeFetchedBinaries()
	os.Exit(code)
}

// handleFetchCommand downloads packages from the mirror into BinDir and keeps
// them there, unlike the downloads other commands make for their own use.
func handleFetchCommand(args []string, cfg *Config) error {
	fetchCmd := flag.NewFlagSet("fetch", flag.ContinueOnError)
	force := fetchCmd.Bool("f", false, "Download again even when the file is already in the binary cache")
	fetchCmd.SetOutput(os.Stderr)
	if err := fetchCmd.Parse(args); err != nil {
		return err
	}
	pkgs := fetchCmd.Args()
	if len(pkgs) == 0 {
		return fmt.Errorf("usage: hokuto fetch [-f] <pkg[@version[-revision]]>...")
	}
	if BinaryMirror == "" {
		return fmt.Errorf("no HOKUTO_MIRROR configured")
	}
	keepFetchedBinaries()

	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return fmt.Errorf("failed to fetch remote index: %w", err)
	}

	var failed []string
	for _, pkg := range pkgs {
		entry, err := GetRemotePackageEntry(pkg, cfg, index)
		if err != nil {
			colArrow.Print("-> ")
			colError.Printf("%s: %v\n", pkg, err)
			failed = append(failed, pkg)
			continue
		}
		path := filepath.Join(BinDir, entry.Filename)
		if _, err := os.Stat(path); err == nil && !*force {
			colArrow.Print("-> ")
			colSuccess.Printf("Already in the binary cache: ")
			colNote.Println(path)
			continue
		}
		if err := fetchSpecificBinaryPackage(entry.Name, entry.Version, entry.Revision, entry.Variant, cfg, false, entry.B3Sum, *force); err != nil {
			colArrow.Print("-> ")
			colError.Printf("%s: %v\n", pkg, err)
			failed = append(failed, pkg)
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Fetched: ")
		colNote.Println(path)
	}
	if len(failed) > 0 {
		return fmt.Errorf("failed to fetch %d package(s): %v", len(failed), failed)
	}
	return nil
}
