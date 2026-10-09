package hokuto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Unattended runs (hokuto-builder's service: bump --auto -y, update
// --build-missing-binaries -y, cross-sync -y) would otherwise try a broken
// package again every round. A package whose own build failed in such a run is
// added to the build blacklist (BuildIgnoreFile) for the target architecture,
// until its recipe's version or revision changes; hokuto blacklist removes it
// sooner.

// ownBuildFailures holds the packages whose own build failed in this process,
// as pkgBuild saw them. A package that only failed because a dependency did is
// not in it: it builds again once the dependency is fixed.
var ownBuildFailures = struct {
	sync.Mutex
	m map[string]bool
}{m: make(map[string]bool)}

func noteOwnBuildFailure(pkgName string) {
	ownBuildFailures.Lock()
	ownBuildFailures.m[pkgName] = true
	ownBuildFailures.Unlock()
}

// ownBuildFailed reports whether pkgName's own build failed in this process; a
// kernel module request (pkg@kernel) counts for its recipe.
func ownBuildFailed(pkgName string) bool {
	ownBuildFailures.Lock()
	defer ownBuildFailures.Unlock()
	if ownBuildFailures.m[pkgName] {
		return true
	}
	for name := range ownBuildFailures.m {
		if strings.HasPrefix(name, pkgName+"@") {
			return true
		}
	}
	return false
}

// buildIgnoreKey keys an entry by package and architecture; native entries,
// the only kind before architectures were recorded, keep the plain name.
func buildIgnoreKey(pkgName, arch string) string {
	if arch == "" {
		return pkgName
	}
	return pkgName + "@" + arch
}

// buildIgnoredArch reports whether pkgName is blacklisted for arch at
// release (version-revision).
func buildIgnoredArch(ignores map[string]buildIgnoreEntry, pkgName, arch, release string) bool {
	entry, ok := ignores[buildIgnoreKey(pkgName, arch)]
	return ok && entry.Version == release
}

// blacklistFailedBuilds blacklists, for arch ("" for the native builds), those
// of pkgs whose own build failed in this process (failed, usually
// ownBuildFailed). release returns a package's current version-revision. It
// reports each one as a "blacklisted" build result and returns them.
func blacklistFailedBuilds(pkgs []string, arch string, release func(string) string, failed func(string) bool) []string {
	var failedPkgs []string
	for _, pkgName := range pkgs {
		if failed(pkgName) {
			failedPkgs = append(failedPkgs, pkgName)
		}
	}
	if len(failedPkgs) == 0 {
		return nil
	}
	ignores, err := loadBuildIgnoreList()
	if err != nil {
		colWarn.Printf("Warning: failed to read build blacklist %s: %v\n", BuildIgnoreFile, err)
		ignores = make(map[string]buildIgnoreEntry)
	}
	var added []string
	for _, pkgName := range failedPkgs {
		rel := release(pkgName)
		if rel == "" {
			continue
		}
		ignores[buildIgnoreKey(pkgName, arch)] = buildIgnoreEntry{Package: pkgName, Arch: arch, Version: rel, AddedAt: time.Now()}
		added = append(added, pkgName)
	}
	if len(added) == 0 {
		return nil
	}
	if err := saveBuildIgnoreList(ignores); err != nil {
		colWarn.Printf("Warning: failed to save build blacklist %s: %v\n", BuildIgnoreFile, err)
		return nil
	}
	where := ""
	if arch != "" {
		where = " (" + arch + ")"
	}
	colArrow.Print("-> ")
	colNote.Printf("Blacklisted%s until their next version or revision (hokuto blacklist remove <pkg> to retry): %s\n", where, strings.Join(added, ", "))
	for _, pkgName := range added {
		reportBuildEvent("blacklisted", pkgName, release(pkgName), blacklistArchName(arch),
			"its build failed; skipped until its version or revision changes")
	}
	return added
}

func blacklistArchName(arch string) string {
	if arch == "" {
		return hostArchForReports()
	}
	return arch
}

// hostArchForReports is the architecture native builds target.
func hostArchForReports() string {
	return GetSystemArchForPackage(&Config{Values: map[string]string{}}, "")
}

// reportBuildEvent appends a result line that is not a package build (a
// blacklisting, an unmatched Repology project) to HOKUTO_BUILD_RESULTS.
func reportBuildEvent(status, pkgName, version, arch, reason string) {
	path := os.Getenv(buildResultsEnv)
	if path == "" {
		return
	}
	if version == "" {
		version = "-"
	}
	line := buildResultLine(time.Now(), status, pkgName, version, arch, 0, reason)
	buildResultsMu.Lock()
	defer buildResultsMu.Unlock()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		debugf("Warning: cannot record %s for %s in %s: %v\n", status, pkgName, path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		debugf("Warning: cannot record %s for %s in %s: %v\n", status, pkgName, path, err)
	}
}

// handleBlacklistCommand lists the build blacklist or removes packages from it:
//
//	hokuto blacklist [list]
//	hokuto blacklist remove [-arch <arch>] <pkg>...
//	hokuto blacklist clear
func handleBlacklistCommand(args []string) error {
	ignores, err := loadBuildIgnoreList()
	if err != nil {
		return fmt.Errorf("failed to read build blacklist %s: %w", BuildIgnoreFile, err)
	}
	cmd := "list"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "list", "ls":
		if len(ignores) == 0 {
			colArrow.Print("-> ")
			colSuccess.Println("The build blacklist is empty.")
			return nil
		}
		keys := make([]string, 0, len(ignores))
		for k := range ignores {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e := ignores[k]
			arch := e.Arch
			if arch == "" {
				arch = "native"
			}
			state := ""
			if e.Version != buildIgnoreRelease(e.Package) {
				state = "  (expired: the recipe has moved on)"
			}
			fmt.Printf("%-32s %-8s %-20s since %s%s\n", e.Package, arch, e.Version, e.AddedAt.Local().Format("2006-01-02 15:04"), state)
		}
		return nil
	case "remove", "rm", "del":
		arch := ""
		var pkgs []string
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "-arch" || args[i] == "--arch":
				if i+1 >= len(args) {
					return fmt.Errorf("-arch needs a value (native, aarch64, ...)")
				}
				arch = args[i+1]
				i++
			case strings.HasPrefix(args[i], "-arch=") || strings.HasPrefix(args[i], "--arch="):
				arch = args[i][strings.Index(args[i], "=")+1:]
			default:
				pkgs = append(pkgs, args[i])
			}
		}
		if len(pkgs) == 0 {
			return fmt.Errorf("usage: hokuto blacklist remove [-arch <arch>] <pkg>...")
		}
		removed := removeBuildIgnores(ignores, pkgs, arch)
		if len(removed) == 0 {
			colArrow.Print("-> ")
			colNote.Println("None of them is blacklisted.")
			return nil
		}
		if err := saveBuildIgnoreList(ignores); err != nil {
			return err
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Removed from the build blacklist: %s\n", strings.Join(removed, ", "))
		return nil
	case "clear":
		if len(ignores) == 0 {
			return nil
		}
		if err := saveBuildIgnoreList(map[string]buildIgnoreEntry{}); err != nil {
			return err
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Cleared %d build blacklist entries.\n", len(ignores))
		return nil
	}
	return fmt.Errorf("unknown blacklist command %q (list, remove, clear)", cmd)
}

// removeBuildIgnores removes pkgs' entries, for one architecture ("native" for
// the native builds) or, without arch, for all; it returns what it removed.
func removeBuildIgnores(ignores map[string]buildIgnoreEntry, pkgs []string, arch string) []string {
	if arch == "native" {
		arch = ""
	}
	want := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		want[p] = true
	}
	var removed []string
	for key, e := range ignores {
		if !want[e.Package] {
			continue
		}
		if arch != "" && e.Arch != arch {
			continue
		}
		delete(ignores, key)
		label := e.Package
		if e.Arch != "" {
			label += " (" + e.Arch + ")"
		}
		removed = append(removed, label)
	}
	sort.Strings(removed)
	return removed
}

// buildIgnoreRelease is the current version-revision of a blacklisted
// package's recipe; a cross-system package (aarch64-gcc) has its base recipe's.
func buildIgnoreRelease(pkgName string) string {
	if rel := recipeRelease(pkgName); rel != "" {
		return rel
	}
	if base := strings.TrimPrefix(pkgName, crossSyncPrefix); base != pkgName {
		return recipeRelease(base)
	}
	return ""
}

// noMatchStateFile remembers, per repository, the Repology projects auto-bump
// found no recipe for, so an unattended run reports each one once.
func noMatchStateFile() string {
	return filepath.Join(filepath.Dir(BumpIgnoreFile), "bump-nomatch.json")
}

// reportNewNoMatches reports the projects of repo in unmatched (project ->
// "recipe name tried\tRepology version") that the last run did not already
// report, and remembers them. It only does so in an unattended run that
// records results, where the report reaches the run log.
func reportNewNoMatches(repo string, unmatched map[string]string) {
	if os.Getenv(buildResultsEnv) == "" {
		return
	}
	state := make(map[string][]string)
	if data, err := os.ReadFile(noMatchStateFile()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	seen := make(map[string]bool)
	for _, p := range state[repo] {
		seen[p] = true
	}
	current := make([]string, 0, len(unmatched))
	for project := range unmatched {
		current = append(current, project)
	}
	sort.Strings(current)
	for _, project := range current {
		if seen[project] {
			continue
		}
		tried, version, _ := strings.Cut(unmatched[project], "\t")
		reportBuildEvent("nomatch", project, version, "-",
			fmt.Sprintf("Repology project %s maps to %s, which is no recipe or package set in %s: map it to the recipe in the auto-bump name switch (internal/hokuto/pkgdev.go)", project, tried, repo))
	}
	state[repo] = current
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	if err := writeStateFile(noMatchStateFile(), append(data, '\n')); err != nil {
		debugf("Warning: failed to save %s: %v\n", noMatchStateFile(), err)
	}
}
