package hokuto

// ABI rebuilds for the build machine. When a freshly built library package no
// longer ships a shared library its previous package had (libfoo.so.3 gone,
// libfoo.so.4 new), every published package linked against it needs a
// rebuild. Installed packages are handled at install time (see pkgInstall);
// this covers what is published, using the libdeps recorded in the mirror
// index, and bumps the consumers' recipe revisions so that
// `hokuto update --build-missing-binaries` (hokuto-builder rebuild) rebuilds
// and publishes them.

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// abiBreak is one library recipe whose new build dropped shared libraries.
type abiBreak struct {
	Library string      // recipe name, e.g. "libfoo"
	Version string      // its new version
	Removed []libDepRef // e.g. elf64:libfoo.so.3
}

// tarballSharedLibraryPaths lists the shared objects a package archive ships
// (files and symlinks such as /usr/lib/libfoo.so.3), as absolute paths.
func tarballSharedLibraryPaths(tarballPath string) ([]string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	var paths []string
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(tarballPath), err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeSymlink {
			continue
		}
		name := "/" + strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if strings.HasPrefix(name, "/var/db/hokuto/") || !isVersionedSharedObjectName(path.Base(name)) {
			continue
		}
		paths = append(paths, name)
	}
	return paths, nil
}

// isVersionedSharedObjectName accepts libfoo.so and libfoo.so.3.1.0, but not
// libfoo.so.3.1.0.notes or libfoo.so.bak.
func isVersionedSharedObjectName(name string) bool {
	idx := strings.Index(name, ".so")
	if idx <= 0 {
		return false
	}
	tail := name[idx+len(".so"):]
	if tail == "" {
		return true
	}
	for _, part := range strings.Split(strings.TrimPrefix(tail, "."), ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return strings.HasPrefix(tail, ".")
}

// removedSharedLibraries returns the libraries (by ELF class and file name,
// the way libdeps refer to them) that oldPaths provide and newPaths no longer
// do. A library that merely moved directory is not removed.
func removedSharedLibraries(oldPaths, newPaths []string) []libDepRef {
	class := func(p string) string {
		if pathIs32BitLibrary(p) {
			return "elf32"
		}
		return "elf64"
	}
	provided := make(map[libDepRef]bool)
	for _, p := range newPaths {
		provided[libDepRef{ABI: class(p), Name: path.Base(p)}] = true
	}
	seen := make(map[libDepRef]bool)
	var removed []libDepRef
	for _, p := range oldPaths {
		ref := libDepRef{ABI: class(p), Name: path.Base(p)}
		if provided[ref] || seen[ref] {
			continue
		}
		seen[ref] = true
		removed = append(removed, ref)
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].String() < removed[j].String() })
	return removed
}

// libDepMatches reports whether a libdeps entry refers to lib. Older packages
// record absolute paths without an ELF class; the class then follows from
// the directory, as for installed packages (pathIs32BitLibrary).
func libDepMatches(entry string, lib libDepRef) bool {
	ref, ok := parseLibDepRef(entry)
	if !ok || path.Base(ref.Name) != lib.Name {
		return false
	}
	if ref.ABI == "" && strings.HasPrefix(ref.Name, "/") {
		ref.ABI = "elf64"
		if pathIs32BitLibrary(ref.Name) {
			ref.ABI = "elf32"
		}
	}
	return ref.ABI == "" || ref.ABI == lib.ABI
}

// latestIndexEntries keeps the newest entry per package name, arch and
// variant.
func latestIndexEntries(index []RepoEntry) []RepoEntry {
	type key struct{ name, arch, variant string }
	latest := make(map[key]RepoEntry)
	var order []key
	for _, e := range index {
		if e.Type == "meta" {
			continue
		}
		k := key{e.Name, e.Arch, e.Variant}
		old, ok := latest[k]
		if !ok {
			order = append(order, k)
		}
		if !ok || isNewer(e, old) {
			latest[k] = e
		}
	}
	entries := make([]RepoEntry, 0, len(order))
	for _, k := range order {
		entries = append(entries, latest[k])
	}
	return entries
}

// abiConsumers maps the recipes of the published arch packages linked against
// a removed library to the libraries concerned. The library's own recipe,
// prebuilt (binary) recipes and packages without a recipe are left out.
// unknown counts packages whose index entry has no libdeps yet (not
// reindexed), which may be consumers too.
func abiConsumers(index []RepoEntry, arch string, brk abiBreak) (consumers map[string][]string, unknown int) {
	consumers = make(map[string][]string)
	for _, e := range latestIndexEntries(index) {
		if e.Arch != arch {
			continue
		}
		if e.MetadataVersion < repoEntryLibdepsMetadataVersion {
			unknown++
			continue
		}
		var hit []string
		for _, lib := range brk.Removed {
			for _, entry := range e.Libdeps {
				if libDepMatches(entry, lib) {
					hit = append(hit, lib.Name)
					break
				}
			}
		}
		if len(hit) == 0 {
			continue
		}
		recipe := e.Name
		if _, err := findPackageMetadataDir(recipe); err != nil {
			source, _, ok := findSplitPackageSource(recipe)
			if !ok {
				continue
			}
			recipe = source
		}
		if sameSourcePackage(recipe, brk.Library) {
			continue
		}
		if pkgDir, err := findPackageMetadataDir(recipe); err == nil && loadBuildOptions(pkgDir)["binary"] {
			continue
		}
		for _, name := range hit {
			if !slices.Contains(consumers[recipe], name) {
				consumers[recipe] = append(consumers[recipe], name)
			}
		}
	}
	return consumers, unknown
}

// previousPackageTarball returns a local copy of the newest published package
// of output older than version-revision, downloading it if needed.
func previousPackageTarball(output, version, revision string, cfg *Config, index []RepoEntry) (string, bool) {
	arch := GetSystemArchForPackage(cfg, output)
	current := RepoEntry{Version: version, Revision: revision}
	var prev *RepoEntry
	for i := range index {
		e := &index[i]
		if e.Name != output || e.Arch != arch || e.Type == "meta" || !isNewer(current, *e) {
			continue
		}
		if prev == nil || isNewer(*e, *prev) {
			prev = e
		}
	}
	if prev == nil {
		return "", false
	}
	local := filepath.Join(BinDir, StandardizeRemoteName(prev.Name, prev.Version, prev.Revision, prev.Arch, prev.Variant))
	if _, err := os.Stat(local); err == nil {
		return local, true
	}
	if err := fetchSpecificBinaryPackage(prev.Name, prev.Version, prev.Revision, prev.Variant, cfg, true, prev.B3Sum, false); err != nil {
		debugf("ABI check: cannot fetch previous %s %s-%s: %v\n", output, prev.Version, prev.Revision, err)
		return "", false
	}
	if _, err := os.Stat(local); err != nil {
		return "", false
	}
	return local, true
}

// detectABIBreak compares the just built packages of recipe pkgName (main
// and split outputs) with their previous published packages and returns the
// shared libraries they no longer provide.
func detectABIBreak(pkgName string, cfg *Config, index []RepoEntry) (abiBreak, error) {
	brk := abiBreak{Library: pkgName}
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return brk, err
	}
	brk.Version = version
	pkgDir, err := findPackageMetadataDir(pkgName)
	if err != nil {
		return brk, err
	}
	outputs := append([]string{getOutputPackageName(pkgName, cfg)}, splitPackageNamesFromDir(pkgDir)...)
	seen := make(map[libDepRef]bool)
	for _, output := range outputs {
		newTarball := findCachedBinaryTarballVersion(output, version, revision, cfg)
		if newTarball == "" {
			continue
		}
		oldTarball, ok := previousPackageTarball(output, version, revision, cfg, index)
		if !ok {
			continue
		}
		oldPaths, err := tarballSharedLibraryPaths(oldTarball)
		if err != nil {
			return brk, err
		}
		if len(oldPaths) == 0 {
			continue
		}
		newPaths, err := tarballSharedLibraryPaths(newTarball)
		if err != nil {
			return brk, err
		}
		for _, lib := range removedSharedLibraries(oldPaths, newPaths) {
			if !seen[lib] {
				seen[lib] = true
				brk.Removed = append(brk.Removed, lib)
			}
		}
	}
	return brk, nil
}

// abiRebuildResult is what bumpABIConsumers did.
type abiRebuildResult struct {
	Bumped  []string // recipes whose revision was bumped
	Skipped []string // recipes left alone, with the reason
}

// bumpABIConsumers bumps the revision of each consumer recipe and commits the
// version files, one commit per git repository, then pushes like a version
// bump. A version file with uncommitted changes is not touched, so none of
// your own edits end up in the commit.
func bumpABIConsumers(consumers map[string][]string, reasons map[string][]string) (abiRebuildResult, error) {
	var result abiRebuildResult
	names := make([]string, 0, len(consumers))
	for name := range consumers {
		names = append(names, name)
	}
	sort.Strings(names)

	byRepo := make(map[string][]string)
	var repoOrder []string
	for _, name := range names {
		pkgDir, err := findPackageMetadataDir(name)
		if err != nil {
			result.Skipped = append(result.Skipped, name+": recipe not found")
			continue
		}
		versionPath := filepath.Join(pkgDir, "version")
		root, err := getGitRepoRoot(pkgDir)
		if err != nil {
			result.Skipped = append(result.Skipped, name+": not in a git repository")
			continue
		}
		if out, err := exec.Command("git", "-C", root, "status", "--porcelain", "--", versionPath).Output(); err != nil || len(strings.TrimSpace(string(out))) > 0 {
			result.Skipped = append(result.Skipped, name+": version file has uncommitted changes")
			continue
		}
		bumped, err := bumpRecipeRevision(pkgDir)
		if err != nil {
			result.Skipped = append(result.Skipped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Printf("%s: %s (links %s)\n", name, bumped, strings.Join(consumers[name], ", "))
		result.Bumped = append(result.Bumped, name)
		if _, ok := byRepo[root]; !ok {
			repoOrder = append(repoOrder, root)
		}
		byRepo[root] = append(byRepo[root], versionPath)
	}

	msg := abiRebuildCommitMessage(reasons)
	for _, root := range repoOrder {
		// Commit only these paths so unrelated staged changes stay out.
		args := append([]string{"-C", root, "commit", "-m", msg, "--"}, byRepo[root]...)
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			return result, fmt.Errorf("git commit in %s failed: %v: %s", root, err, strings.TrimSpace(string(out)))
		}
		if err := pushGitRepo(root); err != nil {
			return result, fmt.Errorf("git push of %s failed: %w", root, err)
		}
	}
	return result, nil
}

// abiRebuildCommitMessage: "rebuild for libfoo ABI change (libfoo.so.3)".
func abiRebuildCommitMessage(reasons map[string][]string) string {
	libs := make([]string, 0, len(reasons))
	for lib := range reasons {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	parts := make([]string, 0, len(libs))
	for _, lib := range libs {
		parts = append(parts, fmt.Sprintf("%s (%s)", lib, strings.Join(reasons[lib], ", ")))
	}
	return "rebuild for " + strings.Join(parts, ", ") + " ABI change"
}

// handleABIRebuilds checks the recipes built in this run for dropped shared
// libraries and bumps the published packages linked against them. It
// returns the libraries whose change led to bumps, for the closing message.
func handleABIRebuilds(built []string, cfg *Config, logMsg func(string, ...interface{})) []string {
	if len(built) == 0 {
		return nil
	}
	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		colWarn.Printf("Warning: ABI check skipped, remote index unavailable: %v\n", err)
		return nil
	}
	arch := GetSystemArch(cfg)

	consumers := make(map[string][]string) // recipe -> libraries
	reasons := make(map[string][]string)   // library recipe -> removed sonames
	unknown := 0
	for _, pkgName := range built {
		brk, err := detectABIBreak(resolveBumpSourcePackage(pkgName), cfg, index)
		if err != nil {
			colWarn.Printf("Warning: ABI check of %s failed: %v\n", pkgName, err)
			continue
		}
		if len(brk.Removed) == 0 {
			continue
		}
		var names []string
		for _, lib := range brk.Removed {
			names = append(names, lib.Name)
		}
		colArrow.Print("-> ")
		colWarn.Printf("%s %s no longer provides %s\n", pkgName, brk.Version, strings.Join(names, ", "))
		found, missing := abiConsumers(index, arch, brk)
		unknown = missing
		if len(found) == 0 {
			continue
		}
		reasons[pkgName] = names
		for recipe, libs := range found {
			for _, lib := range libs {
				if !slices.Contains(consumers[recipe], lib) {
					consumers[recipe] = append(consumers[recipe], lib)
				}
			}
		}
	}
	if unknown > 0 && len(reasons) > 0 {
		colWarn.Printf("Warning: %d published packages have no libdeps in the index yet and were not checked; run `hokuto upload --reindex` once\n", unknown)
	}
	if len(consumers) == 0 {
		return nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Bumping the revision of %d package(s) for the ABI change\n", len(consumers))
	result, err := bumpABIConsumers(consumers, reasons)
	for _, skipped := range result.Skipped {
		colWarn.Printf("Warning: not bumped: %s\n", skipped)
	}
	if err != nil {
		colError.Printf("ABI rebuild bump failed: %v\n", err)
		logMsg("ABI_BUMP_FAILED: %v\n", err)
	}
	if len(result.Bumped) == 0 {
		return nil
	}
	logMsg("ABI_REBUILD_BUMPED: %s: %v\n", abiRebuildCommitMessage(reasons), result.Bumped)

	libs := make([]string, 0, len(reasons))
	for lib := range reasons {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	return libs
}

// printABIRebuildHint tells how to build what handleABIRebuilds bumped.
func printABIRebuildHint(libs []string) {
	if len(libs) == 0 {
		return
	}
	command := "hokuto update --build-missing-binaries"
	if os.Getenv("HOKUTO_BUILDER") == "1" {
		command = "hokuto-builder rebuild"
	}
	fmt.Println()
	colArrow.Print("-> ")
	colWarn.Printf("%s ABI update detected: run `%s` to rebuild and upload the bumped packages\n", strings.Join(libs, ", "), command)
}
