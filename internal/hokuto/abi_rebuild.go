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

// latestIndexEntries keeps, per package name and arch, only the entries of
// its newest version-revision: one per variant built at that version. Older
// packages still on the mirror, including an older build of another variant
// (1.1 optimized next to 1.2 generic), are left out.
func latestIndexEntries(index []RepoEntry) []RepoEntry {
	type key struct{ name, arch string }
	newest := make(map[key]RepoEntry)
	for _, e := range index {
		if e.Type == "meta" {
			continue
		}
		k := key{e.Name, e.Arch}
		if old, ok := newest[k]; !ok || isNewer(e, old) {
			newest[k] = e
		}
	}
	var entries []RepoEntry
	for _, e := range index {
		if e.Type == "meta" {
			continue
		}
		n := newest[key{e.Name, e.Arch}]
		if e.Version == n.Version && e.Revision == n.Revision {
			entries = append(entries, e)
		}
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
		if rebuildPending(recipe, e) {
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
func bumpABIConsumers(consumers map[string][]string, msg string) (abiRebuildResult, error) {
	var result abiRebuildResult
	names := make([]string, 0, len(consumers))
	for name := range consumers {
		names = append(names, name)
	}
	sort.Strings(names)

	byRepo := make(map[string][]string)
	linesByRepo := make(map[string][]string)
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
		linesByRepo[root] = append(linesByRepo[root], revisionBumpLine(name, bumped, "links "+strings.Join(consumers[name], ", ")))
	}

	for _, root := range repoOrder {
		if err := commitRevisionBumps(root, msg, linesByRepo[root], byRepo[root]); err != nil {
			return result, err
		}
		if err := pushGitRepo(root); err != nil {
			return result, fmt.Errorf("git push of %s failed: %w", root, err)
		}
	}
	return result, nil
}

// rebuildCommitMessage combines the soname breaks and private API changes of
// one run: "rebuild for libfoo (libfoo.so.3) ABI change; rebuild for qt 6.13
// private API".
func rebuildCommitMessage(reasons map[string][]string, privateReasons []string) string {
	var parts []string
	if len(reasons) > 0 {
		parts = append(parts, abiRebuildCommitMessage(reasons))
	}
	if len(privateReasons) > 0 {
		sorted := append([]string(nil), privateReasons...)
		sort.Strings(sorted)
		parts = append(parts, "rebuild for "+strings.Join(sorted, ", ")+" private API")
	}
	return strings.Join(parts, "; ")
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

// majorMinor is the "X.Y" of a version ("6.12.0" -> "6.12"), the part a
// library's private API compatibility is tied to.
func majorMinor(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}

// privateAPIChange is one library recipe whose new build changed its
// major.minor version, which ends the compatibility of its private API.
type privateAPIChange struct {
	Library  string   // recipe name, e.g. "qt"
	Version  string   // its new version
	Previous string   // its previously published version
	Sonames  []string // the libraries it ships, e.g. libQt6Gui.so.6
}

// detectPrivateAPIChange reports the shared libraries the just built recipe
// pkgName ships when its major.minor version differs from what is published.
// A first build, a patch release (6.12.0 -> 6.12.1) or a package without
// shared libraries reports nothing.
func detectPrivateAPIChange(pkgName string, cfg *Config, index []RepoEntry) (privateAPIChange, error) {
	change := privateAPIChange{Library: pkgName}
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return change, err
	}
	change.Version = version
	pkgDir, err := findPackageMetadataDir(pkgName)
	if err != nil {
		return change, err
	}
	outputs := append([]string{getOutputPackageName(pkgName, cfg)}, splitPackageNamesFromDir(pkgDir)...)
	current := RepoEntry{Version: version, Revision: revision}
	seen := make(map[string]bool)
	for _, output := range outputs {
		arch := GetSystemArchForPackage(cfg, output)
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
		if prev == nil || majorMinor(prev.Version) == majorMinor(version) {
			continue
		}
		change.Previous = prev.Version
		newTarball := findCachedBinaryTarballVersion(output, version, revision, cfg)
		if newTarball == "" {
			continue
		}
		paths, err := tarballSharedLibraryPaths(newTarball)
		if err != nil {
			return change, err
		}
		for _, p := range paths {
			name := path.Base(p)
			if !seen[name] {
				seen[name] = true
				change.Sonames = append(change.Sonames, name)
			}
		}
	}
	sort.Strings(change.Sonames)
	return change, nil
}

// privateAPIConsumers maps the recipes of the published arch packages that
// use private API of the changed library to the libraries concerned. unknown
// counts packages whose index entry has no privatedeps yet (not reindexed).
func privateAPIConsumers(index []RepoEntry, arch string, change privateAPIChange) (consumers map[string][]string, unknown int) {
	consumers = make(map[string][]string)
	ships := make(map[string]bool, len(change.Sonames))
	for _, soname := range change.Sonames {
		ships[soname] = true
	}
	for _, e := range latestIndexEntries(index) {
		if e.Arch != arch {
			continue
		}
		if e.MetadataVersion < repoEntryPrivateDepsMetadataVersion {
			unknown++
			continue
		}
		var hit []string
		for _, lib := range e.PrivateDeps {
			if ships[lib] && !slices.Contains(hit, lib) {
				hit = append(hit, lib)
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
		if sameSourcePackage(recipe, change.Library) {
			continue
		}
		if pkgDir, err := findPackageMetadataDir(recipe); err == nil && loadBuildOptions(pkgDir)["binary"] {
			continue
		}
		if rebuildPending(recipe, e) {
			continue
		}
		for _, lib := range hit {
			if !slices.Contains(consumers[recipe], lib) {
				consumers[recipe] = append(consumers[recipe], lib)
			}
		}
	}
	return consumers, unknown
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
	var privateReasons []string            // "qt 6.13"
	unknown, privateUnknown := 0, 0
	builtHere := make(map[string]bool, len(built))
	for _, pkgName := range built {
		builtHere[resolveBumpSourcePackage(pkgName)] = true
	}
	built = abiLibraryRecipes(built)
	addConsumers := func(found map[string][]string) {
		for recipe, libs := range found {
			// Built in this same run, so already against the new library.
			if builtHere[recipe] {
				continue
			}
			for _, lib := range libs {
				if !slices.Contains(consumers[recipe], lib) {
					consumers[recipe] = append(consumers[recipe], lib)
				}
			}
		}
	}
	for _, pkgName := range built {
		change, err := detectPrivateAPIChange(resolveBumpSourcePackage(pkgName), cfg, index)
		if err != nil {
			colWarn.Printf("Warning: private API check of %s failed: %v\n", pkgName, err)
		} else if len(change.Sonames) > 0 {
			found, missing := privateAPIConsumers(index, arch, change)
			privateUnknown = missing
			if len(found) > 0 {
				colArrow.Print("-> ")
				colWarn.Printf("%s %s -> %s: packages using its private API need a rebuild\n", pkgName, change.Previous, change.Version)
				privateReasons = append(privateReasons, fmt.Sprintf("%s %s", pkgName, majorMinor(change.Version)))
				addConsumers(found)
			}
		}
	}
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
		addConsumers(found)
	}
	if unknown > 0 && len(reasons) > 0 {
		colWarn.Printf("Warning: %d published packages have no libdeps in the index yet and were not checked; run `hokuto upload --reindex` once\n", unknown)
	}
	if privateUnknown > 0 && len(privateReasons) > 0 {
		colWarn.Printf("Warning: %d published packages have no privatedeps in the index yet and were not checked; run `hokuto upload --reindex` once\n", privateUnknown)
	}
	if len(consumers) == 0 {
		return nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Bumping the revision of %d package(s) for the ABI change\n", len(consumers))
	msg := rebuildCommitMessage(reasons, privateReasons)
	result, err := bumpABIConsumers(consumers, msg)
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
	logMsg("ABI_REBUILD_BUMPED: %s: %v\n", msg, result.Bumped)

	libs := make([]string, 0, len(reasons)+len(privateReasons))
	for lib := range reasons {
		libs = append(libs, lib)
	}
	libs = append(libs, privateReasons...)
	sort.Strings(libs)
	return libs
}

// abiLibraryRecipes leaves out the built recipes with the binary option: they
// ship prebuilt or bundled copies of libraries (proton's libdav1d.so.7) that
// nothing links against, so a library they drop is no ABI change.
func abiLibraryRecipes(built []string) []string {
	var kept []string
	for _, pkgName := range built {
		if pkgDir, err := findPackageMetadataDir(resolveBumpSourcePackage(pkgName)); err == nil && loadBuildOptions(pkgDir)["binary"] {
			debugf("ABI check: skipping %s, a binary recipe\n", pkgName)
			continue
		}
		kept = append(kept, pkgName)
	}
	return kept
}

// rebuildPending reports whether recipe's release is already ahead of its
// published package e: its rebuild is bumped and waiting, so a second check
// of the same library change (it runs on every publishing build) must not
// bump it again.
func rebuildPending(recipe string, e RepoEntry) bool {
	version, revision, err := getRepoVersion2(recipe)
	if err != nil {
		return false
	}
	return isNewer(RepoEntry{Version: version, Revision: revision}, e)
}

// abiRebuildLog receives handleABIRebuilds' log lines when the check runs at
// the end of a publishing build; bump points it at its log.
var abiRebuildLog = func(string, ...interface{}) {}

// abiRebuildHintDeferred is set while bump builds: it prints the rebuild
// hint itself, once, after all its builds.
var abiRebuildHintDeferred bool

// lastABIRebuildLibs collects what the publishing builds' ABI checks bumped
// consumers for, for bump's closing hint.
var lastABIRebuildLibs []string

// checkPublishedBuildABI is the ABI check of a publishing build (hokuto build
// --index: bump --build, hokuto-builder build): every requested recipe that
// now has a package of its current release is compared with its previous
// published package, and the published packages linked against a library it
// dropped get a revision bump. Run only from bump, a library updated any
// other way (a manual version bump, then hokuto-builder build) left its
// consumers linked against a library that no longer exists.
func checkPublishedBuildABI(recipes []string, cfg *Config) {
	var built []string
	for _, recipe := range recipes {
		if bumpedPackageBuilt(recipe, cfg) {
			built = append(built, recipe)
		}
	}
	libs := handleABIRebuilds(built, cfg, abiRebuildLog)
	lastABIRebuildLibs = append(lastABIRebuildLibs, libs...)
	if !abiRebuildHintDeferred {
		printABIRebuildHint(libs)
	}
}

// runningInHokutoBuilder reports whether hokuto runs in a hokuto-builder
// container, which sets HOKUTO_BUILDER=1.
func runningInHokutoBuilder() bool {
	return os.Getenv("HOKUTO_BUILDER") == "1"
}

// printABIRebuildHint tells how to build what handleABIRebuilds bumped.
func printABIRebuildHint(libs []string) {
	if len(libs) == 0 {
		return
	}
	command := "hokuto update --build-missing-binaries"
	if runningInHokutoBuilder() {
		command = "hokuto-builder rebuild"
	}
	fmt.Println()
	colArrow.Print("-> ")
	colWarn.Printf("%s ABI update detected: run `%s` to rebuild and upload the bumped packages\n", strings.Join(libs, ", "), command)
}
