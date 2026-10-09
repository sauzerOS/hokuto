package hokuto

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const equivalentsFile = "equivalents"

type packageEquivalentPair struct {
	Base        string
	Replacement string
}

var packageEquivalentCache struct {
	sync.Mutex
	key   string
	valid bool
	pairs []packageEquivalentPair
	err   error
}

func invalidatePackageEquivalentCache() {
	packageEquivalentCache.Lock()
	packageEquivalentCache.valid = false
	packageEquivalentCache.pairs = nil
	packageEquivalentCache.err = nil
	packageEquivalentCache.Unlock()
}

func parsePackageEquivalentPairs(data []byte, source string) ([]packageEquivalentPair, error) {
	var pairs []packageEquivalentPair
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: expected exactly two package names", source, lineNo)
		}
		if fields[0] == fields[1] {
			return nil, fmt.Errorf("%s:%d: package cannot be equivalent to itself: %s", source, lineNo, fields[0])
		}
		pairs = append(pairs, packageEquivalentPair{Base: fields[0], Replacement: fields[1]})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", source, err)
	}
	return pairs, nil
}

func packageEquivalentSources() []string {
	var paths []string
	seen := make(map[string]bool)
	for _, repoPath := range strings.Split(repoPaths, ":") {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		candidates := []string{filepath.Join(repoPath, equivalentsFile)}
		// The file lives at the repository root, which for a repository
		// split into HOKUTO_PATH entries (sauzeros/core, sauzeros/extra) is
		// above them.
		if root := equivalentsRepoRoot(repoPath); root != "" && root != repoPath {
			candidates = append(candidates, filepath.Join(root, equivalentsFile))
		}
		for _, path := range candidates {
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}
	entries, _ := os.ReadDir(Installed)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(Installed, entry.Name(), equivalentsFile)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	return paths
}

// equivalentsRepoRoot returns the git repository root at or above a
// HOKUTO_PATH entry, looking two levels up at most, or "".
func equivalentsRepoRoot(repoPath string) string {
	dir := filepath.Clean(repoPath)
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func loadPackageEquivalentPairs() ([]packageEquivalentPair, error) {
	index := loadedRemoteIndex()
	key := repoPaths + "\x00" + Installed + "\x00" + remoteIndexIdentity(index)
	packageEquivalentCache.Lock()
	defer packageEquivalentCache.Unlock()
	if packageEquivalentCache.valid && packageEquivalentCache.key == key {
		return append([]packageEquivalentPair(nil), packageEquivalentCache.pairs...), packageEquivalentCache.err
	}
	pairs, err := loadPackageEquivalentPairsUncached()
	if err == nil {
		pairs = appendIndexEquivalentPairs(pairs, index)
	}
	packageEquivalentCache.key = key
	packageEquivalentCache.valid = true
	packageEquivalentCache.pairs = append([]packageEquivalentPair(nil), pairs...)
	packageEquivalentCache.err = err
	return pairs, err
}

// loadedRemoteIndex is the remote index this process has loaded, or nil. It
// never fetches: the pairs it adds are for runs that use the index anyway.
func loadedRemoteIndex() []RepoEntry {
	GlobalRemoteIndexMu.Lock()
	defer GlobalRemoteIndexMu.Unlock()
	if !GlobalRemoteIndexLoaded && GlobalRemoteIndex == nil {
		return nil
	}
	return GlobalRemoteIndex
}

// remoteIndexIdentity tells loaded indexes apart for the pair cache.
func remoteIndexIdentity(index []RepoEntry) string {
	if len(index) == 0 {
		return ""
	}
	return fmt.Sprintf("%p:%d", &index[0], len(index))
}

// appendIndexEquivalentPairs adds the pairs published in the remote index.
// A system that installs binaries without the recipe repositories (a fresh
// sonic-desktop install) otherwise does not know kcmutils' kcoreaddons
// dependency and sonic-frameworks-core-addons are equivalent, and asked to
// choose for every such dependency. Pairs from the repositories and
// installed packages take precedence; a published pair that names a package
// already in one is skipped.
func appendIndexEquivalentPairs(pairs []packageEquivalentPair, index []RepoEntry) []packageEquivalentPair {
	if len(index) == 0 {
		return pairs
	}
	member := make(map[string]bool, 2*len(pairs))
	for _, pair := range pairs {
		member[pair.Base] = true
		member[pair.Replacement] = true
	}
	for i := range index {
		if index[i].Equivalents == "" {
			continue
		}
		parsed, err := parsePackageEquivalentPairs([]byte(index[i].Equivalents), "remote index")
		if err != nil {
			continue
		}
		for _, pair := range parsed {
			if member[pair.Base] || member[pair.Replacement] {
				continue
			}
			member[pair.Base] = true
			member[pair.Replacement] = true
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

func loadPackageEquivalentPairsUncached() ([]packageEquivalentPair, error) {
	byMember := make(map[string]packageEquivalentPair)
	seenPair := make(map[string]bool)
	var result []packageEquivalentPair
	for _, path := range packageEquivalentSources() {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		pairs, err := parsePackageEquivalentPairs(data, path)
		if err != nil {
			return nil, err
		}
		for _, pair := range pairs {
			key := pair.Base + "\x00" + pair.Replacement
			reverseKey := pair.Replacement + "\x00" + pair.Base
			if seenPair[key] || seenPair[reverseKey] {
				continue
			}
			for _, member := range []string{pair.Base, pair.Replacement} {
				if existing, ok := byMember[member]; ok {
					return nil, fmt.Errorf("package %s belongs to multiple equivalence pairs (%s/%s and %s/%s)", member, existing.Base, existing.Replacement, pair.Base, pair.Replacement)
				}
			}
			seenPair[key] = true
			byMember[pair.Base] = pair
			byMember[pair.Replacement] = pair
			result = append(result, pair)
		}
	}
	return result, nil
}

func packageEquivalentPairFor(name string) (packageEquivalentPair, bool) {
	pairs, err := loadPackageEquivalentPairs()
	if err != nil {
		debugf("Ignoring invalid package equivalents: %v\n", err)
		return packageEquivalentPair{}, false
	}
	for _, pair := range pairs {
		if pair.Base == name || pair.Replacement == name {
			return pair, true
		}
	}
	return packageEquivalentPair{}, false
}

func packageUsesReplacementSide(pkgName string) bool {
	pairs, err := loadPackageEquivalentPairs()
	if err != nil {
		return false
	}
	for _, pair := range pairs {
		if pair.Replacement == pkgName {
			return true
		}
	}
	return false
}

// preferEquivalentReplacements is set for an install whose requested
// packages include the replacement side of a pair (installing sonic-desktop):
// its pairs then prefer the replacement for every consumer, so kcmutils gets
// sonic-frameworks-core-addons too instead of KDE's kcoreaddons. An installed
// side still wins (resolveAlternativeDep).
var preferEquivalentReplacements atomic.Bool

// preferEquivalentReplacementsFor sets preferEquivalentReplacements when one
// of names is a replacement-side package.
func preferEquivalentReplacementsFor(names []string) {
	for _, name := range names {
		if packageUsesReplacementSide(name) {
			preferEquivalentReplacements.Store(true)
			return
		}
	}
}

func equivalentDependencyNames(name, consumer string) []string {
	pair, ok := packageEquivalentPairFor(name)
	if !ok {
		return []string{name}
	}
	if preferEquivalentReplacements.Load() {
		return []string{pair.Replacement, pair.Base}
	}
	if packageUsesReplacementSide(consumer) {
		return []string{pair.Replacement, pair.Base}
	}
	if name == pair.Replacement {
		return []string{pair.Replacement, pair.Base}
	}
	return []string{pair.Base, pair.Replacement}
}

func findInstalledDependencySatisfying(name, op, refVersion string) string {
	if installed := findInstalledSatisfying(name, op, refVersion); installed != "" {
		return installed
	}
	if op != "" || refVersion != "" {
		return ""
	}
	pair, ok := packageEquivalentPairFor(name)
	if !ok {
		return ""
	}
	other := pair.Base
	if other == name {
		other = pair.Replacement
	}
	if checkPackageExactMatch(other) {
		return other
	}
	return ""
}

func expandPackageEquivalentDependencies(deps []DepSpec, consumer string) []DepSpec {
	for i := range deps {
		dep := &deps[i]
		if dep.Op != "" || dep.Version != "" || len(dep.Alternatives) > 0 || dep.Name == "" {
			continue
		}
		names := equivalentDependencyNames(dep.Name, consumer)
		if len(names) < 2 {
			continue
		}
		dep.Name = names[0]
		dep.Alternatives = names
	}
	return deps
}

func isPackageEquivalentAlternative(dep DepSpec) bool {
	if len(dep.Alternatives) != 2 {
		return false
	}
	pair, ok := packageEquivalentPairFor(dep.Alternatives[0])
	if !ok {
		return false
	}
	return (dep.Alternatives[0] == pair.Base && dep.Alternatives[1] == pair.Replacement) ||
		(dep.Alternatives[0] == pair.Replacement && dep.Alternatives[1] == pair.Base)
}

func packageEquivalentMetadata(pkgName string) ([]byte, error) {
	pairs, err := loadPackageEquivalentPairs()
	if err != nil {
		return nil, err
	}
	for _, pair := range pairs {
		if pair.Base == pkgName || pair.Replacement == pkgName {
			return []byte(pair.Base + " " + pair.Replacement + "\n"), nil
		}
	}
	// A cross-system package (aarch64-xorg-server) is exclusive with the
	// other side's cross-system package in the same sysroot; the pair must
	// name it, or installing it fails ("equivalence metadata xorg-server/xlibre
	// does not contain package aarch64-xorg-server").
	if prefix := archPrefixOf(pkgName); prefix != "" {
		base := strings.TrimPrefix(pkgName, prefix)
		for _, pair := range pairs {
			if pair.Base == base || pair.Replacement == base {
				return []byte(prefix + pair.Base + " " + prefix + pair.Replacement + "\n"), nil
			}
		}
	}
	return nil, nil
}

func writePackageEquivalentMetadata(pkgName, installedDir string, execCtx *Executor) error {
	data, err := packageEquivalentMetadata(pkgName)
	if err != nil || len(data) == 0 {
		return err
	}
	return writeRootFile(filepath.Join(installedDir, equivalentsFile), data, 0o644, execCtx)
}

func stagedPackageEquivalentConflicts(stagingMetadataDir, pkgName string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(stagingMetadataDir, equivalentsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	pairs, err := parsePackageEquivalentPairs(data, filepath.Join(stagingMetadataDir, equivalentsFile))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var conflicts []string
	for _, pair := range pairs {
		if pair.Base != pkgName && pair.Replacement != pkgName {
			return nil, fmt.Errorf("equivalence metadata %s/%s does not contain package %s", pair.Base, pair.Replacement, pkgName)
		}
		other := pair.Base
		if other == pkgName {
			other = pair.Replacement
		}
		if !seen[other] && checkPackageExactMatch(other) {
			seen[other] = true
			conflicts = append(conflicts, other)
		}
	}
	sort.Strings(conflicts)
	return conflicts, nil
}

func packageListedInWorld(path, pkgName string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == pkgName {
			return true
		}
	}
	return false
}

func removeInstalledEquivalentConflicts(stagingMetadataDir, pkgName string, cfg *Config, execCtx *Executor, yes bool, logger io.Writer) (transferWorld, transferWorldMake bool, err error) {
	conflicts, err := stagedPackageEquivalentConflicts(stagingMetadataDir, pkgName)
	if err != nil {
		return false, false, err
	}
	for _, conflict := range conflicts {
		if !yes && !askForConfirmation(colWarn, "-> %s replaces installed equivalent package %s. Replace it?", pkgName, conflict) {
			return transferWorld, transferWorldMake, fmt.Errorf("cannot install %s alongside equivalent package %s", pkgName, conflict)
		}
		transferWorld = transferWorld || packageListedInWorld(WorldFile, conflict)
		transferWorldMake = transferWorldMake || packageListedInWorld(WorldMakeFile, conflict)
		if err := pkgUninstall(conflict, cfg, execCtx, true, true, logger); err != nil {
			return transferWorld, transferWorldMake, fmt.Errorf("failed to remove equivalent package %s before installing %s: %w", conflict, pkgName, err)
		}
		if err := removeFromWorld(conflict); err != nil {
			return transferWorld, transferWorldMake, err
		}
		if err := removeFromWorldMake(conflict); err != nil {
			return transferWorld, transferWorldMake, err
		}
	}
	return transferWorld, transferWorldMake, nil
}
