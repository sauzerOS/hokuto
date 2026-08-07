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
		path := filepath.Join(repoPath, equivalentsFile)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
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

func loadPackageEquivalentPairs() ([]packageEquivalentPair, error) {
	key := repoPaths + "\x00" + Installed
	packageEquivalentCache.Lock()
	defer packageEquivalentCache.Unlock()
	if packageEquivalentCache.valid && packageEquivalentCache.key == key {
		return append([]packageEquivalentPair(nil), packageEquivalentCache.pairs...), packageEquivalentCache.err
	}
	pairs, err := loadPackageEquivalentPairsUncached()
	packageEquivalentCache.key = key
	packageEquivalentCache.valid = true
	packageEquivalentCache.pairs = append([]packageEquivalentPair(nil), pairs...)
	packageEquivalentCache.err = err
	return pairs, err
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

func equivalentDependencyNames(name, consumer string) []string {
	pair, ok := packageEquivalentPairFor(name)
	if !ok {
		return []string{name}
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
