package hokuto

import (
	"fmt"
	"sort"
	"strings"
)

func collectMetaPackageMissingBinaryTargets(meta MetaPackage, cfg *Config, noRemote bool) ([]string, map[string][]string, error) {
	var remoteIndex []RepoEntry
	if !noRemote && BinaryMirror != "" {
		index, err := GetCachedRemoteIndex(cfg)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot check remote binary availability: %w", err)
		}
		remoteIndex = index
	}

	missingSources := make(map[string]bool)
	splitTargets := make(map[string][]string)
	visited := make(map[string]bool)
	var walkPackage func(string, string, string) error
	walkPackage = func(pkgName, op, refVersion string) error {
		visitKey := strings.Join([]string{pkgName, op, refVersion}, "\x00")
		if visited[visitKey] {
			return nil
		}
		visited[visitKey] = true

		if nested, ok := findInstallMetaPackage(pkgName, cfg, remoteIndex, !noRemote); ok {
			for _, dep := range append(append([]DepSpec(nil), nested.Depends...), nested.Suggests...) {
				if err := walkMetaBuildDep(dep, cfg, walkPackage); err != nil {
					return err
				}
			}
			return nil
		}

		resolvedName := pkgName
		if op != "" && refVersion != "" {
			if source := findSourcePackageSatisfying(pkgName, op, refVersion); source != "" {
				resolvedName = source
			} else if version, _, err := getRepoVersion2(pkgName); err == nil && !versionSatisfies(version, op, refVersion) {
				versioned, err := prepareVersionedPackage(fmt.Sprintf("%s@%s%s", pkgName, op, refVersion))
				if err != nil {
					return err
				}
				resolvedName = versioned
			}
		}

		sourcePkg := resolvedName
		outputPkg := resolvedName
		isSplit := false
		pkgDir := ""
		if splitSource, splitDir, ok := findSplitPackageSource(resolvedName); ok && splitSource != resolvedName {
			sourcePkg, pkgDir, isSplit = splitSource, splitDir, true
		} else {
			var err error
			pkgDir, err = findPackageDir(resolvedName)
			if err != nil {
				return fmt.Errorf("package %s not found in repositories", resolvedName)
			}
		}

		var deps []DepSpec
		var err error
		if isSplit {
			deps, err = parsePackageDependsFile(pkgDir, resolvedName)
		} else {
			deps, err = parseDependsFile(pkgDir)
			outputPkg = getOutputPackageName(sourcePkg, cfg)
		}
		if err != nil {
			return fmt.Errorf("failed to parse dependencies for %s: %w", resolvedName, err)
		}
		for _, dep := range deps {
			if err := walkMetaBuildDep(dep, cfg, walkPackage); err != nil {
				return err
			}
		}

		version, revision, err := getRepoVersion2(sourcePkg)
		if err != nil {
			return err
		}
		if !currentBinaryOutputAvailable(sourcePkg, outputPkg, version, revision, cfg, remoteIndex) {
			missingSources[sourcePkg] = true
			if isSplit {
				addMappedSplitDependency(splitTargets, sourcePkg, outputPkg)
			}
		}
		return nil
	}

	for _, dep := range append(append([]DepSpec(nil), meta.Depends...), meta.Suggests...) {
		if err := walkMetaBuildDep(dep, cfg, walkPackage); err != nil {
			return nil, nil, err
		}
	}
	targets := make([]string, 0, len(missingSources))
	for pkgName := range missingSources {
		targets = append(targets, pkgName)
	}
	sort.Strings(targets)
	return targets, splitTargets, nil
}

func walkMetaBuildDep(dep DepSpec, cfg *Config, walk func(string, string, string) error) error {
	if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
		return nil
	}
	if dep.CrossNative && (cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1") {
		return nil
	}
	depName := dep.Name
	if len(dep.Alternatives) > 0 {
		resolved, err := resolveAlternativeDep(dep, true, cfg)
		if err != nil {
			return err
		}
		depName = resolved
	}
	if depName == "" || shouldSkipMultilibMakeDep(dep, depName, cfg) {
		return nil
	}
	return walk(depName, dep.Op, dep.Version)
}
