package hokuto

import (
	"fmt"
	"path/filepath"
	"strings"
)

// A dependency with a version constraint (glew<2.3) may need an older
// release than the current one. A build satisfies it with that release,
// installed next to the current one under a parallel name (glew-2, the
// major line). Installing a package from the mirror used to ignore the
// constraint: "glew<2.3" became "glew", the current 2.3.1, and a package
// that recorded the parallel name "glew-2" got the newest 2.x, 2.3.1 again,
// looked up under an archive name that does not exist
// (glew-2-2.3.1-1-x86_64-optimized.tar.zst). The release is now chosen from
// the remote index.

// pinnedReleaseFor names the release to install for a constrained
// dependency when the newest one on the mirror does not satisfy it: the
// newest release that does, as name@version-revision ("glew@2.2.0-1"),
// which is fetched under its own archive name and installed under its
// parallel name (glew-2). A parallel name recorded without a constraint
// (libsigc++-2, from libsigc++<3) stands for the newest release of its
// line; when that is the current release, the plain name is returned.
// It returns false when there is nothing to pin: no constraint, the newest
// release satisfies it (the dependency is resolved as usual), or nothing on
// the mirror does.
func pinnedReleaseFor(name, op, version string, cfg *Config, remoteIndex []RepoEntry) (string, bool) {
	if name == "" || strings.Contains(name, "@") || (op == "") != (version == "") {
		return "", false
	}
	if op == "" {
		if _, _, versioned := splitVersionedPackageName(name); !versioned {
			return "", false
		}
	}
	if len(remoteIndex) == 0 {
		if BinaryMirror == "" {
			return "", false
		}
		index, err := GetCachedRemoteIndex(cfg)
		if err != nil {
			return "", false
		}
		remoteIndex = index
	}

	// A parallel name (glew-2) stands for its package, limited to its line.
	base, line := name, ""
	if b, l, ok := splitVersionedPackageName(name); ok && remoteHasPackage(b, remoteIndex) && !remoteHasPackage(name, remoteIndex) {
		base, line = b, l
	}
	if line == "" && op == "" {
		return "", false
	}
	// ==2.28* names its line as a parallel name does (atkmm-2.28).
	if line == "" && op == "==" {
		if prefix, wildcard := wildcardEqualityPrefix(version); wildcard {
			line = prefix
		}
	}

	arch := GetSystemArchForPackage(cfg, base)
	preferred := GetSystemVariantForPackage(cfg, base)
	accepted := map[string]bool{preferred: true}
	if !strings.Contains(preferred, "generic") {
		if strings.HasPrefix(preferred, "multi-") {
			accepted["multi-generic"] = true
		} else {
			accepted["generic"] = true
		}
	}

	// The local binary cache counts too: a release built here (a build
	// dependency from git history) is installable without the mirror.
	candidates := cachedReleaseEntries(base, arch, accepted)
	for i := range remoteIndex {
		candidates = append(candidates, remoteIndex[i])
	}

	var newest, best *RepoEntry
	better := func(candidate, current *RepoEntry) bool {
		if current == nil || isNewer(*candidate, *current) {
			return true
		}
		return candidate.Version == current.Version && candidate.Revision == current.Revision &&
			candidate.Variant == preferred && current.Variant != preferred
	}
	for i := range candidates {
		entry := &candidates[i]
		if entry.Type == "meta" || entry.Name != base || entry.Arch != arch || !accepted[entry.Variant] {
			continue
		}
		if better(entry, newest) {
			newest = entry
		}
		if line != "" && !versionMatchesPackageLine(entry.Version, line) {
			continue
		}
		if (op == "" || versionSatisfies(entry.Version, op, version)) && better(entry, best) {
			best = entry
		}
	}
	if newest == nil || best == nil {
		return "", false
	}
	if (op == "" || versionSatisfies(newest.Version, op, version)) && best.Version == newest.Version && best.Revision == newest.Revision {
		// The current release is the one: install it under its own name.
		if base != name {
			return base, true
		}
		return "", false
	}
	// Installed under the name a build gives it: the line the dependency
	// names (atkmm-2.28, from atkmm-2.28 or atkmm==2.28*), else the major
	// line (glew-2 for glew<2.3). Registered so its archive is looked up
	// as the package's own (glew-2.2.0-1-...), not glew-2-2.2.0-1-...
	installName := base + "-" + line
	if line == "" {
		installName = base + "-" + strings.SplitN(best.Version, ".", 2)[0]
	}
	registerParallelPackageName(installName, base)
	registerParallelPackageVersion(installName, best.Version)
	return fmt.Sprintf("%s@%s-%s", installName, best.Version, best.Revision), true
}

func remoteHasPackage(name string, remoteIndex []RepoEntry) bool {
	for i := range remoteIndex {
		if remoteIndex[i].Name == name {
			return true
		}
	}
	return false
}

// pinnedInstallName is the name a pinned release is installed under: the
// parallel name it carries (glew-2 for glew-2@2.2.0-1), or, for a plain
// pkg@version request, the major line parallelInstallPackageName gives it.
func pinnedInstallName(pinned string, cfg *Config) string {
	name, request, ok := strings.Cut(pinned, "@")
	if !ok {
		return pinned
	}
	version := request
	if dash := strings.LastIndex(request, "-"); dash != -1 && isNumericVersionLine(request[dash+1:]) {
		version = request[:dash]
	}
	return parallelInstallPackageName(name, version, cfg)
}

// locatePinnedBinaryTarball finds the archive of a pinned release
// (glew@2.2.0-1), cached or on the mirror, under its own archive name, to be
// installed under its parallel name.
func locatePinnedBinaryTarball(pinned string, cfg *Config, noRemote bool) (binaryTarball, bool, error) {
	installName := pinnedInstallName(pinned, cfg)
	if path, _, _, ok := findCachedRequestedBinaryTarball(pinned, cfg); ok {
		return cachedBinaryTarball(installName, path), true, nil
	}
	if noRemote || BinaryMirror == "" {
		return binaryTarball{}, false, nil
	}
	index, err := GetCachedRemoteIndex(cfg)
	if err != nil {
		return binaryTarball{}, false, nil
	}
	entry, err := GetRemotePackageEntry(pinned, cfg, index)
	if err != nil {
		return binaryTarball{}, false, nil
	}
	return remoteBinaryTarball(installName, entry, cfg), true, nil
}

// runtimeDepsLookupName is the name a binary's runtime dependencies are
// read under: a pinned release's own (glew@2.2.0-1), not those of the
// newest release of the name it is installed as (glew-2).
func runtimeDepsLookupName(requested, installName string) string {
	if strings.Contains(requested, "@") {
		return requested
	}
	return installName
}

// cachedReleaseEntries lists the releases of name in BinDir, read from the
// archive names (name-version-revision-arch-variant.tar.zst) without opening
// them.
func cachedReleaseEntries(name, arch string, variants map[string]bool) []RepoEntry {
	var entries []RepoEntry
	for variant := range variants {
		suffix := "-" + arch + "-" + variant + ".tar.zst"
		matches, _ := filepath.Glob(filepath.Join(BinDir, name+"-*"+suffix))
		for _, match := range matches {
			rest := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(match), name+"-"), suffix)
			dash := strings.LastIndex(rest, "-")
			if dash <= 0 || rest[0] < '0' || rest[0] > '9' {
				continue
			}
			version, revision := rest[:dash], rest[dash+1:]
			if !isNumericVersionLine(revision) {
				continue
			}
			entries = append(entries, RepoEntry{Name: name, Version: version, Revision: revision, Arch: arch,
				Variant: variant, Filename: filepath.Base(match)})
		}
	}
	return entries
}

// releasesNeededByDependents lists the archives an index must keep besides
// the newest release of each major line: for every constrained dependency
// (glew<2.3) or parallel name (glew-2) a published package records, the
// newest release that meets it, in each variant. "upload --cleanup" deleted
// those as old versions of the same major line (glew 2.2.0 next to 2.3.1),
// leaving the packages that need them uninstallable from the mirror.
func releasesNeededByDependents(index []RepoEntry) map[string]bool {
	type key struct{ name, arch, variant string }
	byPackage := make(map[key][]RepoEntry)
	names := make(map[string]bool)
	for _, entry := range index {
		if entry.Type == "meta" || entry.Filename == "" {
			continue
		}
		names[entry.Name] = true
		k := key{entry.Name, entry.Arch, entry.Variant}
		byPackage[k] = append(byPackage[k], entry)
	}

	needed := make(map[string]bool)
	keepNewestMeeting := func(base, line, op, version, arch string) {
		for k, entries := range byPackage {
			if k.name != base || k.arch != arch {
				continue
			}
			var best *RepoEntry
			for i := range entries {
				e := &entries[i]
				if line != "" && !versionMatchesPackageLine(e.Version, line) {
					continue
				}
				if op != "" && !versionSatisfies(e.Version, op, version) {
					continue
				}
				if best == nil || isNewer(*e, *best) {
					best = e
				}
			}
			if best != nil {
				needed[best.Filename] = true
			}
		}
	}

	for _, entry := range index {
		for _, dep := range depSpecsFromNames(append(append([]string(nil), entry.Depends...), entry.PostInstallDepends...)) {
			candidates := dep.Alternatives
			if len(candidates) == 0 {
				candidates = []string{dep.Name}
			}
			for _, name := range candidates {
				base, line := name, ""
				if b, l, ok := splitVersionedPackageName(name); ok && names[b] && !names[name] {
					base, line = b, l
				}
				if dep.Op == "" && line == "" {
					continue
				}
				keepNewestMeeting(base, line, dep.Op, dep.Version, entry.Arch)
			}
		}
	}
	return needed
}
