package hokuto

import (
	"os"
	"path/filepath"
	"strings"
)

// Suggestions on a system whose packages are cross built.
//
// The build server compiles every recipe natively for x86_64, so any package
// a recipe suggests can be installed there. Packages for other architectures
// (aarch64) only exist for recipes prepared for cross builds; suggesting one
// that is not asks the user about a package the system cannot get.

// nativeBuildArch is the architecture the build server compiles natively.
const nativeBuildArch = "x86_64"

// suggestionInstallableOnArch reports whether pkgName can be installed on the
// system's architecture: a package published for it, or a recipe prepared for
// cross builds. Without an index or a recipe to go by, it says yes rather than
// hide a suggestion that might well be installable.
func suggestionInstallableOnArch(pkgName string, cfg *Config, noRemote bool) bool {
	arch := GetSystemArch(cfg)
	if arch == "" || arch == nativeBuildArch {
		return true
	}

	indexKnown := false
	if !noRemote {
		if index, err := getCachedRemoteIndex(cfg, true); err == nil {
			indexKnown = true
			for _, entry := range index {
				if entry.Name != pkgName {
					continue
				}
				if entry.Type == "meta" || entry.Arch == arch {
					return true
				}
			}
		}
	}

	if pkgDir := suggestionRecipeDir(pkgName); pkgDir != "" {
		supported, _ := packageSupportsCrossBuild(pkgDir, loadBuildOptions(pkgDir))
		return supported
	}
	return !indexKnown
}

// suggestionRecipeDir returns the recipe that builds pkgName, a split output
// included, from the recipe repositories only: installed metadata says nothing
// about whether the recipe is prepared for cross builds.
func suggestionRecipeDir(pkgName string) string {
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		pkgDir := filepath.Join(repoPath, pkgName)
		if info, err := os.Stat(filepath.Join(pkgDir, "build")); err == nil && !info.IsDir() {
			return pkgDir
		}
	}
	if _, sourceDir, ok := findSplitPackageSource(pkgName); ok {
		return sourceDir
	}
	return ""
}

// filterSuggestionForArch drops the alternatives of item that cannot be
// installed on the system's architecture and reports whether any are left.
// known caches the answer per package for one round of suggestions.
func filterSuggestionForArch(item packageSuggestion, cfg *Config, noRemote bool, known map[string]bool) (packageSuggestion, bool) {
	var kept []string
	for _, name := range item.Alternates {
		installable, ok := known[name]
		if !ok {
			installable = suggestionInstallableOnArch(name, cfg, noRemote)
			known[name] = installable
		}
		if installable {
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		return item, false
	}
	if len(kept) != len(item.Alternates) {
		item.Alternates = kept
		item.Dependency = strings.Join(kept, " | ")
		if len(kept) == 1 && item.Op != "" && kept[0] == item.Name {
			item.Dependency += item.Op + item.Version
		}
	}
	return item, true
}
