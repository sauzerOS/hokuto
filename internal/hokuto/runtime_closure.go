package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Builds install runtime dependencies from binaries only, and skip one that
// has no binary on the mirror. The package that needs it is then installed
// without it, and stays that way: later builds only check that their direct
// build dependencies are installed. The hokuto-builder container lost glycin
// that way, which broke gtk+3's pkg-config chain (gdk-pixbuf requires
// glycin-2) and made qemu build without its GTK UI. So a skipped dependency
// is reported, and every build first repairs the runtime dependencies of what
// it is about to build against.

var warnedMissingRuntimeDeps sync.Map

// warnMissingRuntimeDependency reports, once per pair, that depName could not
// be installed for pkgName because no binary of it is available.
func warnMissingRuntimeDependency(depName, pkgName string) {
	if _, seen := warnedMissingRuntimeDeps.LoadOrStore(depName+"\x00"+pkgName, true); seen {
		return
	}
	prepareDependencyProgressLogOutput()
	fmt.Fprint(os.Stderr, colArrow.Sprint("-> "))
	fmt.Fprintln(os.Stderr, colWarn.Sprintf("Warning: runtime dependency %s of %s has no binary available; %s is installed without it", depName, pkgName, pkgName))
}

// hostLineOfCrossSystemPackage reports whether depName, a runtime dependency
// recorded for pkgName, is one of the native lines a cross-system library
// package (aarch64-foo) carries over from its recipe. Those name host
// packages the sysroot copy does not use; its real dependencies carry its own
// prefix. A cross toolchain package (option host-tool: aarch64-gcc,
// aarch64-binutils) is different: its programs run on the host and need its
// native dependencies (gmp, mpfr, zstd, ...).
func hostLineOfCrossSystemPackage(pkgName, depName string) bool {
	prefix := archPrefixOf(pkgName)
	if prefix == "" || archPrefixOf(depName) == prefix {
		return false
	}
	return !crossSystemHostTool(pkgName, prefix)
}

// crossSystemHostTool reports whether the cross-system package pkgName is
// built with the host-tool option, from its installed copy or its recipe.
func crossSystemHostTool(pkgName, prefix string) bool {
	if info, err := os.Stat(filepath.Join(Installed, pkgName, "options")); err == nil && !info.IsDir() {
		return loadBuildOptions(filepath.Join(Installed, pkgName))["host-tool"]
	}
	if dir, err := findPackageMetadataDir(strings.TrimPrefix(pkgName, prefix)); err == nil {
		return loadBuildOptions(dir)["host-tool"]
	}
	return false
}

// missingInstalledRuntimeDeps walks the installed runtime dependencies of
// roots and returns the ones that are not installed, with the installed
// packages that need them. Only installed packages are followed: a root that
// is not installed is the build's own business.
func missingInstalledRuntimeDeps(roots []string, cfg *Config) map[string][]string {
	missing := make(map[string][]string)
	visited := make(map[string]bool)
	queue := append([]string(nil), roots...)
	for len(queue) > 0 {
		pkgName := queue[0]
		queue = queue[1:]
		if visited[pkgName] {
			continue
		}
		visited[pkgName] = true
		installedName := findInstalledDependencySatisfying(pkgName, "", "")
		if installedName == "" {
			continue
		}
		deps, err := parseDependsFile(filepath.Join(Installed, installedName))
		if err != nil {
			continue
		}
		// A cross-system package (aarch64-foo) also records its recipe's
		// native lines, which name host packages it does not use; its real
		// dependencies are the aarch64-* ones, cross-tagged or detected from
		// its libraries. Everything else follows only its native lines.
		for _, dep := range deps {
			if dep.Make || dep.Optional || dep.Rebuild || dep.PostInstall || dep.Suggest {
				continue
			}
			if archPrefixOf(installedName) != "" {
				if len(dep.Alternatives) > 0 || hostLineOfCrossSystemPackage(installedName, dep.Name) {
					continue
				}
			} else if dep.Cross || dep.CrossNative {
				continue
			}
			candidates := dep.Alternatives
			if len(candidates) == 0 {
				candidates = []string{dep.Name}
			}
			satisfiedBy := ""
			for _, cand := range candidates {
				if cand == "" || shouldSkipMultilibMakeDep(dep, cand, cfg) {
					continue
				}
				if found := findInstalledDependencySatisfying(cand, dep.Op, dep.Version); found != "" {
					satisfiedBy = found
					break
				}
			}
			if satisfiedBy != "" {
				queue = append(queue, satisfiedBy)
				continue
			}
			if len(dep.Alternatives) > 0 || dep.Name == "" {
				// An unsatisfied alternative group needs a choice; leave it to
				// the user rather than pick one here.
				continue
			}
			missing[dep.Name] = append(missing[dep.Name], installedName)
		}
	}
	return missing
}

// repairInstalledRuntimeDeps installs, from binaries, the runtime dependencies
// missing below the build dependencies of plan, and returns what it installed.
// A dependency that has no binary is warned about and left out, unless the
// plan builds it.
//
// A package the plan builds is installed when built, but that can be after
// the builds that need it: building openal, harfbuzz and glycin in that
// order, gdk-pixbuf (under ffmpeg, under openal's examples) had no glycin
// when openal linked, since glycin's new revision was not published yet. Its
// published binary, of an older revision if need be, is installed now and
// replaced by the build.
func repairInstalledRuntimeDeps(plan *BuildPlan, cfg *Config, noRemote, quiet bool) []string {
	missing := missingInstalledRuntimeDeps(buildDependencyRoots(plan, cfg), cfg)
	planned := providedByPlan(plan, cfg)
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for name := range missing {
		names = append(names, name)
	}
	sort.Strings(names)

	// Usual for a binary build dependency, whose package lists runtime
	// dependencies its recipe does not (rust needs clang and lld), so this
	// is only worth a warning for one that cannot be installed below.
	debugf("Installing runtime dependencies of build dependencies: %s\n", formatMissingRuntimeDeps(names, missing))

	var installed []string
	for _, name := range names {
		// The build dependency policy: the current revision's binary, or an
		// older one while the current revision is not published yet.
		// In a cross session a plain name is a host package: look it up
		// natively, not as a target binary.
		ok, err := installAvailableBuildDependencyBinaryWithOptions(name, packageBuildConfig(name, cfg), noRemote, quiet, true)
		if err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to install %s: %v\n", name, err)
			continue
		}
		if ok {
			installed = append(installed, name)
			continue
		}
		// An earlier repair in this loop may have installed it as one of
		// its own dependencies.
		if _, built := planned[name]; !built && !isPackageInstalled(name) {
			warnMissingRuntimeDependency(name, strings.Join(missing[name], ", "))
		}
	}
	return installed
}

func formatMissingRuntimeDeps(names []string, missing map[string][]string) string {
	parts := make([]string, 0, len(names))
	for _, name := range names {
		needers := append([]string(nil), missing[name]...)
		sort.Strings(needers)
		parts = append(parts, fmt.Sprintf("%s (needed by %s)", name, strings.Join(needers, ", ")))
	}
	return strings.Join(parts, ", ")
}

// buildDependencyRoots lists what the packages of plan that are compiled here
// build against: their active build dependencies and, when they need it,
// base-devel.
func buildDependencyRoots(plan *BuildPlan, cfg *Config) []string {
	if plan == nil {
		return nil
	}
	seen := make(map[string]bool)
	var roots []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			roots = append(roots, name)
		}
	}
	var compiled []string
	for _, pkgName := range plan.Order {
		if plan.BinaryPackages[pkgName] {
			continue
		}
		compiled = append(compiled, pkgName)
		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			continue
		}
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if !activeBuildDependency(dep, cfg, false) {
				continue
			}
			candidates, err := resolvedBuildDependencyCandidates(dep, false, cfg)
			if err != nil {
				continue
			}
			for _, cand := range candidates {
				add(cand)
			}
		}
	}
	if len(compiled) > 0 && packageSetNeedsDevelPackages(compiled) {
		for _, pkgName := range requiredDevelPackages(cfg, packageSetHasBuildOption(compiled, "multilib")) {
			add(pkgName)
		}
	}
	return roots
}

// providedByPlan lists the packages plan installs or builds, with the split
// outputs of the sources it builds.
func providedByPlan(plan *BuildPlan, cfg *Config) map[string]bool {
	provided := make(map[string]bool)
	if plan == nil {
		return provided
	}
	for _, pkgName := range plan.Order {
		provided[pkgName] = true
		provided[getOutputPackageName(pkgName, cfg)] = true
		if pkgDir, err := findPackageDir(pkgName); err == nil {
			for _, split := range splitPackageNamesFromDir(pkgDir) {
				provided[split] = true
			}
		}
	}
	return provided
}
