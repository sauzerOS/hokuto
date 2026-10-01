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
		for _, dep := range deps {
			if dep.Make || dep.Optional || dep.Rebuild || dep.PostInstall || dep.Suggest || dep.Cross || dep.CrossNative {
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
// missing below roots, and returns what it installed. A dependency that still
// has no binary is warned about and left out.
func repairInstalledRuntimeDeps(roots []string, cfg *Config, noRemote, quiet bool) []string {
	missing := missingInstalledRuntimeDeps(roots, cfg)
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for name := range missing {
		names = append(names, name)
	}
	sort.Strings(names)

	prepareDependencyProgressLogOutput()
	colArrow.Print("-> ")
	colWarn.Printf("Installed build dependencies are missing runtime dependencies: %s\n", formatMissingRuntimeDeps(names, missing))

	var installed []string
	for _, name := range names {
		ok, err := installRuntimeDependencyBinaryOnly(name, cfg, noRemote, nil, quiet)
		if err != nil {
			colArrow.Print("-> ")
			colWarn.Printf("Warning: failed to install %s: %v\n", name, err)
			continue
		}
		if !ok {
			warnMissingRuntimeDependency(name, strings.Join(missing[name], ", "))
			continue
		}
		installed = append(installed, name)
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
