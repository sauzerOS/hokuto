package hokuto

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// purgeOrphans lists the packages removing the packages in removing leaves
// orphaned: orphans then that are not orphans now. Orphans that predate the
// removal are left alone ("hokuto cleanup --orphans" is for those), and so
// are persistent make dependencies (world_make), kept on purpose. A package
// something installed and staying still depends on is kept too (a
// pre-existing orphan can depend on a package that only now loses its
// last other user).
func purgeOrphans(removing map[string]bool) ([]string, error) {
	before, err := findOrphans()
	if err != nil {
		return nil, err
	}
	after, err := findOrphansWithout(removing)
	if err != nil {
		return nil, err
	}
	wasOrphan := make(map[string]bool, len(before))
	for _, pkg := range before {
		wasOrphan[pkg] = true
	}
	worldMake := make(map[string]bool)
	if data, err := os.ReadFile(WorldMakeFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(line); t != "" {
				worldMake[t] = true
			}
		}
	}

	candidates := make(map[string]bool)
	for _, pkg := range after {
		if !wasOrphan[pkg] && !worldMake[pkg] && pkg != protectedBasePackage {
			candidates[pkg] = true
		}
	}

	// Drop, until nothing changes, every candidate an installed package
	// outside the removal still depends on.
	for changed := true; changed; {
		changed = false
		for pkg := range candidates {
			for _, dependent := range installedDependentNames(pkg) {
				if !removing[dependent] && !candidates[dependent] {
					delete(candidates, pkg)
					changed = true
					break
				}
			}
		}
	}

	orphans := make([]string, 0, len(candidates))
	for pkg := range candidates {
		orphans = append(orphans, pkg)
	}
	sort.Strings(orphans)
	return orphans, nil
}

// installedDependentNames lists the installed packages whose runtime
// dependencies name pkgName.
func installedDependentNames(pkgName string) []string {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return nil
	}
	var dependents []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == pkgName {
			continue
		}
		deps, err := getInstalledDeps(e.Name())
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep == pkgName {
				dependents = append(dependents, e.Name())
				break
			}
		}
	}
	return dependents
}

// runPurgeUninstall is "hokuto uninstall --purge": the packages and the
// orphans their removal leaves, asked about once and removed under one bar.
func runPurgeUninstall(packages []string, cfg *Config, force, yes bool) error {
	removing := make(map[string]bool, len(packages))
	for _, pkgName := range packages {
		if pkgName == protectedBasePackage {
			return fmt.Errorf("protected base filesystem package %s cannot be removed", pkgName)
		}
		if !isPackageInstalled(pkgName) && !isMetaPackageInstalled(pkgName) {
			return fmt.Errorf("package %s is not installed", pkgName)
		}
		removing[pkgName] = true
	}

	// What still needs a requested package stops the purge before anything
	// is asked or removed.
	if !force {
		for _, pkgName := range packages {
			if isMetaPackageInstalled(pkgName) {
				continue
			}
			if dependents := installedDependents(pkgName, cfg, removing); len(dependents) > 0 {
				return fmt.Errorf("cannot uninstall %s: other packages depend on it: %s", pkgName, strings.Join(dependents, ", "))
			}
		}
	}

	orphans, err := purgeOrphans(removing)
	if err != nil {
		return fmt.Errorf("failed to find the orphans of this removal: %w", err)
	}

	all := append(append([]string(nil), packages...), orphans...)
	var total int64
	sizes := make(map[string]int64, len(all))
	for _, pkgName := range all {
		if size, ok := installedPackageFootprint(pkgName); ok {
			sizes[pkgName] = size
			total += size
		}
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Attempting to uninstall: ")
	colNote.Println(strings.Join(packages, " "))
	if len(orphans) > 0 {
		colArrow.Print("-> ")
		colSuccess.Print("The following orphans will be removed ")
		fmt.Printf("[%d]", len(orphans))
		colSuccess.Print(": [")
		for i, pkg := range orphans {
			if i > 0 {
				colSuccess.Print(" ")
			}
			colNote.Print(pkg)
		}
		colSuccess.Println("]")
	}
	colArrow.Print("-> ")
	colSuccess.Print("Total Removed Size: ")
	colNote.Println(humanReadableSize(total))
	if !yes {
		colArrow.Print("-> ")
		question := colSuccess.Sprint("About to remove ") + colNote.Sprint(strings.Join(packages, ", ")) +
			colSuccess.Sprintf(" and %d orphan(s). Continue?", len(orphans))
		if !askForConfirmation(colSuccess, "%s", question) {
			colArrow.Print("-> ")
			colWarn.Println("Uninstall canceled.")
			return nil
		}
	}

	// Everything goes; each removal needs only the dependency check against
	// what stays. Dependents first.
	removalSet := make(map[string]bool, len(all))
	for _, pkgName := range all {
		removalSet[pkgName] = true
	}
	order := orderPackagesForUninstall(all)

	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)

	var progress *installProgress
	if !Debug {
		progress = newRemoveProgress(len(order))
	}
	var logger io.Writer
	if progress != nil {
		logger = io.Discard
	}

	var failed []string
	var freed int64
	removedAny := false
	for _, pkgName := range order {
		progress.start(pkgName)
		var removeErr error
		if isMetaPackageInstalled(pkgName) {
			removeErr = removeMetaPackageMarker(pkgName)
		} else {
			removeErr = pkgUninstallWithRemovalSet(pkgName, cfg, RootExec, force, true, logger, removalSet)
		}
		delete(removalSet, pkgName)
		if removeErr != nil {
			progress.endLine()
			colArrow.Print("-> ")
			colWarn.Printf("Failed to remove %s: %v\n", pkgName, removeErr)
			failed = append(failed, pkgName)
			progress.advance()
			continue
		}
		removeFromWorld(pkgName)
		removeFromWorldMake(pkgName)
		freed += sizes[pkgName]
		removedAny = true
		progress.advance()
	}
	progress.finish(len(failed) == 0)

	// Caches built from many packages' files (gdk-pixbuf loaders, icons,
	// desktop entries) must drop what was removed.
	if removedAny {
		if err := PostInstallTasks(RootExec, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "post-remove tasks completed with warnings: %v\n", err)
		}
	}

	colArrow.Print("-> ")
	if len(failed) > 0 {
		colWarn.Printf("Removed %d of %d packages, freed %s; failed: %s\n", len(order)-len(failed), len(order), humanReadableSize(freed), strings.Join(failed, ", "))
		return fmt.Errorf("%d package(s) could not be removed", len(failed))
	}
	colSuccess.Printf("All packages uninstalled, freed %s\n", humanReadableSize(freed))
	return nil
}
