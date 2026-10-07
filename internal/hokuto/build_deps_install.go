package hokuto

import (
	"fmt"
)

// buildDepInstall is one package the build installs before compiling
// anything: a binary build dependency, one of its runtime dependencies, or a
// package that has no recipe here.
type buildDepInstall struct {
	name string // as the build needs it
	cfg  *Config
	// tarball is the binary to install; unset for the two cases below.
	tarball binaryTarball
	// splitSource is set for a split output installed from its source
	// package's binary (installAvailableSplitDependencyBinary).
	splitSource string
	// ensure: a package with no recipe, installed the general way.
	ensure bool
}

func (d buildDepInstall) isBinary() bool {
	return d.splitSource == "" && !d.ensure
}

// Installing the build dependencies used to happen while they were checked:
// each binary was downloaded, then installed, one after another, and its
// install pulled in its missing runtime dependencies from inside it, off the
// progress bar ("Checking glycin" sat there while other packages went in,
// then the bar jumped). Now the check only decides, from the remote index
// and the cache, what is installed. The plan then gets the binaries' missing
// runtime dependencies from the index, everything is downloaded at once, and
// installed in order, each one counted, as "hokuto install" does.

// withBuildDepRuntimeClosure inserts, before each binary of installs, the
// runtime (and post-install) dependencies its archive lists that are neither
// installed nor in the plan, as binaries under the build dependency policy.
// One that has no binary is left out: the install of the package that needs
// it handles it as before. Cross-system packages (aarch64-*) are left to that
// path too, which knows which of their dependencies are host packages.
func withBuildDepRuntimeClosure(installs []buildDepInstall, cfg *Config, noRemote bool) []buildDepInstall {
	var remoteIndex []RepoEntry
	if !noRemote && BinaryMirror != "" {
		if index, err := GetCachedRemoteIndex(cfg); err == nil {
			remoteIndex = index
		}
	}

	visited := make(map[string]bool)
	for _, d := range installs {
		visited[d.name] = true
		if d.isBinary() {
			visited[d.tarball.name] = true
		}
	}

	var out []buildDepInstall
	for _, d := range installs {
		if d.isBinary() && archPrefixOf(d.tarball.name) == "" {
			for _, name := range missingRuntimeDepsOfBinary(d, visited, remoteIndex, noRemote) {
				depCfg := packageBuildConfig(name, cfg)
				b, ok, err := locateBuildDependencyBinaryTarball(name, depCfg, noRemote)
				if err != nil || !ok {
					debugf("Runtime dependency %s of %s has no binary to plan; left to its install\n", name, d.tarball.name)
					continue
				}
				out = append(out, buildDepInstall{name: name, cfg: depCfg, tarball: b})
			}
		}
		out = append(out, d)
	}
	return out
}

// missingRuntimeDepsOfBinary lists, dependencies first, what the binary of d
// needs at run time that is not installed, from the index entry it comes
// from or, for a cached archive, the archive. visited is shared across the
// plan, so each package is planned once.
func missingRuntimeDepsOfBinary(d buildDepInstall, visited map[string]bool, remoteIndex []RepoEntry, noRemote bool) []string {
	var deps []DepSpec
	switch {
	case d.tarball.entry != nil && repoEntryHasDependencyMetadata(*d.tarball.entry):
		deps = append(depSpecsFromNames(d.tarball.entry.Depends), depSpecsFromNames(d.tarball.entry.PostInstallDepends)...)
	case d.tarball.entry == nil && d.tarball.path != "":
		scanned, err := scanTarballDependencySpecs(d.tarball.path)
		if err != nil {
			return nil
		}
		deps = scanned
	default:
		// An index entry from before dependency metadata: its install
		// finds them.
		return nil
	}

	deps = expandArchiveEquivalentDependencies(deps, d.tarball.name)

	var plan []string
	if err := resolveDependencyList(d.tarball.name, deps, visited, &plan, false, true, d.cfg, remoteIndex, !noRemote && len(remoteIndex) > 0); err != nil {
		debugf("Could not plan the runtime dependencies of %s: %v\n", d.tarball.name, err)
	}
	return plan
}

// installBuildDependencyPlan downloads the binaries of installs at once and
// installs everything in order under one progress bar. A split output whose
// binary fails to install is handed to scheduleSplitBuild, as before.
func installBuildDependencyPlan(installs []buildDepInstall, noRemote, quiet bool, addTemporaryBuildDep func(string), scheduleSplitBuild func(sourcePkg, depPkg string)) error {
	if len(installs) == 0 {
		return nil
	}

	var entries []RepoEntry
	for _, d := range installs {
		if d.isBinary() && d.tarball.entry != nil {
			entries = append(entries, *d.tarball.entry)
		}
	}
	prepareDependencyProgressLogOutput()
	prefetchRepoEntries(entries, installs[0].cfg)

	// A package's install leaves those still ahead in the plan to the plan,
	// as in "hokuto install".
	for _, d := range installs {
		installPlanPending.Store(d.name, true)
	}
	defer func() {
		for _, d := range installs {
			installPlanPending.Delete(d.name)
		}
	}()

	bar := newDependencyInstallProgress(len(installs), "Installing Build Dependencies", quiet)
	deactivateProgress := activateDependencyInstallProgress(bar)
	defer func() {
		clearDependencyInstallProgress(bar)
		deactivateProgress()
	}()

	for _, d := range installs {
		installPlanPending.Delete(d.name)
		describeDependencyInstallProgress(bar, d.name)
		if bar == nil {
			colArrow.Print("-> ")
			colSuccess.Print("Installing build dependency: ")
			colNote.Println(d.name)
		}
		if err := installBuildDependency(d, noRemote, quiet, addTemporaryBuildDep, scheduleSplitBuild); err != nil {
			return err
		}
		advanceDependencyInstallProgress(bar)
	}
	return nil
}

func installBuildDependency(d buildDepInstall, noRemote, quiet bool, addTemporaryBuildDep func(string), scheduleSplitBuild func(sourcePkg, depPkg string)) error {
	switch {
	case d.splitSource != "":
		installed, err := installAvailableSplitDependencyBinary(d.splitSource, d.name, d.cfg, noRemote, nil, quiet)
		if err != nil {
			colWarn.Printf("Warning: failed to install available binary dependency %s: %v\n", d.name, err)
			scheduleSplitBuild(d.splitSource, d.name)
			return nil
		}
		if installed {
			addTemporaryBuildDep(d.name)
		}
		return nil

	case d.ensure:
		installed, err := ensurePackageInstalledWithOptions(d.name, d.cfg, noRemote, nil, quiet)
		if err != nil {
			return fmt.Errorf("error: dependency %s has no source package and could not be installed as a binary package: %w", d.name, err)
		}
		if installed {
			addTemporaryBuildDep(d.name)
		}
		return nil
	}

	// Already in by now: a post-install dependency of an earlier package.
	if isPackageInstalled(d.tarball.name) {
		return nil
	}
	tarballPath, err := d.tarball.fetch(d.cfg)
	if err != nil {
		return fmt.Errorf("fatal error fetching binary %s: %v", d.name, err)
	}
	logger, fast := dependencyInstallLogger(quiet)
	isCriticalAtomic.Store(1)
	handlePreInstallUninstall(d.tarball.name, d.cfg, RootExec, false, logger)
	if _, err := pkgInstallWithRemotePolicy(tarballPath, d.tarball.name, d.cfg, RootExec, false, fast, false, noRemote, logger); err != nil {
		isCriticalAtomic.Store(0)
		return fmt.Errorf("fatal error installing binary %s: %v", d.name, err)
	}
	isCriticalAtomic.Store(0)
	addTemporaryBuildDep(d.tarball.name)
	return nil
}
