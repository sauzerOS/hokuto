package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func isPerlModulePackageName(name string) bool {
	if !strings.HasPrefix(name, "perl-") {
		return false
	}
	// perl-N is a parallel interpreter identity, not a CPAN module.
	if base, _, versioned := splitVersionedPackageName(name); versioned && base == "perl" {
		return false
	}
	return true
}

func perlModuleSourceAvailable(name string) bool {
	pkgDir, err := findPackageDir(name)
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(pkgDir, "build"))
	return err == nil && !info.IsDir()
}

func orderPerlModulePackages(candidates map[string]bool) []string {
	// Topologically order modules so providers are rebuilt before
	// modules that depend on them. Cycles retain deterministic lexical order.
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	state := make(map[string]uint8, len(names))
	ordered := make([]string, 0, len(names))
	var visit func(string)
	visit = func(name string) {
		if state[name] == 2 {
			return
		}
		if state[name] == 1 {
			return
		}
		state[name] = 1
		if pkgDir, err := findPackageDir(name); err == nil {
			if deps, err := parseDependsFile(pkgDir); err == nil {
				var moduleDeps []string
				for _, dep := range deps {
					if candidates[dep.Name] {
						moduleDeps = append(moduleDeps, dep.Name)
					}
				}
				sort.Strings(moduleDeps)
				for _, dep := range moduleDeps {
					visit(dep)
				}
			}
		}
		state[name] = 2
		ordered = append(ordered, name)
	}
	for _, name := range names {
		visit(name)
	}
	return ordered
}

func installedPerlModulePackages() []string {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return nil
	}
	candidates := make(map[string]bool)
	for _, entry := range entries {
		if !entry.IsDir() || !isPerlModulePackageName(entry.Name()) {
			continue
		}
		if !perlModuleSourceAvailable(entry.Name()) {
			debugf("Skipping Perl module rebuild for %s: source recipe not found\n", entry.Name())
			continue
		}
		candidates[entry.Name()] = true
	}
	return orderPerlModulePackages(candidates)
}

func repositoryPerlModulePackages() []string {
	candidates := make(map[string]bool)
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !isPerlModulePackageName(entry.Name()) {
				continue
			}
			pkgDir := filepath.Join(repoPath, entry.Name())
			buildInfo, buildErr := os.Stat(filepath.Join(pkgDir, "build"))
			versionInfo, versionErr := os.Stat(filepath.Join(pkgDir, "version"))
			if buildErr != nil || versionErr != nil || buildInfo.IsDir() || versionInfo.IsDir() {
				continue
			}
			candidates[entry.Name()] = true
		}
	}
	return orderPerlModulePackages(candidates)
}

func automaticRebuildTriggers(triggerPkg string, wasInstalled bool) []string {
	if triggerPkg != "perl" || !wasInstalled {
		return nil
	}
	return installedPerlModulePackages()
}

func handlePerlRebuildCommand(cfg *Config) error {
	colArrow.Print("-> ")
	colSuccess.Println("Scanning repositories for Perl modules to rebuild")
	modules := repositoryPerlModulePackages()
	if len(modules) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No Perl module recipes found in HOKUTO_PATH.")
		return nil
	}
	colArrow.Print("-> ")
	colSuccess.Printf("Rebuilding %d Perl module(s): %s\n", len(modules), strings.Join(modules, ", "))
	// This is a repository-wide package rebuild. Do not install modules that
	// were absent before the command; the automatic Perl-upgrade trigger handles
	// rebuilding and reinstalling the installed subset.
	args := append([]string{"--no-install"}, modules...)
	if err := handleBuildCommand(args, cfg); err != nil {
		return fmt.Errorf("failed to rebuild Perl modules: %w", err)
	}
	return nil
}
