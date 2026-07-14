package hokuto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// optionalBuildSnapshot records the exact optional dependency state observed
// when a package build starts. A dependency installed later by another
// parallel worker must not make an earlier build look feature-complete.
type optionalBuildSnapshot struct {
	Valid   bool
	Missing []string
	Present map[string][]string
}

func installedOptionalDependencyNames(dep DepSpec) []string {
	candidates := dep.Alternatives
	if len(candidates) == 0 {
		candidates = []string{dep.Name}
	}

	seen := make(map[string]bool)
	var installed []string
	for _, candidate := range candidates {
		name := ""
		if dep.Op != "" && dep.Version != "" {
			name = findInstalledSatisfying(candidate, dep.Op, dep.Version)
		} else if checkPackageExactMatch(candidate) {
			name = candidate
		} else {
			name = findInstalledPackageVariant(candidate)
		}
		if name != "" && !seen[name] {
			seen[name] = true
			installed = append(installed, name)
		}
	}
	sort.Strings(installed)
	return installed
}

func snapshotOptionalBuildDependencies(pkgDir string, cfg *Config) optionalBuildSnapshot {
	deps, err := parseDependsFile(pkgDir)
	if err != nil {
		return optionalBuildSnapshot{}
	}
	seen := make(map[string]bool)
	var missing []string
	present := make(map[string][]string)
	for _, dep := range deps {
		if !dep.Optional || !activeBuildDependency(dep, cfg, true) {
			continue
		}
		name := formatBuildDependency(dep)
		installed := installedOptionalDependencyNames(dep)
		if len(installed) != 0 {
			present[name] = installed
			continue
		}
		if name != "" && !seen[name] {
			seen[name] = true
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return optionalBuildSnapshot{Valid: true, Missing: missing, Present: present}
}

func readOptionalRebuildTracker() (map[string][]string, error) {
	data, err := os.ReadFile(OptionalRebuildFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}
	entries := make(map[string][]string)
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func lockOptionalRebuildTracker() (func(), error) {
	lockPath := filepath.Join(os.TempDir(), "hokuto-optional-rebuilds.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0666)
	if err != nil {
		return nil, err
	}
	_ = syscall.Fchmod(fd, 0666)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}, nil
}

func updateOptionalRebuildTracker(pkgName string, snapshot optionalBuildSnapshot) error {
	if !snapshot.Valid {
		return nil
	}
	unlock, err := lockOptionalRebuildTracker()
	if err != nil {
		return err
	}
	defer unlock()

	entries, err := readOptionalRebuildTracker()
	if err != nil {
		return err
	}
	if len(snapshot.Missing) == 0 {
		delete(entries, pkgName)
	} else {
		entries[pkgName] = append([]string(nil), snapshot.Missing...)
	}

	if len(entries) == 0 {
		if RootExec == nil {
			return nil
		}
		return removeFileAsRoot(OptionalRebuildFile, RootExec)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(OptionalRebuildFile), 0755); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return writeFileAsRoot(OptionalRebuildFile, data, 0644, RootExec)
}

func printOptionalRebuildReminders() {
	entries, err := readOptionalRebuildTracker()
	if err != nil || len(entries) == 0 {
		return
	}
	packages := make([]string, 0, len(entries))
	for pkgName := range entries {
		packages = append(packages, pkgName)
	}
	sort.Strings(packages)
	for _, pkgName := range packages {
		deps := append([]string(nil), entries[pkgName]...)
		sort.Strings(deps)
		for _, dep := range deps {
			fmt.Fprintln(os.Stderr, colArrow.Sprint("-> ")+colWarn.Sprintf("%s has not been rebuilt with optional dependency %s", pkgName, strings.TrimSpace(dep)))
		}
	}
}
