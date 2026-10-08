package hokuto

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// buildResultsEnv names a file each package build appends its result to, for
// unattended runs (hokuto-builder's service) that report what they built.
// One tab-separated line per package:
//
//	time  status  package  version-revision  arch  seconds  reason
//
// time is RFC 3339 (UTC), status is "success" or "failed", and reason is
// empty on success.
const buildResultsEnv = "HOKUTO_BUILD_RESULTS"

var (
	buildResultsMu       sync.Mutex
	buildResultsRecorded = make(map[string]bool)
)

// recordBuildResult appends pkgName's build result to the results file, when
// one is set.
func recordBuildResult(pkgName string, cfg *Config, buildErr error, elapsed time.Duration) {
	path := os.Getenv(buildResultsEnv)
	if path == "" {
		return
	}
	status, reason := "success", ""
	if buildErr != nil {
		status, reason = "failed", buildErr.Error()
	}
	line := buildResultLine(time.Now(), status, pkgName, buildResultVersion(pkgName), buildResultArch(pkgName, cfg), elapsed, reason)

	buildResultsMu.Lock()
	defer buildResultsMu.Unlock()
	buildResultsRecorded[pkgName] = true
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		debugf("Warning: cannot record the build result of %s in %s: %v\n", pkgName, path, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		debugf("Warning: cannot record the build result of %s in %s: %v\n", pkgName, path, err)
	}
}

// recordUnbuiltFailures records the failed packages that never reached a
// build, such as those blocked by a failed dependency.
func recordUnbuiltFailures(failed map[string]error, cfg *Config) {
	if os.Getenv(buildResultsEnv) == "" {
		return
	}
	for pkgName, err := range failed {
		buildResultsMu.Lock()
		recorded := buildResultsRecorded[pkgName]
		buildResultsMu.Unlock()
		if !recorded {
			recordBuildResult(pkgName, cfg, err, 0)
		}
	}
}

func buildResultLine(when time.Time, status, pkgName, version, arch string, elapsed time.Duration, reason string) string {
	// One line per result: the reason must not break the format.
	reason = strings.Join(strings.Fields(reason), " ")
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%s\n", when.UTC().Format(time.RFC3339), status, pkgName, version, arch, int64(elapsed.Seconds()), reason)
}

// buildResultVersion is the recipe's version-revision. Cross-system packages
// (aarch64-gcc) are built from their base recipe.
func buildResultVersion(pkgName string) string {
	pkgDir, err := findPackageMetadataDir(pkgName)
	if err != nil {
		if base := strings.TrimPrefix(pkgName, crossSyncPrefix); base != pkgName {
			pkgDir, err = findPackageMetadataDir(base)
		}
	}
	if err != nil {
		return "-"
	}
	version, revision, ok := readRecipeVersion(pkgDir)
	if !ok {
		return "-"
	}
	return version + "-" + revision
}

func buildResultArch(pkgName string, cfg *Config) string {
	if cfg == nil {
		cfg = &Config{Values: map[string]string{}}
	}
	return GetSystemArchForPackage(cfg, pkgName)
}
