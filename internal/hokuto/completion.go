package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// printInstallCompletionCandidates writes one installable package name per line.
// It deliberately emits no diagnostics: shell completion must remain parseable
// when local repositories or the remote mirror are unavailable.
func printInstallCompletionCandidates(cfg *Config) {
	names := make(map[string]struct{})
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" {
			names[name] = struct{}{}
		}
	}

	for _, repoPath := range filepath.SplitList(repoPaths) {
		entries, err := os.ReadDir(strings.TrimSpace(repoPath))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == ".git" {
				continue
			}
			add(entry.Name())
			for _, splitName := range splitPackageNamesFromDir(filepath.Join(repoPath, entry.Name())) {
				add(splitName)
			}
		}
	}

	// The binary index contains split outputs as independent entries, making it
	// both the authoritative split-package source and the fallback for systems
	// without a populated HOKUTO_PATH.
	for _, name := range remoteInstallCompletionNames(cfg) {
		add(name)
	}

	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	for _, name := range result {
		fmt.Println(name)
	}
}

func remoteInstallCompletionNames(cfg *Config) []string {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		cacheRoot = os.TempDir()
	}
	cachePath := filepath.Join(cacheRoot, "hokuto", "install-completions")
	readCache := func() []string {
		data, err := os.ReadFile(cachePath)
		if err != nil {
			return nil
		}
		return strings.Fields(string(data))
	}
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < 10*time.Minute {
		return readCache()
	}

	var names []string
	if index, err := getCachedRemoteIndex(cfg, true); err == nil {
		seen := make(map[string]bool)
		for _, entry := range index {
			if entry.Name != "" && !seen[entry.Name] {
				seen[entry.Name] = true
				names = append(names, entry.Name)
			}
		}
		sort.Strings(names)
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
			_ = os.WriteFile(cachePath, []byte(strings.Join(names, "\n")+"\n"), 0o644)
		}
		return names
	}
	// A stale, previously verified list remains useful while offline.
	return readCache()
}
