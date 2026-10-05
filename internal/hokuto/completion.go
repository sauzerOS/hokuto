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
// when local repositories or the remote mirror are unavailable. When the word
// being completed is pkg@..., it writes the versions of pkg the mirror has
// instead, as pkg@version (newest first).
func printInstallCompletionCandidates(cfg *Config, word string) {
	if name, _, ok := strings.Cut(word, "@"); ok {
		for _, version := range remoteInstallCompletionVersions(cfg, name) {
			fmt.Println(name + "@" + version)
		}
		return
	}
	for _, name := range installCompletionCandidates(cfg) {
		fmt.Println(name)
	}
}

func installCompletionCandidates(cfg *Config) []string {
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
	return result
}

func printLogCompletionCandidates(cfg *Config) {
	names := make(map[string]struct{})
	for _, name := range installCompletionCandidates(cfg) {
		names[name] = struct{}{}
	}
	installedRoot := filepath.Join(rootDir, "var", "db", "hokuto", "installed")
	if entries, err := os.ReadDir(installedRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				names[entry.Name()] = struct{}{}
			}
		}
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
	seen := make(map[string]bool)
	var names []string
	for _, e := range remoteCompletionEntries(cfg) {
		if !seen[e.name] {
			seen[e.name] = true
			names = append(names, e.name)
		}
	}
	sort.Strings(names)
	return names
}

// remoteInstallCompletionVersions lists the versions of pkgName the mirror
// has for this system's architecture, newest first.
func remoteInstallCompletionVersions(cfg *Config, pkgName string) []string {
	arch := GetSystemArchForPackage(cfg, pkgName)
	seen := make(map[string]bool)
	var versions []string
	for _, e := range remoteCompletionEntries(cfg) {
		if e.name == pkgName && e.arch == arch && !seen[e.version] {
			seen[e.version] = true
			versions = append(versions, e.version)
		}
	}
	sort.Slice(versions, func(i, j int) bool { return compareVersions(versions[i], versions[j]) > 0 })
	return versions
}

type completionEntry struct {
	name, arch, version string
}

// remoteCompletionEntries is the name, architecture and version of every
// package on the mirror, cached for ten minutes so a TAB does not download
// the index each time. A stale list remains useful while offline.
func remoteCompletionEntries(cfg *Config) []completionEntry {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		cacheRoot = os.TempDir()
	}
	cachePath := filepath.Join(cacheRoot, "hokuto", "install-completions-v2")
	readCache := func() []completionEntry {
		data, err := os.ReadFile(cachePath)
		if err != nil {
			return nil
		}
		var entries []completionEntry
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) == 3 {
				entries = append(entries, completionEntry{name: f[0], arch: f[1], version: f[2]})
			}
		}
		return entries
	}
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < 10*time.Minute {
		return readCache()
	}

	index, err := getCachedRemoteIndex(cfg, true)
	if err != nil {
		return readCache()
	}
	var entries []completionEntry
	var b strings.Builder
	seen := make(map[completionEntry]bool)
	for _, entry := range index {
		e := completionEntry{name: entry.Name, arch: entry.Arch, version: entry.Version}
		if e.name == "" || e.version == "" || seen[e] {
			continue
		}
		if e.arch == "" {
			e.arch = "-"
		}
		seen[e] = true
		entries = append(entries, e)
		fmt.Fprintf(&b, "%s %s %s\n", e.name, e.arch, e.version)
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err == nil {
		_ = os.WriteFile(cachePath, []byte(b.String()), 0o644)
	}
	return entries
}
