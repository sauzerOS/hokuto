package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type MetaPackage struct {
	Name        string
	Description string
	Depends     []DepSpec
	Suggests    []DepSpec
}

func metaPackageDBDir() string {
	return filepath.Join(rootDir, "var", "db", "hokuto", "metapackages")
}

func metaPackageMarkerPath(name string) string {
	return filepath.Join(metaPackageDBDir(), name)
}

func isMetaPackageInstalled(name string) bool {
	info, err := os.Stat(metaPackageMarkerPath(name))
	return err == nil && !info.IsDir()
}

func packageOrMetaInstalled(name string) bool {
	return checkPackageExactMatch(name) || isMetaPackageInstalled(name)
}

func installMetaPackageMarker(meta MetaPackage) error {
	if err := os.MkdirAll(metaPackageDBDir(), 0o755); err != nil {
		if os.IsPermission(err) && os.Geteuid() != 0 {
			if runErr := RootExec.Run(exec.Command("mkdir", "-p", metaPackageDBDir())); runErr != nil {
				return runErr
			}
		} else {
			return err
		}
	}
	var b strings.Builder
	b.WriteString("name=" + meta.Name + "\n")
	if meta.Description != "" {
		b.WriteString("description=" + meta.Description + "\n")
	}
	for _, line := range metaPackageDependsLines(meta) {
		b.WriteString("depends=" + line + "\n")
	}
	for _, line := range metaPackageSuggestLines(meta) {
		b.WriteString("suggests=" + line + "\n")
	}
	path := metaPackageMarkerPath(meta.Name)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		if os.IsPermission(err) && os.Geteuid() != 0 {
			return writeRootFile(path, []byte(b.String()), 0o644, RootExec)
		}
		return err
	}
	return nil
}

func removeMetaPackageMarker(name string) error {
	err := os.Remove(metaPackageMarkerPath(name))
	if os.IsNotExist(err) {
		return nil
	}
	if os.IsPermission(err) && os.Geteuid() != 0 {
		return RootExec.Run(exec.Command("rm", "-f", metaPackageMarkerPath(name)))
	}
	return err
}

func installedMetaPackageNames() []string {
	entries, err := os.ReadDir(metaPackageDBDir())
	if err != nil {
		return nil
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func installedMetaPackages() []MetaPackage {
	names := installedMetaPackageNames()
	metas := make([]MetaPackage, 0, len(names))
	for _, name := range names {
		if meta, ok := findMetaPackage(name); ok {
			metas = append(metas, meta)
			continue
		}
		if meta, ok := readInstalledMetaPackageMarker(name); ok {
			metas = append(metas, meta)
		}
	}
	return metas
}

func findInstallMetaPackage(name string, cfg *Config, remoteIndex []RepoEntry, allowRemote bool) (MetaPackage, bool) {
	if meta, ok := findMetaPackage(name); ok {
		return meta, true
	}
	return findRemoteMetaPackage(name, cfg, remoteIndex, allowRemote)
}

func findRemoteMetaPackage(name string, cfg *Config, remoteIndex []RepoEntry, allowRemote bool) (MetaPackage, bool) {
	if !allowRemote {
		return MetaPackage{}, false
	}
	if len(remoteIndex) == 0 && BinaryMirror != "" {
		if idx, err := GetCachedRemoteIndex(cfg); err == nil {
			remoteIndex = idx
		}
	}
	for _, entry := range remoteIndex {
		if entry.Type != "meta" || entry.Name != name {
			continue
		}
		deps, err := parseDependsData([]byte(strings.Join(entry.Depends, "\n")))
		if err != nil {
			debugf("Warning: failed to parse remote meta package %s dependencies: %v\n", name, err)
			return MetaPackage{}, false
		}
		suggests, err := parseMetaPackageSuggests(entry.Suggests)
		if err != nil {
			debugf("Warning: failed to parse remote meta package %s suggestions: %v\n", name, err)
			return MetaPackage{}, false
		}
		return MetaPackage{
			Name:        entry.Name,
			Description: entry.Description,
			Depends:     deps,
			Suggests:    suggests,
		}, true
	}
	return MetaPackage{}, false
}

func localMetaPackageIndexEntries() []RepoEntry {
	metasByName := make(map[string]MetaPackage)
	for _, root := range metaPackageSearchRoots() {
		for _, rel := range []string{
			filepath.Join(".hokuto", "metapackages.toml"),
			filepath.Join(".hokuto", "metapackages"),
		} {
			metas, err := parseMetaPackageFile(filepath.Join(root, rel))
			if err != nil {
				debugf("Warning: failed to parse meta package manifest %s: %v\n", filepath.Join(root, rel), err)
				continue
			}
			for name, meta := range metas {
				if _, exists := metasByName[name]; !exists {
					metasByName[name] = meta
				}
			}
		}
	}

	names := make([]string, 0, len(metasByName))
	for name := range metasByName {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]RepoEntry, 0, len(names))
	for _, name := range names {
		meta := metasByName[name]
		entries = append(entries, RepoEntry{
			Name:        meta.Name,
			Type:        "meta",
			Version:     "0",
			Revision:    "0",
			Arch:        "meta",
			Variant:     "meta",
			Depends:     metaPackageDependsLines(meta),
			Suggests:    metaPackageSuggestLines(meta),
			Description: meta.Description,
		})
	}
	return entries
}

func syncMetaPackageIndexEntries(index map[string]RepoEntry) bool {
	changed := false

	desired := make(map[string]RepoEntry)
	for _, entry := range localMetaPackageIndexEntries() {
		desired[metaRepoEntryKey(entry)] = entry
	}

	for key, entry := range index {
		if entry.Type != "meta" {
			continue
		}
		if desiredEntry, ok := desired[key]; !ok || !repoEntriesEqual(entry, desiredEntry) {
			changed = true
		}
		delete(index, key)
	}

	for key, entry := range desired {
		if existing, ok := index[key]; !ok || !repoEntriesEqual(existing, entry) {
			changed = true
		}
		index[key] = entry
	}
	return changed
}

func repoEntriesEqual(a, b RepoEntry) bool {
	if a.Name != b.Name ||
		a.Type != b.Type ||
		a.Version != b.Version ||
		a.Revision != b.Revision ||
		a.Arch != b.Arch ||
		a.Variant != b.Variant ||
		a.Filename != b.Filename ||
		a.Size != b.Size ||
		a.B3Sum != b.B3Sum ||
		a.Description != b.Description ||
		len(a.Depends) != len(b.Depends) ||
		len(a.Suggests) != len(b.Suggests) {
		return false
	}
	for i := range a.Depends {
		if a.Depends[i] != b.Depends[i] {
			return false
		}
	}
	for i := range a.Suggests {
		if a.Suggests[i] != b.Suggests[i] {
			return false
		}
	}
	return true
}

func metaRepoEntryKey(entry RepoEntry) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s", entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant)
}

func readInstalledMetaPackageMarker(name string) (MetaPackage, bool) {
	data, err := os.ReadFile(metaPackageMarkerPath(name))
	if err != nil {
		return MetaPackage{}, false
	}
	meta := MetaPackage{Name: name}
	var depLines, suggestLines []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "description":
			meta.Description = value
		case "depends":
			depLines = append(depLines, value)
		case "suggests":
			suggestLines = append(suggestLines, value)
		}
	}
	deps, err := parseDependsData([]byte(strings.Join(depLines, "\n")))
	if err == nil {
		meta.Depends = deps
	}
	if suggests, err := parseMetaPackageSuggests(suggestLines); err == nil {
		meta.Suggests = suggests
	}
	return meta, true
}

func findMetaPackage(name string) (MetaPackage, bool) {
	for _, repoPath := range metaPackageSearchRoots() {
		for _, rel := range []string{
			filepath.Join(".hokuto", "metapackages.toml"),
			filepath.Join(".hokuto", "metapackages"),
		} {
			metas, err := parseMetaPackageFile(filepath.Join(repoPath, rel))
			if err != nil {
				debugf("Warning: failed to parse meta package manifest %s: %v\n", filepath.Join(repoPath, rel), err)
				continue
			}
			if meta, ok := metas[name]; ok {
				return meta, true
			}
		}
	}
	return MetaPackage{}, false
}

func metaPackageSearchRoots() []string {
	var roots []string
	seen := make(map[string]bool)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if seen[clean] {
			return
		}
		seen[clean] = true
		roots = append(roots, clean)
	}

	for _, repoPath := range filepath.SplitList(repoPaths) {
		add(repoPath)
		if parent := filepath.Dir(strings.TrimSpace(repoPath)); parent != "." && parent != "" {
			add(parent)
		}
	}
	return roots
}

func parseMetaPackageFile(path string) (map[string]MetaPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	metas := make(map[string]MetaPackage)
	var current string
	var multilineKey string
	var multilineValues []string
	flushMultiline := func() error {
		if current == "" || multilineKey == "" {
			return nil
		}
		meta := metas[current]
		if multilineKey == "depends" {
			deps, err := parseMetaPackageDepends(multilineValues)
			if err != nil {
				return err
			}
			meta.Depends = append(meta.Depends, deps...)
		} else if multilineKey == "suggests" || multilineKey == "suggest" {
			suggests, err := parseMetaPackageSuggests(multilineValues)
			if err != nil {
				return err
			}
			meta.Suggests = append(meta.Suggests, suggests...)
		}
		metas[current] = meta
		multilineKey = ""
		multilineValues = nil
		return nil
	}

	for _, raw := range strings.Split(string(data), "\n") {
		line := stripMetaPackageComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if multilineKey != "" {
			done := strings.Contains(line, "]")
			line = strings.TrimSuffix(line, "]")
			multilineValues = append(multilineValues, parseMetaPackageListValues(line)...)
			if done {
				if err := flushMultiline(); err != nil {
					return nil, err
				}
			}
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if err := flushMultiline(); err != nil {
				return nil, err
			}
			current = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if current == "" {
				return nil, fmt.Errorf("empty meta package section in %s", path)
			}
			if _, ok := metas[current]; !ok {
				metas[current] = MetaPackage{Name: current}
			}
			continue
		}

		if current == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		meta := metas[current]
		switch key {
		case "description":
			meta.Description = unquoteMetaPackageValue(value)
			metas[current] = meta
		case "depends":
			if strings.HasPrefix(value, "[") && !strings.Contains(value, "]") {
				multilineKey = "depends"
				multilineValues = append(multilineValues, parseMetaPackageListValues(strings.TrimPrefix(value, "["))...)
				metas[current] = meta
				continue
			}
			values := parseMetaPackageListValues(value)
			deps, err := parseMetaPackageDepends(values)
			if err != nil {
				return nil, err
			}
			meta.Depends = append(meta.Depends, deps...)
			metas[current] = meta
		case "suggests", "suggest":
			if strings.HasPrefix(value, "[") && !strings.Contains(value, "]") {
				multilineKey = key
				multilineValues = append(multilineValues, parseMetaPackageListValues(strings.TrimPrefix(value, "["))...)
				metas[current] = meta
				continue
			}
			values := parseMetaPackageListValues(value)
			suggests, err := parseMetaPackageSuggests(values)
			if err != nil {
				return nil, err
			}
			meta.Suggests = append(meta.Suggests, suggests...)
			metas[current] = meta
		}
	}
	if err := flushMultiline(); err != nil {
		return nil, err
	}
	return metas, nil
}

func stripMetaPackageComment(line string) string {
	inQuote := false
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if r == '#' && !inQuote {
			return line[:i]
		}
	}
	return line
}

func parseMetaPackageListValues(value string) []string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if value == "" {
		return nil
	}

	var values []string
	var b strings.Builder
	inQuote := false
	escaped := false
	for _, r := range value {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if (r == ',' || r == ' ' || r == '\t') && !inQuote {
			if token := strings.TrimSpace(b.String()); token != "" {
				values = append(values, token)
				b.Reset()
			}
			continue
		}
		b.WriteRune(r)
	}
	if token := strings.TrimSpace(b.String()); token != "" {
		values = append(values, token)
	}
	return values
}

func unquoteMetaPackageValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") {
		return strings.Trim(value, "\"")
	}
	return value
}

func parseMetaPackageDepends(values []string) ([]DepSpec, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return parseDependsData([]byte(strings.Join(values, "\n")))
}

func parseMetaPackageSuggests(values []string) ([]DepSpec, error) {
	if len(values) == 0 {
		return nil, nil
	}
	suggests := make([]DepSpec, 0, len(values))
	for _, value := range values {
		deps, err := parseDependsData([]byte(value))
		if err != nil {
			return nil, err
		}
		for _, dep := range deps {
			dep.Suggest = true
			suggests = append(suggests, dep)
		}
	}
	return suggests, nil
}

func metaPackageDependsLines(meta MetaPackage) []string {
	lines := make([]string, 0, len(meta.Depends))
	for _, dep := range meta.Depends {
		lines = append(lines, depSpecLine(dep))
	}
	return lines
}

func metaPackageSuggestLines(meta MetaPackage) []string {
	lines := make([]string, 0, len(meta.Suggests))
	for _, dep := range meta.Suggests {
		line := depSpecLine(dep) + " suggest"
		if dep.SuggestText != "" {
			line += " " + dep.SuggestText
		}
		lines = append(lines, line)
	}
	return lines
}

func depSpecLine(dep DepSpec) string {
	name := dep.Name
	if len(dep.Alternatives) > 1 {
		name = strings.Join(dep.Alternatives, " | ")
	}
	if dep.Op != "" {
		name += dep.Op + dep.Version
	}
	return name
}
