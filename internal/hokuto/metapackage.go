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

func readInstalledMetaPackageMarker(name string) (MetaPackage, bool) {
	data, err := os.ReadFile(metaPackageMarkerPath(name))
	if err != nil {
		return MetaPackage{}, false
	}
	meta := MetaPackage{Name: name}
	var depLines []string
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
		}
	}
	deps, err := parseDependsData([]byte(strings.Join(depLines, "\n")))
	if err == nil {
		meta.Depends = deps
	}
	return meta, true
}

func findMetaPackage(name string) (MetaPackage, bool) {
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
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

func metaPackageDependsLines(meta MetaPackage) []string {
	lines := make([]string, 0, len(meta.Depends))
	for _, dep := range meta.Depends {
		lines = append(lines, depSpecLine(dep))
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
