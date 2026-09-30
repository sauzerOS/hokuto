package hokuto

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"os/exec"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// GetSystemArch returns the current system architecture, normalized (e.g., x86_64, aarch64).
func GetSystemArch(cfg *Config) string {
	return GetSystemArchForPackage(cfg, "")
}

// GetSystemArchForPackage returns the appropriate architecture for a given package.
// If the package name starts with an architecture prefix (e.g., aarch64-curl), it returns that architecture.
func GetSystemArchForPackage(cfg *Config, pkgName string) string {
	// 1. Explicit package prefix detection
	// We handle prefixes like aarch64-, x86_64-
	if strings.HasPrefix(pkgName, "aarch64-") {
		return "aarch64"
	}
	if strings.HasPrefix(pkgName, "x86_64-") {
		return "x86_64"
	}

	// 2. Cross-compilation override
	if cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		arch := cfg.Values["HOKUTO_CROSS_ARCH"]
		if arch == "arm64" || arch == "aarch64" {
			return "aarch64"
		}
		if arch == "amd64" || arch == "x86_64" {
			return "x86_64"
		}
		return arch
	}

	// 3. System detection
	arch := cfg.Values["HOKUTO_ARCH"]
	if arch == "" {
		cmd := exec.Command("uname", "-m")
		out, err := cmd.Output()
		if err == nil {
			arch = strings.TrimSpace(string(out))
		} else {
			arch = runtime.GOARCH
		}
	}
	if arch == "amd64" {
		arch = "x86_64"
	}
	if arch == "arm64" {
		arch = "aarch64"
	}
	return arch
}

// GetSystemVariant returns "generic" if HOKUTO_GENERIC=1 is set in config, otherwise "optimized".
// If multilib is enabled and the package supports it, returns "multi-generic" or "multi-optimized".
func GetSystemVariant(cfg *Config) string {
	return GetSystemVariantForPackage(cfg, "")
}

// GetSystemVariantForPackage returns the variant string for a specific package.
// If multilib is enabled and the package supports it, returns "multi-generic" or "multi-optimized".
func GetSystemVariantForPackage(cfg *Config, pkgName string) string {
	baseVariant := "optimized"

	// Cross-packages (prefixed with architecture) or forced generic logic
	isCrossPkg := strings.HasPrefix(pkgName, "aarch64-") || strings.HasPrefix(pkgName, "x86_64-")

	// A package's own build options decide which variant it is finalized as,
	// so the lookup has to ask the same question the build did. Two gaps used
	// to make it answer "optimized" for things that were published "generic":
	//
	//   - a split package has no recipe directory of its own, so its options
	//     were never consulted at all; they live in the recipe that produces
	//     it (llvm-libs -> llvm).
	//   - only options["generic"] was honoured, while the build also turns
	//     aarch64 output generic for "nocrossopt" recipes and the cross modes.
	//
	// isGenericBuildVariant is the function the build itself uses, so defer to
	// it once the right options file has been located.
	isGenericOpt := false
	if pkgName != "" && cfg != nil {
		optionsDir := ""
		if pkgDir, err := findPackageMetadataDir(pkgName); err == nil && pkgDir != "" {
			optionsDir = pkgDir
		} else if _, sourceDir, ok := findSplitPackageSource(pkgName); ok {
			optionsDir = sourceDir
		}
		if optionsDir != "" {
			isGenericOpt = isGenericBuildVariant(GetSystemArchForPackage(cfg, pkgName), cfg, loadBuildOptions(optionsDir))
		}
	}

	if HokutoGeneric || cfg.Values["HOKUTO_GENERIC"] == "1" || cfg.Values["HOKUTO_CROSS_ARCH"] != "" || isCrossPkg || isGenericOpt {
		baseVariant = "generic"
	}

	// Check if multilib is enabled and package supports it
	// FIX: Disable multilib for cross builds to match build-time packaging logic
	if cfg.Values["HOKUTO_CROSS_ARCH"] == "" && cfg.Values["HOKUTO_MULTILIB"] == "1" && pkgName != "" && pkgName != "sauzeros-base" && !isCrossPkg {
		if isMultilibPackage(pkgName) {
			return "multi-" + baseVariant
		}
	}

	return baseVariant
}

// repoEntryMetadataVersion identifies entries whose archive metadata has been
// fully scanned. Increment it whenever ReadPackageMetadata gains a field that
// requires existing remote archives to be scanned again; `hokuto upload
// --reindex` then rescans the older entries.
//
//	1: depends
//	2: libdeps
const repoEntryMetadataVersion = 2

// repoEntryDependsMetadataVersion is the first metadata version with a
// scanned depends list. Clients check this one, not repoEntryMetadataVersion,
// so an index that has not been reindexed yet does not make them download
// packages just to read their dependencies.
const repoEntryDependsMetadataVersion = 1

// repoEntryLibdepsMetadataVersion is the first metadata version with a
// scanned libdeps list; older entries' Libdeps are unknown, not empty.
const repoEntryLibdepsMetadataVersion = 2

// RepoEntry represents a single package in the repository index.
type RepoEntry struct {
	Name     string   `json:"name"`
	Type     string   `json:"type,omitempty"`
	Version  string   `json:"version"`
	Revision string   `json:"revision"`
	Arch     string   `json:"arch"`
	Variant  string   `json:"variant"` // generic or optimized
	Filename string   `json:"filename"`
	Size     int64    `json:"size"`
	B3Sum    string   `json:"b3sum"`
	Depends  []string `json:"depends,omitempty"`
	// Libdeps are the shared libraries the package links against, as in its
	// libdeps file (elf64:libfoo.so.3). Known from metadata version 2 on.
	Libdeps         []string `json:"libdeps,omitempty"`
	Suggests        []string `json:"suggests,omitempty"`
	Description     string   `json:"description,omitempty"`
	MetadataVersion int      `json:"metadata_version,omitempty"`
}

// ReadPackageMetadata extracts pkginfo and computes checksum for a local tarball.
func ReadPackageMetadata(tarballPath string) (RepoEntry, error) {
	entry := RepoEntry{
		Filename:        filepath.Base(tarballPath),
		MetadataVersion: repoEntryMetadataVersion,
	}

	// 1. Compute checksum and size
	info, err := os.Stat(tarballPath)
	if err != nil {
		return entry, err
	}
	entry.Size = info.Size()

	sum, err := ComputeChecksum(tarballPath, nil)
	if err != nil {
		return entry, fmt.Errorf("failed to compute checksum: %w", err)
	}
	entry.B3Sum = sum

	// 2. Scan tarball once for all metadata (pkginfo, depends and libdeps)
	metadata, deps, libdeps, err := scanTarballMetadataWithLibdeps(tarballPath)
	if err != nil {
		return entry, fmt.Errorf("failed to scan tarball metadata: %w", err)
	}

	fillRepoEntryMetadata(&entry, metadata, deps, libdeps)
	return entry, nil
}

// fillRepoEntryMetadata sets the fields of entry that come from a package's
// pkginfo, depends and libdeps files.
func fillRepoEntryMetadata(entry *RepoEntry, metadata map[string]string, deps, libdeps []string) {
	entry.Name = metadata["name"]
	entry.Version = metadata["version"]
	entry.Revision = metadata["revision"]
	entry.Arch = metadata["arch"]
	entry.Variant = IdentifyVariant(entry.Name, metadata["generic"] == "1", metadata["multilib"] == "1")
	entry.Depends = deps
	entry.Libdeps = libdeps
}

// repoEntryFromPackageOutput is ReadPackageMetadata for a tarball hokuto has
// just created from outputDir: the metadata is read from the files the archive
// was made of instead of decompressing the archive to find them again.
func repoEntryFromPackageOutput(tarballPath, outputDir, pkgName string) (RepoEntry, error) {
	entry := RepoEntry{
		Filename:        filepath.Base(tarballPath),
		MetadataVersion: repoEntryMetadataVersion,
	}
	info, err := os.Stat(tarballPath)
	if err != nil {
		return entry, err
	}
	entry.Size = info.Size()
	if entry.B3Sum, err = ComputeChecksum(tarballPath, nil); err != nil {
		return entry, fmt.Errorf("failed to compute checksum: %w", err)
	}

	metaDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	pkginfo, err := os.ReadFile(filepath.Join(metaDir, "pkginfo"))
	if err != nil {
		return entry, err
	}
	var deps []string
	if data, err := os.ReadFile(filepath.Join(metaDir, "depends")); err == nil {
		deps = runtimeDependsForIndex(data, tarballPath)
	}
	libdeps := []string{}
	if data, err := os.ReadFile(filepath.Join(metaDir, "libdeps")); err == nil {
		libdeps = append(libdeps, libdepsForIndex(data)...)
	}
	fillRepoEntryMetadata(&entry, ParsePkgInfo(pkginfo), deps, libdeps)
	if entry.Name == "" || entry.Version == "" {
		return entry, fmt.Errorf("pkginfo in %s has no name or version", metaDir)
	}
	return entry, nil
}

// libdepsForIndex returns a libdeps file's entries as the index stores them.
func libdepsForIndex(data []byte) []string {
	var libdeps []string
	for _, line := range strings.Split(string(data), "\n") {
		if dep, ok := parseLibDepRef(line); ok {
			libdeps = append(libdeps, dep.String())
		}
	}
	return libdeps
}

// runtimeDependsForIndex returns the hard runtime dependencies of a depends
// file as the index stores them. source only labels a parse warning.
func runtimeDependsForIndex(data []byte, source string) []string {
	depSpecs, err := parseDependsData(data)
	if err != nil {
		debugf("Warning: failed to parse depends data for %s: %v\n", source, err)
		return nil
	}
	var dependencies []string
	for _, d := range depSpecs {
		if !d.Make && !d.Optional && !d.Rebuild && !d.PostInstall && !d.Suggest { // Only store hard runtime dependencies
			name := d.Name
			if len(d.Alternatives) > 1 {
				name = strings.Join(d.Alternatives, " | ")
			}
			dependencies = append(dependencies, name+d.Op+d.Version)
		}
	}
	return dependencies
}

// scanTarballMetadata reads pkginfo and depends files from a .tar.zst archive in one pass.
func scanTarballMetadata(tarballPath string) (map[string]string, []string, error) {
	metadata, deps, _, err := scanTarballMetadataWithLibdeps(tarballPath)
	return metadata, deps, err
}

// scanTarballMetadataWithLibdeps is scanTarballMetadata that also returns the
// package's libdeps entries. Only hokuto's own metadata directory counts, not
// a payload file that happens to be called libdeps.
func scanTarballMetadataWithLibdeps(tarballPath string) (map[string]string, []string, []string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()

	zsr, err := zstd.NewReader(f)
	if err != nil {
		return nil, nil, nil, err
	}
	defer zsr.Close()

	var metadata map[string]string
	libdeps := []string{}
	var dependencies []string

	tr := tar.NewReader(zsr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}

		if strings.HasSuffix(header.Name, "/libdeps") && strings.Contains(header.Name, "var/db/hokuto/installed/") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to read libdeps from %s: %w", tarballPath, err)
			}
			libdeps = append(libdeps, libdepsForIndex(data)...)
			continue
		}

		// 1. Look for pkginfo
		if strings.HasSuffix(header.Name, "/pkginfo") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to read pkginfo from %s: %w", tarballPath, err)
			}
			metadata = ParsePkgInfo(data)
			continue
		}

		// 2. Look for depends
		if strings.HasSuffix(header.Name, "/depends") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to read depends from %s: %w", tarballPath, err)
			}
			dependencies = append(dependencies, runtimeDependsForIndex(data, tarballPath)...)
			continue
		}
	}

	if metadata == nil {
		return nil, nil, nil, fmt.Errorf("pkginfo not found in %s", tarballPath)
	}

	return metadata, dependencies, libdeps, nil
}

func scanTarballDependencySpecs(tarballPath string) ([]DepSpec, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zsr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zsr.Close()

	tr := tar.NewReader(zsr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if strings.HasSuffix(header.Name, "/depends") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("failed to read depends from %s: %w", tarballPath, err)
			}
			return parseDependsData(data)
		}
	}

	return []DepSpec{}, nil
}

func ParsePkgInfo(data []byte) map[string]string {
	meta := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			meta[parts[0]] = parts[1]
		}
	}
	return meta
}

// IdentifyVariant returns the variant string (e.g., "optimized", "generic", "multi-optimized").
func IdentifyVariant(pkgName string, isGeneric bool, isMultilib bool) string {
	variant := "optimized"
	if isGeneric {
		variant = "generic"
	}
	if isMultilib && isMultilibPackage(pkgName) {
		variant = "multi-" + variant
	}
	return variant
}

// StandardizeRemoteName generates a consistent filename for the remote repository.
func StandardizeRemoteName(name, ver, rev, arch, variant string) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s.tar.zst", name, ver, rev, arch, variant)
}

// isNewer returns true if a is newer than b.
func isNewer(a, b RepoEntry) bool {
	cmp := compareVersions(a.Version, b.Version)
	if cmp > 0 {
		return true
	}
	if cmp < 0 {
		return false
	}
	// Revisions
	ar, _ := strconv.Atoi(a.Revision)
	br, _ := strconv.Atoi(b.Revision)
	return ar > br
}

// SaveRepoIndex writes the index to a JSON file.
func SaveRepoIndex(path string, index []RepoEntry) error {
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ParseRepoIndex reads the index from JSON data.
func ParseRepoIndex(data []byte) ([]RepoEntry, error) {
	var index []RepoEntry
	if len(data) == 0 {
		return index, nil
	}
	err := json.Unmarshal(data, &index)
	return index, err
}

func parseDependsData(content []byte) ([]DepSpec, error) {
	var dependencies []DepSpec
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if this line contains alternative dependencies (using |)
		if strings.Contains(line, "|") {
			// Parse alternative dependencies
			altDeps, err := parseAlternativeDeps(line)
			if err != nil {
				return nil, fmt.Errorf("failed to parse alternative dependencies: %w", err)
			}
			dependencies = append(dependencies, altDeps...)
		} else {
			// Regular dependency parsing
			name, op, ver, optional, rebuild, makeDep, cross, crossNative, noCross, runtimeOnly, postInstall, suggest, suggestText := parseDepToken(line)
			makeOpt := hasDependencyFlag(line, "makeopt")
			if name != "" {
				dependencies = append(dependencies, DepSpec{
					Name:         name,
					Op:           op,
					Version:      ver,
					Optional:     optional,
					Rebuild:      rebuild,
					Make:         makeDep || makeOpt,
					MakeOpt:      makeOpt,
					Cross:        cross,
					CrossNative:  crossNative,
					NoCross:      noCross,
					RuntimeOnly:  runtimeOnly,
					PostInstall:  postInstall,
					Suggest:      suggest,
					SuggestText:  suggestText,
					Alternatives: nil,
				})
			}
		}
	}

	return dependencies, nil
}

// parseAlternativeDeps parses a line with alternative dependencies like "rust | rustup make"
// Returns a single DepSpec with Alternatives populated
func parseAlternativeDeps(line string) ([]DepSpec, error) {
	// Split by | to get alternatives
	parts := strings.Split(line, "|")
	var alternatives []string
	var commonOp, commonVer string
	var commonOptional, commonRebuild, commonMake, commonMakeOpt, commonCross, commonCrossNative, commonNoCross, commonRuntimeOnly, commonPostInstall, commonSuggest bool
	var commonSuggestText string

	for _, part := range parts {
		part = strings.TrimSpace(part)
		name, op, ver, optional, rebuild, makeDep, cross, crossNative, noCross, runtimeOnly, postInstall, suggest, suggestText := parseDepToken(part)
		makeOpt := hasDependencyFlag(part, "makeopt")
		if name != "" {
			alternatives = append(alternatives, name)
			if commonOp == "" && op != "" {
				commonOp = op
				commonVer = ver
			}
			commonOptional = commonOptional || optional
			commonRebuild = commonRebuild || rebuild
			commonMake = commonMake || makeDep || makeOpt
			commonMakeOpt = commonMakeOpt || makeOpt
			commonCross = commonCross || cross
			commonNoCross = commonNoCross || noCross
			commonCrossNative = commonCrossNative || crossNative
			commonRuntimeOnly = commonRuntimeOnly || runtimeOnly
			commonPostInstall = commonPostInstall || postInstall
			commonSuggest = commonSuggest || suggest
			if commonSuggestText == "" && suggestText != "" {
				commonSuggestText = suggestText
			}
		}
	}

	if len(alternatives) == 0 {
		return nil, fmt.Errorf("no alternatives found in line: %s", line)
	}

	// For binary index, we mostly care about runtime names.
	return []DepSpec{{
		Name:         alternatives[0],
		Op:           commonOp,
		Version:      commonVer,
		Optional:     commonOptional,
		Rebuild:      commonRebuild,
		Make:         commonMake,
		MakeOpt:      commonMakeOpt,
		Cross:        commonCross,
		CrossNative:  commonCrossNative,
		RuntimeOnly:  commonRuntimeOnly,
		PostInstall:  commonPostInstall,
		Suggest:      commonSuggest,
		SuggestText:  commonSuggestText,
		Alternatives: alternatives,
	}}, nil
}
