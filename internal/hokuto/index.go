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
	if cfg.Values["HOKUTO_GENERIC"] == "1" || cfg.Values["HOKUTO_CROSS_ARCH"] != "" {
		baseVariant = "generic"
	}

	// Check if multilib is enabled and package supports it
	if cfg.Values["HOKUTO_MULTILIB"] == "1" && pkgName != "" && pkgName != "sauzeros-base" {
		if isMultilibPackage(pkgName) {
			return "multi-" + baseVariant
		}
	}

	return baseVariant
}

// RepoEntry represents a single package in the repository index.
type RepoEntry struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Revision string   `json:"revision"`
	Arch     string   `json:"arch"`
	Variant  string   `json:"variant"` // generic or optimized
	Filename string   `json:"filename"`
	Size     int64    `json:"size"`
	B3Sum    string   `json:"b3sum"`
	Depends  []string `json:"depends,omitempty"`
}

// ReadPackageMetadata extracts pkginfo and computes checksum for a local tarball.
func ReadPackageMetadata(tarballPath string) (RepoEntry, error) {
	entry := RepoEntry{
		Filename: filepath.Base(tarballPath),
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

	// 2. Scan tarball once for all metadata (pkginfo and depends)
	metadata, deps, err := scanTarballMetadata(tarballPath)
	if err != nil {
		return entry, fmt.Errorf("failed to scan tarball metadata: %w", err)
	}

	// 3. Populate RepoEntry
	entry.Name = metadata["name"]
	entry.Version = metadata["version"]
	entry.Revision = metadata["revision"]
	entry.Arch = metadata["arch"]

	// 4. Identify variant
	entry.Variant = IdentifyVariant(entry.Name, metadata["generic"] == "1", metadata["multilib"] == "1")

	// 5. Populate Dependencies
	entry.Depends = deps

	return entry, nil
}

// scanTarballMetadata reads pkginfo and depends files from a .tar.zst archive in one pass.
func scanTarballMetadata(tarballPath string) (map[string]string, []string, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	zsr, err := zstd.NewReader(f)
	if err != nil {
		return nil, nil, err
	}
	defer zsr.Close()

	var metadata map[string]string
	var dependencies []string

	tr := tar.NewReader(zsr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		// 1. Look for pkginfo
		if strings.HasSuffix(header.Name, "/pkginfo") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read pkginfo from %s: %w", tarballPath, err)
			}
			metadata = parsePkgInfo(data)
			continue
		}

		// 2. Look for depends
		if strings.HasSuffix(header.Name, "/depends") {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read depends from %s: %w", tarballPath, err)
			}
			depSpecs, err := parseDependsData(data)
			if err != nil {
				debugf("Warning: failed to parse depends data for %s: %v\n", tarballPath, err)
				continue
			}
			for _, d := range depSpecs {
				if !d.Make { // Only store runtime dependencies
					dependencies = append(dependencies, d.Name)
				}
			}
			continue
		}
	}

	if metadata == nil {
		return nil, nil, fmt.Errorf("pkginfo not found in %s", tarballPath)
	}

	return metadata, dependencies, nil
}

func parsePkgInfo(data []byte) map[string]string {
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
	if isMultilib && pkgName != "sauzeros-base" {
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
			name, op, ver, optional, rebuild, makeDep := parseDepToken(line)
			if name != "" {
				dependencies = append(dependencies, DepSpec{
					Name:         name,
					Op:           op,
					Version:      ver,
					Optional:     optional,
					Rebuild:      rebuild,
					Make:         makeDep,
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
	var commonOptional, commonRebuild, commonMake bool

	for i, part := range parts {
		part = strings.TrimSpace(part)
		name, op, ver, optional, rebuild, makeDep := parseDepToken(part)
		if name != "" {
			alternatives = append(alternatives, name)
			// Assuming common flags for all alternatives in a single line
			if i == 0 {
				commonOp = op
				commonVer = ver
				commonOptional = optional
				commonRebuild = rebuild
				commonMake = makeDep
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
		Alternatives: alternatives,
	}}, nil
}
