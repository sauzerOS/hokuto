package hokuto

import (
	"archive/tar"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if cfg.Values["HOKUTO_MULTILIB"] == "1" && pkgName != "" {
		if isMultilibPackage(pkgName) {
			return "multi-" + baseVariant
		}
	}

	return baseVariant
}

// RepoEntry represents a single package in the repository index.
type RepoEntry struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Arch     string `json:"arch"`
	Variant  string `json:"variant"` // generic or optimized
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	B3Sum    string `json:"b3sum"`
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

	// 2. Extract pkginfo from tar.zst
	pkgInfoData, err := extractPkgInfoFromTar(tarballPath)
	if err != nil {
		return entry, fmt.Errorf("failed to extract pkginfo: %w", err)
	}

	// 3. Parse pkginfo
	metadata := parsePkgInfo(pkgInfoData)
	entry.Name = metadata["name"]
	entry.Version = metadata["version"]
	entry.Revision = metadata["revision"]
	entry.Arch = metadata["arch"]

	// 4. Identify variant
	entry.Variant = IdentifyVariant(metadata["generic"] == "1", metadata["multilib"] == "1")

	return entry, nil
}

// extractPkgInfoFromTar reads the pkginfo file from a .tar.zst archive without unpacking everything.
func extractPkgInfoFromTar(tarballPath string) ([]byte, error) {
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

		// Look for pkginfo in var/db/hokuto/installed/<pkg>/pkginfo
		if strings.HasSuffix(header.Name, "/pkginfo") {
			return io.ReadAll(tr)
		}
	}

	return nil, fmt.Errorf("pkginfo not found in archive")
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
func IdentifyVariant(isGeneric bool, isMultilib bool) string {
	variant := "optimized"
	if isGeneric {
		variant = "generic"
	}
	if isMultilib {
		variant = "multi-" + variant
	}
	return variant
}

// StandardizeRemoteName generates a consistent filename for the remote repository.
func StandardizeRemoteName(name, ver, rev, arch, variant string) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s.tar.zst", name, ver, rev, arch, variant)
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
