package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
)

func listPackages(searchTerm string) error {
	// Step 1: Always get the full list of installed package directories first.
	entries, err := os.ReadDir(Installed)
	if err != nil {
		// Handle cases where the 'Installed' directory might not exist yet
		if os.IsNotExist(err) {
			fmt.Println("No packages installed.")
			return nil
		}
		return err
	}

	var allPkgs []string
	for _, e := range entries {
		if e.IsDir() {
			allPkgs = append(allPkgs, e.Name())
		}
	}

	// Step 2: Filter the list if a search term was provided.
	var pkgsToShow []string
	if searchTerm != "" {
		// Partial matching
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, show everything
		pkgsToShow = allPkgs
	}

	// Step 3: Handle the case where no packages were found after filtering.
	if len(pkgsToShow) == 0 {
		if searchTerm != "" {
			colArrow.Print("-> ")
			colSuccess.Printf("No packages found matching: %s\n", searchTerm)
			// --- MODIFICATION: Return the specific sentinel error ---
			return errPackageNotFound
		}
		return nil
	}

	// Step 4: Print the information for the final list of packages.
	// ... (rest of the function is unchanged)
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown"
		if data, err := os.ReadFile(versionFile); err == nil {
			versionInfo = strings.TrimSpace(string(data))
		}

		// Read buildtime (duration string) if present.
		buildtimeFile := filepath.Join(Installed, p, "buildtime")
		buildtimeStr := ""

		if data, err := os.ReadFile(buildtimeFile); err == nil {
			raw := strings.TrimSpace(string(data))
			if raw != "" {
				// Try to parse the content as a time.Duration string.
				if d, err := time.ParseDuration(raw); err == nil {

					// Apply formatting rules based on magnitude:
					if d >= time.Minute {
						// >= 1 minute: Truncate to the nearest whole second (e.g., 18m53s)
						buildtimeStr = d.Truncate(time.Second).String()
					} else if d >= time.Second {
						// 1s to 59s: Convert to raw seconds and format with 2 decimal places (e.g., 8.15s)
						buildtimeStr = fmt.Sprintf("%.2fs", d.Seconds())
					} else if d >= time.Millisecond {
						// 1ms to 999ms: Format using milliseconds with limited precision (e.g., 35.29ms)
						// This converts to floating point milliseconds and formats with 2 decimal places.
						buildtimeStr = fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
					} else {
						// < 1ms: Use the standard duration string (e.g., 476µs or 500ns)
						// Truncate to the nearest microsecond to keep it clean.
						buildtimeStr = d.Truncate(time.Microsecond).String()
					}

				} else {
					// Fallback for old format (plain float seconds)
					if secs, err := strconv.ParseFloat(raw, 64); err == nil {
						buildtimeStr = fmt.Sprintf("%.2fs", secs)
					} else {
						// Fallback: show the raw value.
						buildtimeStr = raw
					}
				}
			}
		}

		// Print aligned: versionInfo then some spacing then buildtime if present
		if buildtimeStr != "" {
			cPrintf(color.Cyan, "%-30s %s\n", fmt.Sprintf("%s %s", p, versionInfo), buildtimeStr)
		} else {
			cPrintf(color.Cyan, "%s %s\n", p, versionInfo)
		}
	}

	return nil
}

func FetchRemoteIndex(cfg *Config) ([]RepoEntry, error) {
	ctx := context.Background()
	var data []byte
	var err error

	// Check for R2 credentials before attempting to initialize client
	hasCreds := cfg.Values["R2_ACCESS_KEY_ID"] != "" && cfg.Values["R2_SECRET_ACCESS_KEY"] != ""
	// Also allow if we are using the default "sauzeros" bucket which might be public (though in this codebase writes seem to use creds, reads might be public?
	// The user request implies R2 is slowing things down when creds are missing, so we should be strict).
	// Actually, looking at NewR2Client, it sets "dummy" creds if missing. We want to avoid that if the intention is to use the mirror.

	if hasCreds {
		r2, r2Err := NewR2Client(cfg)
		if r2Err == nil {
			colArrow.Print("-> ")
			colSuccess.Println("Fetching remote index from R2")
			data, err = r2.DownloadFile(ctx, "repo-index.json")
		} else {
			debugf("R2 client initialization skipped: %v\n", r2Err)
			err = r2Err
		}
	} else {
		// Explicitly set err to trigger fallback
		err = fmt.Errorf("R2 credentials not configured, skipping R2")
		debugf("R2 credentials missing, skipping R2 fetch\n")
	}

	var sigData []byte
	if err == nil {
		// If index was from R2, try to get sig from R2
		if r2, r2Err := NewR2Client(cfg); r2Err == nil {
			sigData, _ = r2.DownloadFile(ctx, "repo-index.json.sig")
		}
	} else {
		// Fallback: try download via BinaryMirror URL
		if BinaryMirror != "" {
			colArrow.Print("-> ")
			colSuccess.Println("Fetching remote index via Binary Mirror")
			url := fmt.Sprintf("%s/repo-index.json", BinaryMirror)
			dest := filepath.Join(os.TempDir(), "hokuto-index.json")
			if dlErr := downloadFileQuiet(url, url, dest); dlErr == nil {
				data, err = os.ReadFile(dest)
				os.Remove(dest)

				// Also try to fetch sig from mirror
				sigUrl := url + ".sig"
				sigDest := dest + ".sig"
				if dlErr := downloadFileQuiet(sigUrl, sigUrl, sigDest); dlErr == nil {
					sigData, _ = os.ReadFile(sigDest)
					os.Remove(sigDest)
				}
			}
		}
	}

	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("failed to fetch remote index: %w", err)
	}

	// Signature Verification
	if os.Getenv("HOKUTO_VERIFY_SIGNATURE") != "0" {
		if len(sigData) == 0 {
			return nil, fmt.Errorf("MISSING REPO INDEX SIGNATURE: the remote index is not signed and signature verification is enforced")
		}
		if vErr := VerifyRepoIndexSignature(data, sigData, cfg); vErr != nil {
			return nil, vErr
		}
		colArrow.Print("-> ")
		colSuccess.Println("Remote index signature OK")
	} else if len(sigData) > 0 {
		// Even if not enforced, if it's there, verify it for safety
		if vErr := VerifyRepoIndexSignature(data, sigData, cfg); vErr != nil {
			colWarn.Printf("Warning: remote index signature verification failed: %v\n", vErr)
		}
	}

	return ParseRepoIndex(data)
}

func listRemotePackages(searchTerm string, cfg *Config) error {
	remoteIndex, err := FetchRemoteIndex(cfg)
	if err != nil {
		return err
	}

	foundAny := false
	for _, entry := range remoteIndex {
		if searchTerm != "" && !strings.Contains(entry.Name, searchTerm) {
			continue
		}

		variantDisplay := entry.Variant
		multiSuffix := ""

		// Identify variant and multi-bitness
		// Possible variants: optimized, generic, multi-optimized, multi-generic
		if strings.HasPrefix(variantDisplay, "multi-") {
			variantDisplay = strings.TrimPrefix(variantDisplay, "multi-")
			multiSuffix = " (multi)"
		}

		if variantDisplay == "optimized" {
			variantDisplay = "native"
		}

		cPrintf(color.Cyan, "%-25s %-15s %-10s %s%s\n", entry.Name, fmt.Sprintf("%s-%s", entry.Version, entry.Revision), entry.Arch, variantDisplay, multiSuffix)
		foundAny = true
	}

	if !foundAny && searchTerm != "" {
		colArrow.Print("-> ")
		colSuccess.Printf("No remote packages found matching: %s\n", searchTerm)
	}

	return nil
}

// GetRemotePackageVersion searches the remote index for a package matching system criteria.
func GetRemotePackageVersion(pkgName string, cfg *Config, remoteIndex []RepoEntry) (version, revision string, err error) {
	targetVersion := ""
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
		targetVersion = pkgName[idx+1:]
	}

	arch := GetSystemArch(cfg)
	variant := GetSystemVariantForPackage(cfg, lookupName)

	var bestMatch *RepoEntry
	for i := range remoteIndex {
		entry := &remoteIndex[i]
		if entry.Name == lookupName && entry.Arch == arch && entry.Variant == variant {
			// If targetVersion is specified, only match that exact version
			if targetVersion != "" {
				if entry.Version == targetVersion {
					// Found the exact version
					return entry.Version, entry.Revision, nil
				}
				continue
			}

			if bestMatch == nil || isNewer(*entry, *bestMatch) {
				bestMatch = entry
			}
		}
	}

	if bestMatch != nil {
		return bestMatch.Version, bestMatch.Revision, nil
	}

	if targetVersion != "" {
		return "", "", fmt.Errorf("package %s@%s not found in remote index for %s (%s)", lookupName, targetVersion, arch, variant)
	}

	return "", "", fmt.Errorf("package %s not found in remote index for %s (%s)", pkgName, arch, variant)
}

// showManifest prints the file list for a package manifest, skipping directories,
// checksums, and any entries under var/db/hokuto (internal metadata).

func showManifest(pkgName string) error {
	manifestPath := filepath.Join(Installed, pkgName, "manifest")

	// Read manifest as the invoking user (no sudo/cat helper)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("package %s is not installed (manifest not found)", pkgName)
		}
		return fmt.Errorf("failed to read manifest for %s: %w", pkgName, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip directory entries (lines that end with '/')
		if strings.HasSuffix(line, "/") {
			continue
		}

		// Each file line is expected to be: "<path>  <checksum>"
		// We only want to print the path (first whitespace-separated field).
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := fields[0]

		// Normalize for checking internal metadata: consider both absolute and relative variants.
		clean := filepath.Clean(path)
		// Remove leading slash for consistent prefix checking
		cleanNoSlash := strings.TrimPrefix(clean, "/")

		// Filter out internal metadata paths under var/db/hokuto
		if strings.HasPrefix(cleanNoSlash, filepath.ToSlash(filepath.Clean("var/db/hokuto"))) {
			continue
		}

		// Print the manifest file path (exact path as stored in manifest)
		fmt.Println(path)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning manifest: %w", err)
	}
	return nil
}

// findPackagesByManifestString searches every installed/<pkg>/manifest for the given query string.
// It prints the package names (one per line) for packages whose manifest contains a path
// matching the query. Directory entries and internal metadata (var/db/hokuto) are ignored.

func findPackagesByManifestString(query string) error {
	if query == "" {
		return fmt.Errorf("empty search string")
	}

	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No packages installed.")
			return nil
		}
		return fmt.Errorf("failed to read installed db: %w", err)
	}

	foundAny := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(Installed, pkgName, "manifest")

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			// skip packages without readable manifest rather than failing the whole run
			continue
		}

		match := false
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// skip directory entries
			if strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			path := fields[0]

			// skip internal metadata entries
			clean := filepath.Clean(path)
			cleanNoSlash := strings.TrimPrefix(clean, "/")
			if strings.HasPrefix(cleanNoSlash, filepath.ToSlash("var/db/hokuto")) {
				continue
			}

			if strings.Contains(path, query) {
				match = true
				break
			}
		}
		if scannerErr := scanner.Err(); scannerErr != nil {
			// ignore malformed manifest for this package
			continue
		}

		if match {
			fmt.Println(pkgName)
			foundAny = true
		}
	}

	if !foundAny {
		// exit code could indicate no matches; print a friendly message instead
		fmt.Println("No packages found matching:", query)
	}
	return nil
}
