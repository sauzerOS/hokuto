package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
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

// addToWorld adds a package to the world file if it's not already there.
