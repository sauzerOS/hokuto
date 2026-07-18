package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
)

type packageIntegrityIssue struct {
	Package string
	Missing []string
}

func integrityPathExists(path string, privilegedExec *Executor) (bool, error) {
	if _, err := os.Lstat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else if !os.IsPermission(err) {
		return false, err
	}

	// Protected package paths (for example parts of /var/cache/cups) cannot be
	// verified by the calling user. GNU stat checks the directory entry itself,
	// so broken symlinks still count as present just like os.Lstat above.
	cmd := exec.Command("stat", "--", path)
	if err := privilegedExec.Run(cmd); err == nil {
		return true, nil
	} else {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, err
	}
}

func scanInstalledPackageIntegrity(searchTerm string, cfg *Config) ([]packageIntegrityIssue, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read installed package database: %w", err)
	}

	root := rootDir
	if cfg != nil && cfg.Values["HOKUTO_ROOT"] != "" {
		root = cfg.Values["HOKUTO_ROOT"]
	}
	if root == "" {
		root = "/"
	}
	execContext := context.Background()
	if RootExec != nil && RootExec.Context != nil {
		execContext = RootExec.Context
	}
	privilegedExec := &Executor{
		Context:         execContext,
		ShouldRunAsRoot: true,
		Interactive:     true,
		Stdout:          io.Discard,
		Stderr:          io.Discard,
	}

	var issues []packageIntegrityIssue
	for _, entry := range entries {
		if !entry.IsDir() || (searchTerm != "" && !strings.Contains(entry.Name(), searchTerm)) {
			continue
		}
		pkgName := entry.Name()
		manifestPath := filepath.Join(Installed, pkgName, "manifest")
		file, err := os.Open(manifestPath)
		if err != nil {
			issues = append(issues, packageIntegrityIssue{Package: pkgName, Missing: []string{"installed package manifest"}})
			continue
		}

		var missing []string
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			manifestPath := parseManifestFilePath(scanner.Text())
			if manifestPath == "" {
				continue
			}
			diskPath := manifestPathOnDisk(root, manifestPath)
			exists, err := integrityPathExists(diskPath, privilegedExec)
			if err != nil {
				file.Close()
				return nil, fmt.Errorf("failed to inspect %s for %s: %w", manifestPath, pkgName, err)
			}
			if !exists {
				missing = append(missing, filepath.ToSlash(filepath.Clean(manifestPath)))
			}
		}
		scanErr := scanner.Err()
		file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan manifest for %s: %w", pkgName, scanErr)
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			issues = append(issues, packageIntegrityIssue{Package: pkgName, Missing: missing})
		}
	}

	sort.Slice(issues, func(i, j int) bool { return issues[i].Package < issues[j].Package })
	return issues, nil
}

func reinstallPackageForIntegrity(pkgName string, cfg *Config) error {
	versionData, err := os.ReadFile(filepath.Join(Installed, pkgName, "version"))
	fields := strings.Fields(string(versionData))

	installName := pkgName
	var tarballPath string
	if err == nil && len(fields) > 0 {
		version := fields[0]
		revision := "1"
		if len(fields) > 1 {
			revision = fields[1]
		}
		if cached := findCachedBinaryTarballVersion(pkgName, version, revision, cfg); cached != "" {
			tarballPath = cached
		} else {
			for _, variant := range dependencyVariantCandidates(pkgName, cfg) {
				fetched, ok, fetchErr := fetchExactBinaryTarballIfAvailable(pkgName, version, revision, variant, cfg, false)
				if fetchErr != nil {
					return fetchErr
				}
				if ok {
					tarballPath = fetched
					break
				}
			}
		}
	} else if err != nil {
		debugf("Installed version metadata for %s is unavailable; resolving a current binary for integrity repair: %v\n", pkgName, err)
	} else {
		debugf("Installed version metadata for %s is empty; resolving a current binary for integrity repair\n", pkgName)
	}

	if tarballPath == "" {
		var ok bool
		installName, tarballPath, ok, err = availableBinaryPackageTarball(pkgName, cfg, false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no binary is available; rebuild it with 'hokuto build %s'", pkgName)
		}
	}

	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)
	handlePreInstallUninstall(installName, cfg, RootExec, true, nil)
	if _, err := pkgInstallWithRemotePolicy(tarballPath, installName, cfg, RootExec, true, false, false, false, nil); err != nil {
		return err
	}
	return nil
}

func checkInstalledPackageIntegrity(searchTerm string, cfg *Config) error {
	colArrow.Print("-> ")
	colSuccess.Println("Checking installed package integrity")
	issues, err := scanInstalledPackageIntegrity(searchTerm, cfg)
	if err != nil {
		return err
	}
	if len(issues) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("All installed package files are present.")
		return nil
	}

	colArrow.Print("-> ")
	colWarn.Printf("Found %d package(s) with missing files.\n", len(issues))
	for _, issue := range issues {
		colWarn.Printf("  %s: %d missing file(s)\n", issue.Package, len(issue.Missing))
		limit := min(len(issue.Missing), 10)
		for _, path := range issue.Missing[:limit] {
			fmt.Printf("    %s\n", path)
		}
		if len(issue.Missing) > limit {
			fmt.Printf("    ... and %d more\n", len(issue.Missing)-limit)
		}
	}

	for _, issue := range issues {
		if !askForConfirmation(colWarn, "Reinstall %s?", colNote.Sprint(issue.Package)) {
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Reinstalling %s\n", issue.Package)
		if err := reinstallPackageForIntegrity(issue.Package, cfg); err != nil {
			colWarn.Printf("Warning: failed to reinstall %s: %v\n", issue.Package, err)
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Reinstalled %s successfully.\n", issue.Package)
	}
	return nil
}

func listPackages(searchTerm string, sortBySize bool) error {
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

	// Step 4: Collect the information for the final list of packages.
	var output []SortablePagerLine
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown"
		if data, err := os.ReadFile(versionFile); err == nil {
			versionInfo = strings.TrimSpace(string(data))
		}

		sizeInfo := "?"
		sizeBytes := int64(0)
		hasSize := false
		if total, _, _, err := installedPackageSize(p); err == nil {
			sizeInfo = humanReadableSize(total)
			sizeBytes = total
			hasSize = true
		}

		// Read pkginfo for Arch/Variant
		pkgInfoFile := filepath.Join(Installed, p, "pkginfo")
		arch := "?"
		variantDisplay := "?"
		multiSuffix := ""

		if data, err := os.ReadFile(pkgInfoFile); err == nil {
			meta := ParsePkgInfo(data)
			if v, ok := meta["arch"]; ok {
				arch = v
			}

			// Compute variant display string
			isGeneric := meta["generic"] == "1"
			isMultilib := meta["multilib"] == "1"
			variant := "optimized"
			if isGeneric {
				variant = "generic"
			}

			variantDisplay = variant
			if variantDisplay == "optimized" {
				variantDisplay = "native"
			}

			if isMultilib {
				multiSuffix = " (multi)"
			}
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

		// Add to output slice
		prefix := colArrow.Sprint("->")

		// Format: -> Name Version Arch Variant(multi) [BuildTime]
		pkgStr := fmt.Sprintf("%s %s %s %s",
			prefix,
			colSuccess.Sprintf("%-25s", fitPackageListColumn(p, 25)),
			colNote.Sprintf("%-15s", fitPackageListColumn(versionInfo, 15)),
			color.Yellow.Sprintf("%10s", sizeInfo))
		pkgStr += fmt.Sprintf(" %s",
			color.Cyan.Sprintf("%-10s %s%s",
				fitPackageListColumn(arch, 10),
				variantDisplay,
				multiSuffix))

		if buildtimeStr != "" {
			pkgStr += fmt.Sprintf(" %s", color.Yellow.Sprint(buildtimeStr))
		}

		output = append(output, SortablePagerLine{
			Line:    pkgStr,
			Name:    p,
			Size:    sizeBytes,
			HasSize: hasSize,
		})
	}

	return RunSortablePager("Installed Packages", output, sortBySize)
}

func FetchRemoteIndex(cfg *Config) ([]RepoEntry, error) {
	return fetchRemoteIndex(cfg, false)
}

// fetchRemoteIndex fetches the remote package index. When quiet is true,
// informational status lines are suppressed so callers can keep an active
// progress bar intact.
func fetchRemoteIndex(cfg *Config, quiet bool) ([]RepoEntry, error) {
	ctx := context.Background()
	var data []byte
	var err error
	mirrorAttempted := false

	// Check for R2 credentials before attempting to initialize client
	hasCreds := cfg.Values["R2_ACCESS_KEY_ID"] != "" && cfg.Values["R2_SECRET_ACCESS_KEY"] != ""
	// Also allow if we are using the default "sauzeros" bucket which might be public (though in this codebase writes seem to use creds, reads might be public?
	// The user request implies R2 is slowing things down when creds are missing, so we should be strict).
	// Actually, looking at NewR2Client, it sets "dummy" creds if missing. We want to avoid that if the intention is to use the mirror.

	var sigData []byte
	// 1. Try public Binary Mirror first (high priority for most users)
	if BinaryMirror != "" {
		mirrorAttempted = true
		if !quiet {
			prepareDependencyProgressLogOutput()
			fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprint("Fetching remote index via Binary Mirror"))
		}
		url := fmt.Sprintf("%s/repo-index.json", BinaryMirror)
		dest := filepath.Join(os.TempDir(), "hokuto-index.json")
		indexDownloadOpt := downloadOptions{Quiet: true, NativeAttempts: 2, NativeOnly: true}
		if dlErr := downloadFileWithOptions(url, url, dest, indexDownloadOpt); dlErr == nil {
			data, err = os.ReadFile(dest)
			os.Remove(dest)

			// Also try to fetch sig from mirror
			sigUrl := url + ".sig"
			sigDest := dest + ".sig"
			if dlErr := downloadFileWithOptions(sigUrl, sigUrl, sigDest, indexDownloadOpt); dlErr == nil {
				sigData, _ = os.ReadFile(sigDest)
				os.Remove(sigDest)
			}
		} else {
			debugf("Mirror fetch failed: %v, continuing in local mode\n", dlErr)
			err = dlErr
		}
	}

	// 2. Fallback to R2 only when no public mirror was configured. If the
	// configured mirror is unreachable, treat that as remote unavailable and
	// let callers continue with local repositories/caches.
	if len(data) == 0 && !mirrorAttempted && hasCreds {
		r2, r2Err := NewR2Client(cfg)
		if r2Err == nil {
			if !quiet {
				prepareDependencyProgressLogOutput()
				fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprintf("Fetching remote index from %s (R2 fallback)", getMirrorDisplayName(cfg)))
			}
			data, err = r2.DownloadFile(ctx, "repo-index.json")
			if err == nil {
				sigData, _ = r2.DownloadFile(ctx, "repo-index.json.sig")
			}
		} else {
			debugf("R2 client initialization skipped: %v\n", r2Err)
			if err == nil {
				err = r2Err
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
		if !quiet {
			fmt.Fprintln(os.Stdout, colArrow.Sprint("->"), colSuccess.Sprint("Remote index signature OK"))
		}
	} else if len(sigData) > 0 {
		// Even if not enforced, if it's there, verify it for safety
		if vErr := VerifyRepoIndexSignature(data, sigData, cfg); vErr != nil {
			colWarn.Printf("Warning: remote index signature verification failed: %v\n", vErr)
		}
	}

	return ParseRepoIndex(data)
}

// GetCachedRemoteIndex returns the global remote index, fetching it if necessary.
func GetCachedRemoteIndex(cfg *Config) ([]RepoEntry, error) {
	return getCachedRemoteIndex(cfg, false)
}

// getCachedRemoteIndex returns the process-wide remote index and controls only
// the informational output emitted when the cache must be populated.
func getCachedRemoteIndex(cfg *Config, quiet bool) ([]RepoEntry, error) {
	GlobalRemoteIndexMu.Lock()
	defer GlobalRemoteIndexMu.Unlock()

	if GlobalRemoteIndexLoaded {
		return GlobalRemoteIndex, GlobalRemoteIndexErr
	}

	index, err := fetchRemoteIndex(cfg, quiet)
	if err != nil {
		GlobalRemoteIndexErr = err
		GlobalRemoteIndexLoaded = true
		return nil, err
	}

	GlobalRemoteIndex = index
	GlobalRemoteIndexErr = nil
	GlobalRemoteIndexLoaded = true
	return GlobalRemoteIndex, nil
}

// IsPackageInIndex checks if a specific package version exists in the index.
func IsPackageInIndex(index []RepoEntry, name, version, revision string, cfg *Config) bool {
	arch := GetSystemArch(cfg)
	variant := GetSystemVariantForPackage(cfg, name)

	// Fallback logic for generic/multi-generic variants should match GetRemotePackageVersion's looseness
	// OR be strict. Since build plan gives specific version/revision, we probably want exact match
	// on version/revision, but allow variant fallback if the system allows it?
	// Actually, getRepoVersion2 usually returns the version from the *source* repo.
	// We want to see if a binary of that version exists.

	// Check preferred variant first
	for _, entry := range index {
		if entry.Type == "meta" {
			continue
		}
		if entry.Name == name && entry.Arch == arch && entry.Variant == variant && entry.Version == version && entry.Revision == revision {
			return true
		}
	}

	// Fallback variants (optimized -> generic, etc)
	fallbackVariant := ""
	switch variant {
	case "optimized":
		fallbackVariant = "generic"
	case "multi-optimized":
		fallbackVariant = "multi-generic"
	}

	if fallbackVariant != "" {
		for _, entry := range index {
			if entry.Type == "meta" {
				continue
			}
			if entry.Name == name && entry.Arch == arch && entry.Variant == fallbackVariant && entry.Version == version && entry.Revision == revision {
				return true
			}
		}
	}

	return false
}

func listRemotePackages(searchTerm string, cfg *Config, sortBySize bool) error {
	remoteIndex, err := FetchRemoteIndex(cfg)
	if err != nil {
		return err
	}

	var output []SortablePagerLine
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

		sizeInfo := "?"
		hasSize := entry.Size >= 0
		if hasSize {
			sizeInfo = humanReadableSize(entry.Size)
		}

		line := fmt.Sprintf("%s %s %s %s %s",
			colArrow.Sprint("->"),
			colSuccess.Sprintf("%-25s", fitPackageListColumn(entry.Name, 25)),
			colNote.Sprintf("%-15s", fitPackageListColumn(fmt.Sprintf("%s-%s", entry.Version, entry.Revision), 15)),
			color.Yellow.Sprintf("%10s", sizeInfo),
			color.Cyan.Sprintf("%-10s %s%s",
				fitPackageListColumn(entry.Arch, 10),
				variantDisplay,
				multiSuffix))
		output = append(output, SortablePagerLine{
			Line:    line,
			Name:    entry.Name,
			Size:    entry.Size,
			HasSize: hasSize,
		})
		foundAny = true
	}

	if !foundAny && searchTerm != "" {
		colArrow.Print("-> ")
		colSuccess.Printf("No remote packages found matching: %s\n", searchTerm)
		return nil
	}

	return RunSortablePager("Remote Packages", output, sortBySize)
}

func fitPackageListColumn(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

// GetRemotePackageEntry searches the remote index for a package matching system criteria.
// It returns the full RepoEntry or an error if not found.
func GetRemotePackageEntry(pkgName string, cfg *Config, remoteIndex []RepoEntry) (*RepoEntry, error) {
	targetVersion := ""
	targetRevision := ""
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
		verStr := pkgName[idx+1:]
		// Check for revision (format: version-revision)
		// Only treat it as revision if the part after the last dash is numeric
		if lastDash := strings.LastIndex(verStr, "-"); lastDash != -1 {
			possibleRev := verStr[lastDash+1:]
			if _, err := strconv.Atoi(possibleRev); err == nil {
				targetVersion = verStr[:lastDash]
				targetRevision = possibleRev
			} else {
				targetVersion = verStr
			}
		} else {
			targetVersion = verStr
		}
	}

	arch := GetSystemArch(cfg)
	variant := GetSystemVariantForPackage(cfg, lookupName)
	versionedBase, versionedLine, versionedName := splitVersionedPackageName(lookupName)
	if targetVersion == "" && versionedName {
		targetVersion = parallelPackageVersion(lookupName)
	}

	// Helper to search in a specific variant
	searchInVariant := func(searchVariant string) *RepoEntry {
		var localBest *RepoEntry
		for i := range remoteIndex {
			entry := &remoteIndex[i]
			if entry.Type == "meta" {
				continue
			}
			// Historical parallel installs use pkg-MAJOR locally, while archives
			// and index entries retain the canonical package name.
			match := entry.Name == lookupName || (versionedName && entry.Name == versionedBase)
			if match && entry.Arch == arch && entry.Variant == searchVariant {
				if versionedName && !versionMatchesPackageLine(entry.Version, versionedLine) {
					continue
				}
				if targetVersion != "" {
					if entry.Version == targetVersion {
						if targetRevision != "" && entry.Revision != targetRevision {
							continue
						}
						return entry
					}
					continue
				}
				if localBest == nil || isNewer(*entry, *localBest) {
					localBest = entry
				}
			}
		}
		return localBest
	}

	var absoluteBest *RepoEntry

	// Helper to update absoluteBest
	updateBest := func(match *RepoEntry) {
		if match == nil {
			return
		}
		if absoluteBest == nil || isNewer(*match, *absoluteBest) ||
			(match.Version == absoluteBest.Version && match.Revision == absoluteBest.Revision &&
				match.Variant == variant && absoluteBest.Variant != variant) {
			absoluteBest = match
		}
	}

	// 1. Preferred Variant
	updateBest(searchInVariant(variant))

	// 2. Generic Variant (if preferred was not generic)
	if !strings.Contains(variant, "generic") {
		fallbackVariant := "generic"
		if strings.HasPrefix(variant, "multi-") {
			fallbackVariant = "multi-generic"
		}
		updateBest(searchInVariant(fallbackVariant))
	}

	// 3. Multi variants fallback
	// If we are looking for non-multi (e.g. optimized) but only multi- exists, try that.
	if !strings.HasPrefix(variant, "multi-") && isMultilibPackage(lookupName) {
		// Try multi- + variant (e.g. "optimized" -> "multi-optimized")
		updateBest(searchInVariant("multi-" + variant))
		// Try multi-generic
		updateBest(searchInVariant("multi-generic"))
	}

	if absoluteBest != nil {
		return absoluteBest, nil
	}

	if targetVersion != "" {
		verStr := targetVersion
		if targetRevision != "" {
			verStr += "-" + targetRevision
		}
		return nil, fmt.Errorf("package %s@%s not found in remote index for %s (%s)", lookupName, verStr, arch, variant)
	}

	return nil, fmt.Errorf("package %s not found in remote index for %s (%s)", pkgName, arch, variant)
}

// GetRemotePackageVersion searches the remote index for a package matching system criteria.
func GetRemotePackageVersion(pkgName string, cfg *Config, remoteIndex []RepoEntry) (version, revision string, err error) {
	entry, err := GetRemotePackageEntry(pkgName, cfg, remoteIndex)
	if err != nil {
		return "", "", err
	}
	return entry.Version, entry.Revision, nil
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
		// Use LastIndexAny regarding spaces to separate the path from the checksum
		lastSpace := strings.LastIndexAny(line, " \t")
		if lastSpace == -1 {
			continue
		}
		path := strings.TrimSpace(line[:lastSpace])

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

func manifestPathOnDisk(root, manifestPath string) string {
	clean := filepath.Clean(manifestPath)
	if filepath.IsAbs(clean) {
		return filepath.Join(root, strings.TrimPrefix(clean, string(os.PathSeparator)))
	}
	return filepath.Join(root, clean)
}

func formatByteSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func installedPackageSize(pkgName string) (int64, int, int, error) {
	manifestPath := filepath.Join(Installed, pkgName, "manifest")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, 0, fmt.Errorf("package %s is not installed (manifest not found)", pkgName)
		}
		return 0, 0, 0, fmt.Errorf("failed to read manifest for %s: %w", pkgName, err)
	}

	root := rootDir
	if root == "" {
		root = "/"
	}

	var total int64
	var counted, missing int
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}
		manifestFilePath := parseManifestFilePath(line)
		if manifestFilePath == "" {
			continue
		}

		cleanNoSlash := strings.TrimPrefix(filepath.Clean(manifestFilePath), string(os.PathSeparator))
		if strings.HasPrefix(filepath.ToSlash(cleanNoSlash), "var/db/hokuto") {
			continue
		}

		info, err := os.Lstat(manifestPathOnDisk(root, manifestFilePath))
		if err != nil {
			if os.IsNotExist(err) {
				missing++
				continue
			}
			return 0, 0, 0, fmt.Errorf("failed to stat %s: %w", manifestFilePath, err)
		}
		if info.IsDir() {
			continue
		}
		total += info.Size()
		counted++
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, fmt.Errorf("error scanning manifest: %w", err)
	}
	return total, counted, missing, nil
}

func showInstalledPackageSize(pkgName string) error {
	total, counted, missing, err := installedPackageSize(pkgName)
	if err != nil {
		return err
	}

	colArrow.Print("-> ")
	colSuccess.Printf("%s: ", pkgName)
	colNote.Printf("%s", formatByteSize(total))
	fmt.Printf(" (%d bytes, %d files", total, counted)
	if missing > 0 {
		fmt.Printf(", %d missing", missing)
	}
	fmt.Println(")")
	return nil
}

// findPackagesByManifestString searches every installed/<pkg>/manifest for the given query string.
// It prints the package names (one per line) for packages whose manifest contains a path
// matching the query. Directory entries and internal metadata (var/db/hokuto) are ignored.

func findPackagesByManifestString(query string) error {
	if query == "" {
		return fmt.Errorf("empty search string")
	}

	root := rootDir
	if root == "" {
		root = "/"
	}
	canonicalQuery := filepath.ToSlash(filepath.Clean(canonicalizePath(root, query)))

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
			lastSpace := strings.LastIndexAny(line, " \t")
			if lastSpace == -1 {
				continue
			}
			path := strings.TrimSpace(line[:lastSpace])

			// skip internal metadata entries
			clean := filepath.Clean(path)
			cleanNoSlash := strings.TrimPrefix(clean, "/")
			if strings.HasPrefix(cleanNoSlash, filepath.ToSlash("var/db/hokuto")) {
				continue
			}

			canonicalPath := filepath.ToSlash(filepath.Clean(canonicalizePath(root, path)))
			if strings.Contains(path, query) || strings.Contains(canonicalPath, canonicalQuery) {
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
