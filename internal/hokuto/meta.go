package hokuto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sort"

	"github.com/gookit/color"
	"github.com/klauspost/compress/zstd"
)

// PackageMetadata represents the structure of metadata.json
type PackageMetadata struct {
	URL           string                      `json:"url"`
	Category      string                      `json:"category"`
	Description   string                      `json:"description"`
	Info          string                      `json:"info"`
	License       string                      `json:"license"`
	Tags          []string                    `json:"tags"`
	Subpackages   []string                    `json:"subpackages,omitempty"`
	SplitMetadata map[string]SplitPkgMetadata `json:"split_metadata,omitempty"`
}

// SplitPkgMetadata contains per-split metadata overrides in metadata.json.
// Empty fields inherit from the source package metadata.
type SplitPkgMetadata struct {
	URL         string   `json:"url,omitempty"`
	Category    string   `json:"category,omitempty"`
	Description string   `json:"description,omitempty"`
	Info        string   `json:"info,omitempty"`
	License     string   `json:"license,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// PkgDBEntry represents a single package in the global database
type PkgDBEntry struct {
	Name          string          `json:"name"`
	Type          string          `json:"type,omitempty"`
	Version       string          `json:"version"`
	SourcePackage string          `json:"source_package,omitempty"`
	Metadata      PackageMetadata `json:"metadata"`
}

// PkgDB represents the global package database
type PkgDB struct {
	Revision int64        `json:"revision"`
	Packages []PkgDBEntry `json:"packages"`
}

var validTags = []string{
	"boot", "bluetooth", "browser", "calculator", "chat", "cli", "compiler", "cosmic",
	"crypto", "devel", "disk-tools", "editor", "emulator", "encryption",
	"file-manager", "firmware", "fonts", "games", "gnome", "graphics", "gui",
	"ide", "kde", "kernel", "library", "mail", "misc", "multimedia",
	"network", "optical-tools", "perl", "print", "python", "scan", "search",
	"server", "shell", "sync", "torrent", "utility", "virtual-machine",
	"wallet", "wine", "xfce", "compression", "usenet", "vpn", "x11", "wayland", "meta",
	"database", "archive", "pdf", "office",
}

func init() {
	sort.Strings(validTags)
}

// HandleMetaCommand handles the 'hokuto meta' command.
func HandleMetaCommand(args []string, cfg *Config) error {
	editMode := false
	dbMode := false
	var pkgName string

	for _, arg := range args {
		if arg == "-e" {
			editMode = true
		} else if arg == "-db" {
			dbMode = true
		} else if !strings.HasPrefix(arg, "-") {
			pkgName = arg
		}
	}

	if dbMode {
		return GeneratePkgDB(cfg)
	}

	if pkgName == "" {
		return fmt.Errorf("usage: hokuto meta <pkgname> [-e] or hokuto meta -db")
	}

	pkgDir, err := findPackageDir(pkgName)
	sourcePkg := ""
	if err != nil {
		if foundSource, foundDir, ok := findSplitPackageSource(pkgName); ok {
			pkgDir = foundDir
			sourcePkg = foundSource
		} else if editMode {
			return err
		}
	}

	var meta PackageMetadata
	metadataExists := false
	if pkgDir != "" {
		metaPath := filepath.Join(pkgDir, "metadata.json")
		if data, readErr := os.ReadFile(metaPath); readErr == nil {
			_ = json.Unmarshal(data, &meta)
			metadataExists = true
		}
		if splitNames := splitPackageNamesFromDir(pkgDir); len(splitNames) > 0 {
			meta.Subpackages = splitNames
		}
	}

	if editMode {
		if sourcePkg != "" && sourcePkg != pkgName {
			if err := editSplitMetadata(pkgName, sourcePkg, pkgDir, &meta, cfg); err != nil {
				return err
			}
			return regeneratePkgDBAfterMetadataEdit(cfg)
		}
		if err := editMetadata(pkgName, pkgDir, &meta, cfg); err != nil {
			return err
		}
		return regeneratePkgDBAfterMetadataEdit(cfg)
	}

	displayMeta := effectiveMetadataForPackage(pkgName, sourcePkg, &meta)
	if !metadataExists || !hasMetadataEntry(&displayMeta) {
		if entry, found, dbErr := lookupPackageMetadataDatabase(pkgName, cfg, true); dbErr == nil && found {
			displayMeta = entry.Metadata
			sourcePkg = entry.SourcePackage
			metadataExists = true
		} else if dbErr != nil {
			debugf("Package metadata database lookup failed for %s: %v\n", pkgName, dbErr)
		}
	}
	if !metadataExists || !hasMetadataEntry(&displayMeta) {
		if pkgDir != "" {
			colWarn.Printf("No metadata entry found for '%s'. Run 'hokuto meta %s -e' to create one.\n", pkgName, pkgName)
			return nil
		}
		return fmt.Errorf("package %s has no metadata in the local or remote package database", pkgName)
	}

	displayMetadata(pkgName, sourcePkg, &displayMeta)
	return nil
}

func findPackageDatabaseEntry(db *PkgDB, pkgName string) (PkgDBEntry, bool) {
	if db == nil {
		return PkgDBEntry{}, false
	}
	for _, entry := range db.Packages {
		if entry.Name == pkgName {
			return entry, true
		}
	}
	return PkgDBEntry{}, false
}

func lookupPackageMetadataDatabase(pkgName string, cfg *Config, allowRemote bool) (PkgDBEntry, bool, error) {
	if db, err := readPkgDB(PkgDBPath); err == nil {
		if entry, found := findPackageDatabaseEntry(db, pkgName); found {
			return entry, true, nil
		}
	}
	if !allowRemote {
		return PkgDBEntry{}, false, nil
	}
	db, err := getRemotePkgDB(cfg)
	if err != nil {
		return PkgDBEntry{}, false, err
	}
	entry, found := findPackageDatabaseEntry(db, pkgName)
	return entry, found, nil
}

type MetadataCandidate struct {
	Name        string
	URL         string
	Description string
	License     string
	Category    string
	Source      string // "Arch" or "AUR"
}

func applyCandidate(meta *PackageMetadata, cand *MetadataCandidate) {
	meta.URL = cand.URL
	meta.Description = cand.Description
	meta.License = cand.License
	meta.Category = cand.Category
}

func effectiveMetadataForPackage(pkgName, sourcePkg string, meta *PackageMetadata) PackageMetadata {
	effective := *meta
	effective.SplitMetadata = nil
	if sourcePkg == "" || sourcePkg == pkgName || meta.SplitMetadata == nil {
		return effective
	}

	override, ok := meta.SplitMetadata[pkgName]
	if !ok {
		return effective
	}
	if override.URL != "" {
		effective.URL = override.URL
	}
	if override.Category != "" {
		effective.Category = override.Category
	}
	if override.Description != "" {
		effective.Description = override.Description
	}
	if override.Info != "" {
		effective.Info = override.Info
	}
	if override.License != "" {
		effective.License = override.License
	}
	if override.Tags != nil {
		effective.Tags = append([]string(nil), override.Tags...)
	}
	effective.Subpackages = nil
	return effective
}

func splitMetadataOverride(parent, split PackageMetadata) SplitPkgMetadata {
	override := SplitPkgMetadata{}
	if split.URL != parent.URL {
		override.URL = split.URL
	}
	if split.Category != parent.Category {
		override.Category = split.Category
	}
	if split.Description != parent.Description {
		override.Description = split.Description
	}
	if split.Info != parent.Info {
		override.Info = split.Info
	}
	if split.License != parent.License {
		override.License = split.License
	}
	if !stringSlicesEqual(split.Tags, parent.Tags) {
		override.Tags = append([]string(nil), split.Tags...)
	}
	return override
}

func splitMetadataOverrideEmpty(override SplitPkgMetadata) bool {
	return override.URL == "" &&
		override.Category == "" &&
		override.Description == "" &&
		override.Info == "" &&
		override.License == "" &&
		override.Tags == nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasMetadataEntry(meta *PackageMetadata) bool {
	return meta.URL != "" ||
		meta.Category != "" ||
		meta.Description != "" ||
		meta.Info != "" ||
		meta.License != "" ||
		len(meta.Tags) > 0
}

func regeneratePkgDBAfterMetadataEdit(cfg *Config) error {
	colArrow.Print("-> ")
	colNote.Println("Updating package database")
	return GeneratePkgDB(cfg)
}

func searchMetadata(pkgName string) ([]MetadataCandidate, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	var candidates []MetadataCandidate
	seen := make(map[string]bool)

	// 1. Arch Linux API
	archURL := fmt.Sprintf("https://archlinux.org/packages/search/json/?q=%s", pkgName)
	req, _ := http.NewRequest("GET", archURL, nil)
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		var result struct {
			Results []struct {
				PkgName string   `json:"pkgname"`
				Repo    string   `json:"repo"`
				URL     string   `json:"url"`
				PkgDesc string   `json:"pkgdesc"`
				License []string `json:"licenses"`
			} `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			for _, r := range result.Results {
				license := ""
				if len(r.License) > 0 {
					license = r.License[0]
				}
				category := "extra"
				if r.Repo == "core" {
					category = "base"
				}
				cand := MetadataCandidate{
					Name:        r.PkgName,
					URL:         r.URL,
					Description: r.PkgDesc,
					License:     license,
					Category:    category,
					Source:      "Arch",
				}
				if r.PkgName == pkgName {
					// Exact match found on Arch, return immediately with just this one?
					// User said: "handle the case were there is no exact match"
					// So if exact match exists, we take it.
					return []MetadataCandidate{cand}, nil
				}
				if !seen[cand.Name] {
					candidates = append(candidates, cand)
					seen[cand.Name] = true
				}
			}
		}
		resp.Body.Close()
	}

	// 2. AUR RPC API (Search)
	aurURL := fmt.Sprintf("https://aur.archlinux.org/rpc/?v=5&type=search&arg=%s", pkgName)
	req, _ = http.NewRequest("GET", aurURL, nil)
	req.Header.Set("User-Agent", ua)

	resp, err = client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		var result struct {
			Results []struct {
				Name        string `json:"Name"`
				URL         string `json:"URL"`
				Description string `json:"Description"`
				License     string `json:"License"`
			} `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			var exactMatch *MetadataCandidate
			for _, r := range result.Results {
				cand := MetadataCandidate{
					Name:        r.Name,
					URL:         r.URL,
					Description: r.Description,
					License:     r.License,
					Category:    "extra",
					Source:      "AUR",
				}
				if r.Name == pkgName {
					exactMatch = &cand
				}
				if !seen[cand.Name] {
					candidates = append(candidates, cand)
					seen[cand.Name] = true
				}
			}
			// If exact match found on AUR and none on Arch, return it.
			if exactMatch != nil {
				return []MetadataCandidate{*exactMatch}, nil
			}
		}
		resp.Body.Close()
	}

	return candidates, nil
}

func promptSelection(candidates []MetadataCandidate) *MetadataCandidate {
	fmt.Printf("\nMultiple matches found. Please choose one:\n")
	for i, c := range candidates {
		fmt.Printf("%2d) %-20s [%s] %s\n", i+1, c.Name, c.Source, c.Description)
	}
	fmt.Printf(" q) skip\n")

	for {
		fmt.Printf("\nChoice [1-%d, q]: ", len(candidates))
		var input string
		fmt.Scanln(&input)
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "q" {
			return nil
		}

		idx := 0
		n, _ := fmt.Sscanf(input, "%d", &idx)
		if n == 1 && idx >= 1 && idx <= len(candidates) {
			return &candidates[idx-1]
		}
		fmt.Println("Invalid selection.")
	}
}

func displayMetadata(pkgName, sourcePkg string, meta *PackageMetadata) {
	colNote.Printf("\nPackage: %s\n", pkgName)
	if sourcePkg != "" && sourcePkg != pkgName {
		colSuccess.Print("Source:      ")
		fmt.Println(sourcePkg)
	}
	fmt.Printf("----------------------------------------\n")
	colSuccess.Print("URL:         ")
	fmt.Println(meta.URL)
	colSuccess.Print("Category:    ")
	fmt.Println(meta.Category)
	colSuccess.Print("Description: ")
	fmt.Println(meta.Description)
	colSuccess.Print("License:     ")
	fmt.Println(meta.License)
	colSuccess.Print("Tags:        ")
	fmt.Println(strings.Join(meta.Tags, ", "))
	if len(meta.Subpackages) > 0 {
		colSuccess.Print("Subpackages: ")
		fmt.Println(strings.Join(meta.Subpackages, ", "))
	}
	colSuccess.Print("Info:        ")
	fmt.Println()
	if meta.Info != "" {
		fmt.Println(meta.Info)
	} else {
		fmt.Println("(none)")
	}
	fmt.Println()
}

func editMetadata(pkgName, pkgDir string, meta *PackageMetadata, cfg *Config) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Editing metadata for %s\n", pkgName)

	// If essential metadata is missing, try to fetch it
	if meta.URL == "" || meta.Category == "" || meta.Description == "" {
		candidates, _ := searchMetadata(pkgName)
		if len(candidates) == 1 {
			applyCandidate(meta, &candidates[0])
		} else if len(candidates) > 1 {
			selected := promptSelection(candidates)
			if selected != nil {
				applyCandidate(meta, selected)
			}
		}
	}

	meta.URL = promptInput("URL", meta.URL, reader)
	meta.Category = promptInput("Category (base/extra)", meta.Category, reader)
	meta.Description = promptInput("Description", meta.Description, reader)
	meta.License = promptInput("License", meta.License, reader)

	// Tags
	fmt.Printf("Available tags: %s\n", strings.Join(validTags, ", "))
	fmt.Printf("Current tags: %s\n", strings.Join(meta.Tags, ", "))
	tagsInput := promptInput("Enter tags (comma separated)", strings.Join(meta.Tags, ", "), reader)
	meta.Tags = []string{}
	for _, t := range strings.Split(tagsInput, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			meta.Tags = append(meta.Tags, t)
		}
	}
	sort.Strings(meta.Tags)

	// Info (Check README)
	if meta.Info == "" {
		readmeFiles := []string{"README", "README.md", "readme.md", "readme"}
		for _, f := range readmeFiles {
			path := filepath.Join(pkgDir, f)
			if data, err := os.ReadFile(path); err == nil {
				meta.Info = string(data)
				break
			}
		}
	}

	fmt.Printf("\nAdditional Info/Comments:\n")
	if meta.Info != "" {
		fmt.Printf("Current info exists (%d chars).\n", len(meta.Info))
	} else {
		fmt.Println("(none)")
	}

	editInfo := promptYesNo("Do you want to edit/set Info?", false)
	if editInfo {
		// Use temporary file for editing info
		tmpFile, err := os.CreateTemp("", "hokuto-meta-info-*.txt")
		if err == nil {
			tmpPath := tmpFile.Name()
			_ = os.WriteFile(tmpPath, []byte(meta.Info), 0644)
			tmpFile.Close()

			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "nano"
			}
			if err := runEditor(editor, tmpPath); err == nil {
				if newData, err := os.ReadFile(tmpPath); err == nil {
					meta.Info = string(newData)
				}
			}
			os.Remove(tmpPath)
		}
	}

	// Save
	metaPath := filepath.Join(pkgDir, "metadata.json")
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return err
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Metadata saved to %s\n", metaPath)
	return nil
}

func editSplitMetadata(pkgName, sourcePkg, pkgDir string, parent *PackageMetadata, cfg *Config) error {
	reader := bufio.NewReader(os.Stdin)
	effective := effectiveMetadataForPackage(pkgName, sourcePkg, parent)

	fmt.Printf("Editing split metadata for %s\n", pkgName)

	if effective.URL == "" || effective.Category == "" || effective.Description == "" {
		candidates, _ := searchMetadata(pkgName)
		if len(candidates) == 1 {
			applyCandidate(&effective, &candidates[0])
		} else if len(candidates) > 1 {
			selected := promptSelection(candidates)
			if selected != nil {
				applyCandidate(&effective, selected)
			}
		}
	}

	effective.URL = promptInput("URL", effective.URL, reader)
	effective.Category = promptInput("Category (base/extra)", effective.Category, reader)
	effective.Description = promptInput("Description", effective.Description, reader)
	effective.License = promptInput("License", effective.License, reader)

	fmt.Printf("Available tags: %s\n", strings.Join(validTags, ", "))
	fmt.Printf("Current tags: %s\n", strings.Join(effective.Tags, ", "))
	tagsInput := promptInput("Enter tags (comma separated)", strings.Join(effective.Tags, ", "), reader)
	effective.Tags = []string{}
	for _, t := range strings.Split(tagsInput, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			effective.Tags = append(effective.Tags, t)
		}
	}
	sort.Strings(effective.Tags)

	fmt.Printf("\nAdditional Info/Comments:\n")
	if effective.Info != "" {
		fmt.Printf("Current info exists (%d chars).\n", len(effective.Info))
	} else {
		fmt.Println("(none)")
	}

	editInfo := promptYesNo("Do you want to edit/set Info?", false)
	if editInfo {
		tmpFile, err := os.CreateTemp("", "hokuto-meta-info-*.txt")
		if err == nil {
			tmpPath := tmpFile.Name()
			_ = os.WriteFile(tmpPath, []byte(effective.Info), 0644)
			tmpFile.Close()

			editor := os.Getenv("EDITOR")
			if editor == "" {
				editor = "nano"
			}
			if err := runEditor(editor, tmpPath); err == nil {
				if newData, err := os.ReadFile(tmpPath); err == nil {
					effective.Info = string(newData)
				}
			}
			os.Remove(tmpPath)
		}
	}

	parentComparable := *parent
	parentComparable.Subpackages = nil
	parentComparable.SplitMetadata = nil
	override := splitMetadataOverride(parentComparable, effective)
	if splitMetadataOverrideEmpty(override) {
		if parent.SplitMetadata != nil {
			delete(parent.SplitMetadata, pkgName)
			if len(parent.SplitMetadata) == 0 {
				parent.SplitMetadata = nil
			}
		}
	} else {
		if parent.SplitMetadata == nil {
			parent.SplitMetadata = make(map[string]SplitPkgMetadata)
		}
		parent.SplitMetadata[pkgName] = override
	}

	metaPath := filepath.Join(pkgDir, "metadata.json")
	data, err := json.MarshalIndent(parent, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return err
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Split metadata saved to %s\n", metaPath)
	return nil
}

func promptInput(label, defaultValue string, reader *bufio.Reader) string {
	fmt.Printf("%s [%s]: ", label, defaultValue)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultValue
	}
	return input
}

func promptYesNo(label string, defaultYes bool) bool {
	defStr := "Y/n"
	if !defaultYes {
		defStr = "y/N"
	}
	fmt.Printf("%s [%s]: ", label, defStr)
	var input string
	fmt.Scanln(&input)
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

// GeneratePkgDB generates the global package database from all repositories.
func GeneratePkgDB(cfg *Config) error {
	return generatePkgDB(cfg, false)
}

// generatePkgDBQuiet regenerates the package database without writing status
// messages. It is used by detached post-command refreshes and by operations
// which must refresh the database before immediately uploading it.
func generatePkgDBQuiet(cfg *Config) error {
	return generatePkgDB(cfg, true)
}

func generatePkgDB(cfg *Config, quiet bool) error {
	unlock, err := lockPkgDBGeneration()
	if err != nil {
		return err
	}
	defer unlock()

	if !quiet {
		colArrow.Print("-> ")
		colNote.Println("Generating global package database")
	}

	db := PkgDB{
		Revision: time.Now().Unix(),
		Packages: []PkgDBEntry{},
	}

	paths := filepath.SplitList(repoPaths)
	seen := make(map[string]bool)

	for _, base := range paths {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if !e.IsDir() || seen[e.Name()] {
				continue
			}

			pkgName := e.Name()
			pkgDir := filepath.Join(base, pkgName)

			// Try to read version
			verPath := filepath.Join(pkgDir, "version")
			verData, err := os.ReadFile(verPath)
			if err != nil {
				continue
			}
			fields := strings.Fields(string(verData))
			if len(fields) == 0 {
				continue
			}
			version := fields[0]

			// Try to read metadata
			var meta PackageMetadata
			metaPath := filepath.Join(pkgDir, "metadata.json")
			if data, err := os.ReadFile(metaPath); err == nil {
				_ = json.Unmarshal(data, &meta)
			}
			sort.Strings(meta.Tags)
			splitNames := splitPackageNamesFromDir(pkgDir)
			if len(splitNames) > 0 {
				meta.Subpackages = append([]string(nil), splitNames...)
			}
			parentDBMeta := meta
			parentDBMeta.SplitMetadata = nil

			db.Packages = append(db.Packages, PkgDBEntry{
				Name:     pkgName,
				Version:  version,
				Metadata: parentDBMeta,
			})
			seen[pkgName] = true

			for _, splitName := range splitNames {
				if seen[splitName] {
					continue
				}
				splitMeta := effectiveMetadataForPackage(splitName, pkgName, &meta)
				sort.Strings(splitMeta.Tags)
				db.Packages = append(db.Packages, PkgDBEntry{
					Name:          splitName,
					Version:       version,
					SourcePackage: pkgName,
					Metadata:      splitMeta,
				})
				seen[splitName] = true
			}
		}
	}

	for _, metaEntry := range localMetaPackageIndexEntries() {
		if seen[metaEntry.Name] {
			continue
		}
		db.Packages = append(db.Packages, PkgDBEntry{
			Name:    metaEntry.Name,
			Type:    "meta",
			Version: "meta",
			Metadata: PackageMetadata{
				Category:    "meta",
				Description: metaEntry.Description,
				Tags:        []string{"meta"},
			},
		})
		seen[metaEntry.Name] = true
	}

	dbDir := filepath.Dir(PkgDBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		if os.IsPermission(err) && os.Geteuid() != 0 && RootExec != nil {
			if runErr := RootExec.Run(exec.Command("mkdir", "-p", dbDir)); runErr != nil {
				return fmt.Errorf("failed to create database directory: %w", runErr)
			}
		} else {
			return fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	var compressed bytes.Buffer
	zw, err := zstd.NewWriter(&compressed)
	if err != nil {
		return fmt.Errorf("failed to create zstd writer: %w", err)
	}

	enc := json.NewEncoder(zw)
	if err := enc.Encode(db); err != nil {
		zw.Close()
		return fmt.Errorf("failed to encode database: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finalize database compression: %w", err)
	}

	if err := writeFileAsRoot(PkgDBPath, compressed.Bytes(), 0644, RootExec); err != nil {
		return fmt.Errorf("failed to write database file: %w", err)
	}

	if !quiet {
		colArrow.Print("-> ")
		colSuccess.Printf("Global package database generated: %s (revision: %d, packages: %d)\n", PkgDBPath, db.Revision, len(db.Packages))
	}
	return nil
}

// lockPkgDBGeneration serializes manual and background database writers. The
// lock is deliberately outside the database directory so an unprivileged
// edit command can acquire it before writeFileAsRoot performs any escalation.
func lockPkgDBGeneration() (func(), error) {
	lockID := hashString(PkgDBPath)
	lockPath := filepath.Join(os.TempDir(), "hokuto-pkg-db-"+lockID[:16]+".lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open package database lock: %w", err)
	}
	_ = syscall.Fchmod(fd, 0666)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("failed to lock package database: %w", err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = syscall.Close(fd)
	}, nil
}

// SearchPkgDB searches the global package database by name or tag.
func SearchPkgDB(args []string, cfg *Config) error {
	if len(args) == 0 {
		printSearchHelp()
		return nil
	}

	tagMode := false
	strictMode := false
	query := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-tag":
			tagMode = true
			if i+1 < len(args) {
				query = args[i+1]
				i++
			}
		case "-strict":
			strictMode = true
		default:
			query = args[i]
		}
	}

	if query == "" {
		printSearchHelp()
		return nil
	}

	if !tagMode {
		if pkgName, major, ok := parseMajorVersionSearch(query); ok {
			return searchPackageMajorVersion(pkgName, major, cfg)
		}
		if strings.Contains(query, "@") {
			return fmt.Errorf("invalid version-line search %q: use pkgname@MAJOR (for example, java-openjdk@17)", query)
		}
	}

	results := []PkgDBEntry{}
	queryLower := strings.ToLower(query)
	db, dbErr := readPkgDB(PkgDBPath)
	if dbErr == nil {
		for _, pkg := range db.Packages {
			if packageDBEntryMatchesSearch(pkg, query, queryLower, tagMode, strictMode) {
				results = append(results, pkg)
			}
		}
	}
	if tagMode && dbErr != nil {
		if os.IsNotExist(dbErr) {
			return fmt.Errorf("package database not found: %s. Run 'hokuto sync' to enable tag searches", PkgDBPath)
		}
		return dbErr
	}

	// A rootfs or binary-only system may have no HOKUTO_PATH and therefore no
	// useful locally generated database. Fall back to the signed binary index
	// for ordinary name/description searches. Tags remain local-only because
	// RepoEntry intentionally does not carry source metadata tags.
	var remoteErr error
	if len(results) == 0 && !tagMode {
		results, remoteErr = searchRemotePackageIndex(query, queryLower, strictMode, cfg)
	}
	if len(results) == 0 && dbErr != nil && remoteErr != nil {
		if os.IsNotExist(dbErr) {
			return fmt.Errorf("package database not found at %s and remote search failed: %w", PkgDBPath, remoteErr)
		}
		return fmt.Errorf("local package database unavailable (%v) and remote search failed: %w", dbErr, remoteErr)
	}

	if len(results) == 0 {
		colWarn.Printf("No matches found for '%s'.\n", query)
		return nil
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })

	colNote.Printf("\nSearch results for '%s' (%d matches):\n", query, len(results))
	fmt.Printf("--------------------------------------------------------------------------------\n")
	for _, r := range results {
		colSuccess.Printf("%-20s ", r.Name)
		fmt.Printf("%-10s ", r.Version)
		if r.Type == "meta" {
			color.Magenta.Print("(meta) ")
		}
		if r.SourcePackage != "" {
			color.Yellow.Printf("(split: %s) ", r.SourcePackage)
		}
		if len(r.Metadata.Tags) > 0 {
			color.Cyan.Printf("[%s]", strings.Join(r.Metadata.Tags, ", "))
		}
		fmt.Println()
		if r.Metadata.Description != "" {
			fmt.Printf("  %s\n", r.Metadata.Description)
		}
	}
	fmt.Println()

	return nil
}

func packageDBEntryMatchesSearch(pkg PkgDBEntry, query, queryLower string, tagMode, strictMode bool) bool {
	if tagMode {
		for _, tag := range pkg.Metadata.Tags {
			if (strictMode && strings.EqualFold(tag, query)) ||
				(!strictMode && strings.Contains(strings.ToLower(tag), queryLower)) {
				return true
			}
		}
		return false
	}
	if strictMode {
		return strings.EqualFold(pkg.Name, query)
	}
	return strings.Contains(strings.ToLower(pkg.Name), queryLower) ||
		strings.Contains(strings.ToLower(pkg.Metadata.Description), queryLower)
}

func searchRemotePackageIndex(query, queryLower string, strictMode bool, cfg *Config) ([]PkgDBEntry, error) {
	index, err := getCachedRemoteIndex(cfg, true)
	if err != nil {
		return nil, err
	}

	matchedNames := make(map[string]RepoEntry)
	for _, entry := range index {
		nameMatch := strings.Contains(strings.ToLower(entry.Name), queryLower) ||
			strings.Contains(strings.ToLower(entry.Description), queryLower)
		if strictMode {
			nameMatch = strings.EqualFold(entry.Name, query)
		}
		if !nameMatch {
			continue
		}
		if entry.Type != "meta" && entry.Arch != GetSystemArchForPackage(cfg, entry.Name) {
			continue
		}
		current, exists := matchedNames[entry.Name]
		if !exists || isNewer(entry, current) {
			matchedNames[entry.Name] = entry
		}
	}

	results := make([]PkgDBEntry, 0, len(matchedNames))
	for name, candidate := range matchedNames {
		selected := candidate
		if candidate.Type != "meta" {
			if preferred, resolveErr := GetRemotePackageEntry(name, cfg, index); resolveErr == nil {
				selected = *preferred
			}
		}
		results = append(results, PkgDBEntry{
			Name:    selected.Name,
			Type:    selected.Type,
			Version: selected.Version,
			Metadata: PackageMetadata{
				Description: selected.Description,
			},
		})
	}
	return results, nil
}

type majorVersionSearchResult struct {
	version  string
	revision string
	remote   bool
	git      bool
}

func parseMajorVersionSearch(query string) (string, string, bool) {
	pkgName, major, found := strings.Cut(strings.TrimSpace(query), "@")
	if !found || pkgName == "" || major == "" || strings.Contains(major, "@") {
		return "", "", false
	}
	if _, err := strconv.Atoi(major); err != nil {
		return "", "", false
	}
	return pkgName, major, true
}

func normalizePackageRevision(revision string) string {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return "1"
	}
	return revision
}

// compareMajorLineVersions performs a natural comparison so embedded numeric
// components such as the 20 in 17.0.20+7 are compared numerically. The general
// dependency comparator splits only on dots and would otherwise order 9+7
// after 20+7 lexicographically.
func compareMajorLineVersions(a, b string) int {
	for ai, bi := 0, 0; ai < len(a) || bi < len(b); {
		if ai >= len(a) {
			return -1
		}
		if bi >= len(b) {
			return 1
		}
		aDigit := a[ai] >= '0' && a[ai] <= '9'
		bDigit := b[bi] >= '0' && b[bi] <= '9'
		aj, bj := ai, bi
		for aj < len(a) && (a[aj] >= '0' && a[aj] <= '9') == aDigit {
			aj++
		}
		for bj < len(b) && (b[bj] >= '0' && b[bj] <= '9') == bDigit {
			bj++
		}
		at, bt := a[ai:aj], b[bi:bj]
		if aDigit && bDigit {
			an := strings.TrimLeft(at, "0")
			bn := strings.TrimLeft(bt, "0")
			if an == "" {
				an = "0"
			}
			if bn == "" {
				bn = "0"
			}
			if len(an) < len(bn) {
				return -1
			}
			if len(an) > len(bn) {
				return 1
			}
			if an < bn {
				return -1
			}
			if an > bn {
				return 1
			}
		} else {
			if at < bt {
				return -1
			}
			if at > bt {
				return 1
			}
		}
		ai, bi = aj, bj
	}
	return 0
}

func addMajorVersionSearchCandidate(best *majorVersionSearchResult, version, revision string, remote, git bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return
	}
	revision = normalizePackageRevision(revision)
	cmp := compareMajorLineVersions(version, best.version)
	if best.version == "" || cmp > 0 || (cmp == 0 && revisionCompare(revision, best.revision) > 0) {
		*best = majorVersionSearchResult{
			version:  version,
			revision: revision,
			remote:   remote,
			git:      git,
		}
		return
	}
	if cmp == 0 && revisionCompare(revision, best.revision) == 0 {
		best.remote = best.remote || remote
		best.git = best.git || git
	}
}

func searchPackageMajorVersion(pkgName, major string, cfg *Config) error {
	best := majorVersionSearchResult{}
	targetArch := GetSystemArchForPackage(cfg, pkgName)
	remoteIndex, remoteErr := getCachedRemoteIndex(cfg, true)
	if remoteErr == nil {
		for _, entry := range remoteIndex {
			if entry.Type == "meta" || entry.Name != pkgName || entry.Arch != targetArch {
				continue
			}
			if strings.SplitN(strings.TrimSpace(entry.Version), ".", 2)[0] == major {
				addMajorVersionSearchCandidate(&best, entry.Version, entry.Revision, true, false)
			}
		}
	}

	gitErr := addGitMajorVersionCandidates(&best, pkgName, major)
	if best.version == "" {
		if remoteErr != nil && gitErr != nil {
			debugf("Major-version search remote lookup failed: %v\n", remoteErr)
			debugf("Major-version search Git lookup failed: %v\n", gitErr)
		}
		return fmt.Errorf("no version of %s in major line %s was found in the remote repository or Git history", pkgName, major)
	}

	source := "remote repository"
	if best.git {
		source = "Git history"
	}
	if best.remote && best.git {
		source = "remote repository and Git history"
	}
	colSuccess.Printf("%s@%s: latest version is %s", pkgName, major, best.version)
	colNote.Printf(" (revision %s; %s)\n", best.revision, source)
	return nil
}

func addGitMajorVersionCandidates(best *majorVersionSearchResult, pkgName, major string) error {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return err
	}
	if versionData, readErr := os.ReadFile(filepath.Join(pkgDir, "version")); readErr == nil {
		fields := strings.Fields(string(versionData))
		if len(fields) > 0 && strings.SplitN(fields[0], ".", 2)[0] == major {
			revision := "1"
			if len(fields) > 1 {
				revision = fields[1]
			}
			addMajorVersionSearchCandidate(best, fields[0], revision, false, true)
		}
	}

	gitRootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	gitRootCmd.Dir = pkgDir
	gitRootOut, err := gitRootCmd.Output()
	if err != nil {
		return fmt.Errorf("package directory %s is not in a Git repository: %w", pkgDir, err)
	}
	gitRoot := strings.TrimSpace(string(gitRootOut))
	relPath, err := filepath.Rel(gitRoot, pkgDir)
	if err != nil {
		return fmt.Errorf("failed to determine the repository path for %s: %w", pkgName, err)
	}

	logCmd := exec.Command("git", "log", "--all", "--format=%H", "--", relPath)
	logCmd.Dir = gitRoot
	logOut, err := logCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to search Git history for %s: %w", pkgName, err)
	}
	for _, commit := range strings.Fields(string(logOut)) {
		showCmd := exec.Command("git", "show", fmt.Sprintf("%s:%s/version", commit, relPath))
		showCmd.Dir = gitRoot
		showOut, showErr := showCmd.Output()
		if showErr != nil {
			continue
		}
		fields := strings.Fields(string(showOut))
		if len(fields) == 0 || strings.SplitN(fields[0], ".", 2)[0] != major {
			continue
		}
		revision := "1"
		if len(fields) > 1 {
			revision = fields[1]
		}
		addMajorVersionSearchCandidate(best, fields[0], revision, false, true)
	}
	return nil
}

func printSearchHelp() {
	colNote.Println("Usage: hokuto search <query>       Search by package name or description")
	colNote.Println("       hokuto search <pkg>@<major> Find the latest release in a major version line")
	colNote.Println("       hokuto search -tag <tag>    Search by package tag")
	colNote.Println("       hokuto search -strict <q>   Search for exact name matches")
	fmt.Println()
	colSuccess.Println("Available Tags:")
	// Print tags in a grid
	for i, t := range validTags {
		fmt.Printf("%-20s", t)
		if (i+1)%5 == 0 {
			fmt.Println()
		}
	}
	fmt.Printf("\n")
}
