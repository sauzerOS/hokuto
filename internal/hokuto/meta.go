package hokuto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sort"

	"github.com/gookit/color"
	"github.com/klauspost/compress/zstd"
)

// PackageMetadata represents the structure of metadata.json
type PackageMetadata struct {
	URL         string   `json:"url"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Info        string   `json:"info"`
	License     string   `json:"license"`
	Tags        []string `json:"tags"`
}

// PkgDBEntry represents a single package in the global database
type PkgDBEntry struct {
	Name     string          `json:"name"`
	Version  string          `json:"version"`
	Metadata PackageMetadata `json:"metadata"`
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
	if err != nil {
		return err
	}

	metaPath := filepath.Join(pkgDir, "metadata.json")
	var meta PackageMetadata

	// Load existing metadata if available
	if data, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(data, &meta)
	}

	if editMode {
		return editMetadata(pkgName, pkgDir, &meta, cfg)
	}

	// If essential metadata is missing, try to fetch it
	if meta.URL == "" || meta.Category == "" || meta.Description == "" {
		colArrow.Print("-> ")
		colNote.Printf("Metadata missing. Searching Arch/AUR for '%s'\n", pkgName)
		candidates, err := searchMetadata(pkgName)
		if err != nil {
			colWarn.Printf("Search failed: %v\n", err)
		} else if len(candidates) == 1 {
			applyCandidate(&meta, &candidates[0])
		} else if len(candidates) > 1 {
			selected := promptSelection(candidates)
			if selected != nil {
				applyCandidate(&meta, selected)
			}
		} else {
			colWarn.Printf("No matches found for '%s'.\n", pkgName)
		}
	}

	displayMetadata(pkgName, &meta)
	return nil
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

func displayMetadata(pkgName string, meta *PackageMetadata) {
	colNote.Printf("\nPackage: %s\n", pkgName)
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
	colArrow.Print("-> ")
	colNote.Println("Generating global package database")

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

			db.Packages = append(db.Packages, PkgDBEntry{
				Name:     pkgName,
				Version:  version,
				Metadata: meta,
			})
			seen[pkgName] = true
		}
	}

	// Ensure directory exists
	dbDir := filepath.Dir(PkgDBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Write and compress
	f, err := os.Create(PkgDBPath)
	if err != nil {
		return fmt.Errorf("failed to create database file: %w", err)
	}
	defer f.Close()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		return fmt.Errorf("failed to create zstd writer: %w", err)
	}
	defer zw.Close()

	enc := json.NewEncoder(zw)
	if err := enc.Encode(db); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Global package database generated: %s (revision: %d, packages: %d)\n", PkgDBPath, db.Revision, len(db.Packages))
	return nil
}

// SearchPkgDB searches the global package database by name or tag.
func SearchPkgDB(args []string, cfg *Config) error {
	if len(args) == 0 {
		printSearchHelp()
		return nil
	}

	tagMode := false
	query := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "-tag" {
			tagMode = true
			if i+1 < len(args) {
				query = args[i+1]
				i++
			}
		} else {
			query = args[i]
		}
	}

	if query == "" {
		printSearchHelp()
		return nil
	}

	db, err := readPkgDB(PkgDBPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("package database not found: %s. Run 'hokuto meta -db' or 'hokuto sync'", PkgDBPath)
		}
		return err
	}

	results := []PkgDBEntry{}
	queryLower := strings.ToLower(query)

	for _, pkg := range db.Packages {
		if tagMode {
			for _, t := range pkg.Metadata.Tags {
				if strings.Contains(strings.ToLower(t), queryLower) {
					results = append(results, pkg)
					break
				}
			}
		} else {
			if strings.Contains(strings.ToLower(pkg.Name), queryLower) ||
				strings.Contains(strings.ToLower(pkg.Metadata.Description), queryLower) {
				results = append(results, pkg)
			}
		}
	}

	if len(results) == 0 {
		colWarn.Printf("No matches found for '%s'.\n", query)
		return nil
	}

	colNote.Printf("\nSearch results for '%s' (%d matches):\n", query, len(results))
	fmt.Printf("--------------------------------------------------------------------------------\n")
	for _, r := range results {
		colSuccess.Printf("%-20s ", r.Name)
		fmt.Printf("%-10s ", r.Version)
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

func printSearchHelp() {
	colNote.Println("Usage: hokuto search <query>       Search by package name or description")
	colNote.Println("       hokuto search -tag <tag>    Search by package tag")
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
