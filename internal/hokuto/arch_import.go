package hokuto

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PKGBUILDInfo holds parsed information from a PKGBUILD
type PKGBUILDInfo struct {
	Version     string
	Sources     []string
	Depends     []string
	MakeDepends []string
	BuildFunc   string
	PackageFunc string
}

// fetchPKGBUILD downloads the PKGBUILD from Arch or AUR
func fetchPKGBUILD(pkgName string, source string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	var url string

	if source == "AUR" {
		// AUR PKGBUILD URL format
		url = fmt.Sprintf("https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=%s", pkgName)
	} else {
		// Arch Linux PKGBUILD - use GitLab packaging repo
		url = fmt.Sprintf("https://gitlab.archlinux.org/archlinux/packaging/packages/%s/-/raw/main/PKGBUILD", pkgName)
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch PKGBUILD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("PKGBUILD not found (HTTP %d)", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read PKGBUILD: %w", err)
	}

	return string(body), nil
}

// parsePKGBUILD extracts relevant information from PKGBUILD content
func parsePKGBUILD(content string, pkgName string) (*PKGBUILDInfo, error) {
	info := &PKGBUILDInfo{}

	// Extract pkgver
	if match := regexp.MustCompile(`(?m)^pkgver=(.+)$`).FindStringSubmatch(content); len(match) > 1 {
		info.Version = strings.Trim(match[1], `"'`)
	}

	// Extract source array (handle multi-line)
	info.Sources = extractBashArray(content, "source")

	// Extract depends array
	info.Depends = extractBashArray(content, "depends")

	// Extract makedepends array
	info.MakeDepends = extractBashArray(content, "makedepends")

	// Extract build() function
	info.BuildFunc = extractBashFunction(content, "build")

	// Extract package() function
	info.PackageFunc = extractBashFunction(content, "package")

	// Replace variable references in sources
	for i, src := range info.Sources {
		src = strings.ReplaceAll(src, "${pkgname}", pkgName)
		src = strings.ReplaceAll(src, "$pkgname", pkgName)
		src = strings.ReplaceAll(src, "${pkgver}", "${version}")
		src = strings.ReplaceAll(src, "$pkgver", "${version}")
		info.Sources[i] = src
	}

	return info, nil
}

// extractBashArray extracts values from a bash array declaration
func extractBashArray(content string, arrayName string) []string {
	var result []string

	// Match array declaration (single or multi-line)
	// Use ^\s* to ensure we match the variable definition at the start of a line
	// preventing 'depends' from matching 'makedepends'.
	pattern := fmt.Sprintf(`(?ms)^\s*%s=\((.*?)\)`, arrayName)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(content)

	if len(match) < 2 {
		return result
	}

	arrayContent := match[1]

	// Split by whitespace and newlines, respecting quotes
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, ch := range arrayContent {
		if (ch == '"' || ch == '\'') && !inQuote {
			inQuote = true
			quoteChar = ch
			continue
		} else if ch == quoteChar && inQuote {
			inQuote = false
			quoteChar = 0
			if current.Len() > 0 {
				result = append(result, current.String())
				current.Reset()
			}
			continue
		}

		if inQuote {
			current.WriteRune(ch)
		} else if ch != ' ' && ch != '\n' && ch != '\t' {
			current.WriteRune(ch)
		} else if current.Len() > 0 {
			result = append(result, current.String())
			current.Reset()
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// extractBashFunction extracts the body of a bash function
func extractBashFunction(content string, funcName string) string {
	// Match function definition
	pattern := fmt.Sprintf(`(?s)%s\s*\(\s*\)\s*\{(.*?)\n\}`, funcName)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(content)

	if len(match) < 2 {
		return ""
	}

	return strings.TrimSpace(match[1])
}

// generatePackageFromArch creates a package structure from Arch/AUR PKGBUILD
func generatePackageFromArch(pkgName string, source string, targetDir string) error {
	colArrow.Print("-> ")
	colSuccess.Printf("Searching %s for '%s'\n", source, pkgName)

	// Fetch PKGBUILD
	pkgbuild, err := fetchPKGBUILD(pkgName, source)
	if err != nil {
		return fmt.Errorf("failed to fetch PKGBUILD: %w", err)
	}

	colArrow.Print("-> ")
	colSuccess.Println("Parsing PKGBUILD")

	// Parse PKGBUILD
	info, err := parsePKGBUILD(pkgbuild, pkgName)
	if err != nil {
		return fmt.Errorf("failed to parse PKGBUILD: %w", err)
	}

	if info.Version == "" {
		return fmt.Errorf("could not extract version from PKGBUILD")
	}

	// Determine package directory
	var pkgDir string
	if targetDir != "" {
		pkgDir = filepath.Join(targetDir, pkgName)
	} else {
		if newPackageDir == "" {
			return fmt.Errorf("newPackageDir is not set")
		}
		pkgDir = filepath.Join(newPackageDir, pkgName)
	}

	// Check if package already exists
	if fi, err := os.Stat(pkgDir); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("package %s already exists at %s", pkgName, pkgDir)
		}
		return fmt.Errorf("path %s exists and is not a directory", pkgDir)
	}

	// Create package directory
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return fmt.Errorf("failed to create package directory: %w", err)
	}

	// 1. Create version file
	versionContent := fmt.Sprintf("%s 1\n", info.Version)
	versionPath := filepath.Join(pkgDir, "version")
	if err := os.WriteFile(versionPath, []byte(versionContent), 0o644); err != nil {
		return fmt.Errorf("failed to create version file: %w", err)
	}

	// 2. Create .sources file (with placeholders)
	dotSourcesPath := filepath.Join(pkgDir, ".sources")
	dotSourcesContent := strings.Join(info.Sources, "\n")
	if dotSourcesContent != "" {
		dotSourcesContent += "\n"
	}
	if err := os.WriteFile(dotSourcesPath, []byte(dotSourcesContent), 0o644); err != nil {
		return fmt.Errorf("failed to create .sources file: %w", err)
	}

	// 3. Create sources file (with version substituted)
	sourcesPath := filepath.Join(pkgDir, "sources")
	sourcesContent := applySubstitutions(dotSourcesContent, info.Version, pkgName, nil)
	if err := os.WriteFile(sourcesPath, []byte(sourcesContent), 0o644); err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}

	// 4. Create depends file
	dependsPath := filepath.Join(pkgDir, "depends")
	var dependsLines []string
	for _, dep := range info.Depends {
		dependsLines = append(dependsLines, dep)
	}
	for _, dep := range info.MakeDepends {
		dependsLines = append(dependsLines, dep+" make")
	}
	dependsContent := strings.Join(dependsLines, "\n")
	if dependsContent != "" {
		dependsContent += "\n"
	}
	if err := os.WriteFile(dependsPath, []byte(dependsContent), 0o644); err != nil {
		return fmt.Errorf("failed to create depends file: %w", err)
	}

	// 5. Create build script
	buildPath := filepath.Join(pkgDir, "build")
	buildScript := generateBuildScript(info, pkgName)
	if err := os.WriteFile(buildPath, []byte(buildScript), 0o755); err != nil {
		return fmt.Errorf("failed to create build file: %w", err)
	}

	// Success messages
	colArrow.Print("-> ")
	colSuccess.Printf("Package %s created in %s\n", pkgName, pkgDir)
	colArrow.Print("-> ")
	colInfo.Printf("Version: %s 1\n", info.Version)
	if len(info.Sources) > 0 {
		colArrow.Print("-> ")
		colInfo.Printf("Sources: %d URLs added\n", len(info.Sources))
	}
	if len(info.Depends)+len(info.MakeDepends) > 0 {
		colArrow.Print("-> ")
		colInfo.Printf("Depends: %d packages\n", len(info.Depends)+len(info.MakeDepends))
	}

	return nil
}

// generateBuildScript creates a build script from PKGBUILD functions
func generateBuildScript(info *PKGBUILDInfo, pkgName string) string {
	var script strings.Builder

	script.WriteString("#!/bin/sh -e\n")
	script.WriteString("# Auto-generated from PKGBUILD\n")
	script.WriteString("# You may need to adjust this script for Hokuto\n\n")

	// Add build() function content if present
	if info.BuildFunc != "" {
		script.WriteString("# Build phase\n")
		buildContent := translatePKGBUILDFunction(info.BuildFunc, pkgName)
		script.WriteString(buildContent)
		script.WriteString("\n\n")
	}

	// Add package() function content if present
	if info.PackageFunc != "" {
		script.WriteString("# Install phase\n")
		packageContent := translatePKGBUILDFunction(info.PackageFunc, pkgName)
		script.WriteString(packageContent)
		script.WriteString("\n")
	}

	if info.BuildFunc == "" && info.PackageFunc == "" {
		script.WriteString("# No build or package functions found in PKGBUILD\n")
		script.WriteString("# Add your build instructions here\n")
	}

	return script.String()
}

// translatePKGBUILDFunction translates PKGBUILD function body to Hokuto format
func translatePKGBUILDFunction(funcBody string, pkgName string) string {
	// Replace PKGBUILD variables with Hokuto equivalents
	// ${pkgdir} -> ${1}
	// ${pkgver} -> ${2}
	// ${pkgname} -> ${3}
	// Remove ${srcdir} references (hokuto builds in source dir)

	result := funcBody

	// Replace pkgdir
	result = strings.ReplaceAll(result, "${pkgdir}", "${1}")
	result = strings.ReplaceAll(result, "$pkgdir", "${1}")

	// Replace pkgver
	result = strings.ReplaceAll(result, "${pkgver}", "${2}")
	result = strings.ReplaceAll(result, "$pkgver", "${2}")

	// Replace pkgname
	result = strings.ReplaceAll(result, "${pkgname}", "${3}")
	result = strings.ReplaceAll(result, "$pkgname", "${3}")

	// Remove srcdir references (just remove the variable, keep the path)
	result = regexp.MustCompile(`\$\{srcdir\}/`).ReplaceAllString(result, "")
	result = regexp.MustCompile(`\$srcdir/`).ReplaceAllString(result, "")
	result = strings.ReplaceAll(result, "${srcdir}", ".")
	result = strings.ReplaceAll(result, "$srcdir", ".")

	return result
}
