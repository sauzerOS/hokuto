package hokuto

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PKGBUILDInfo holds parsed information from a PKGBUILD
type PKGBUILDInfo struct {
	PkgBase     string
	Version     string
	Sources     []string
	Depends     []string
	MakeDepends []string
	PrepareFunc string
	BuildFunc   string
	PackageFunc string
	SplitFuncs  []PKGBUILDFunction
}

type PKGBUILDFunction struct {
	Name    string
	Package string
	Body    string
	Depends []string
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

func archPackageFileURL(pkgName, source, fileName string) (string, error) {
	clean := filepath.ToSlash(filepath.Clean(fileName))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("unsafe local PKGBUILD source path %q", fileName)
	}
	parts := strings.Split(clean, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	escapedPath := strings.Join(parts, "/")
	if source == "AUR" {
		return fmt.Sprintf("https://aur.archlinux.org/cgit/aur.git/plain/%s?h=%s", escapedPath, url.QueryEscape(pkgName)), nil
	}
	return fmt.Sprintf("https://gitlab.archlinux.org/archlinux/packaging/packages/%s/-/raw/main/%s", url.PathEscape(pkgName), escapedPath), nil
}

func downloadArchPackageFile(pkgName, source, fileName, destination string) error {
	fileURL, err := archPackageFileURL(pkgName, source, fileName)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fileURL)
	if err != nil {
		return fmt.Errorf("failed to fetch %s: %w", fileName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch %s (HTTP %d)", fileName, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tmp := destination + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, resp.Body)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func materializeArchLocalSources(info *PKGBUILDInfo, pkgName, source, pkgDir string) error {
	for i, item := range info.Sources {
		if isRemoteImportSource(item) || strings.HasPrefix(item, "files/") {
			continue
		}
		// Renamed remote sources have already been translated to "URL -> name".
		if fields := strings.Fields(item); len(fields) >= 3 && fields[len(fields)-2] == "->" && isRemoteImportSource(fields[0]) {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(item))
		destination := filepath.Join(pkgDir, "files", filepath.FromSlash(clean))
		colArrow.Print("-> ")
		colSuccess.Printf("Downloading PKGBUILD file %s\n", item)
		if err := downloadArchPackageFile(pkgName, source, clean, destination); err != nil {
			return err
		}
		info.Sources[i] = "files/" + clean
	}
	return nil
}

// parsePKGBUILD extracts relevant information from PKGBUILD content
func parsePKGBUILD(content string, pkgName string) (*PKGBUILDInfo, error) {
	info := &PKGBUILDInfo{}
	variables := extractPKGBUILDVariables(content)
	info.PkgBase = variables["pkgbase"]
	if info.PkgBase == "" {
		info.PkgBase = pkgName
	}

	// Extract pkgver
	info.Version = variables["pkgver"]

	// Extract source array (handle multi-line)
	info.Sources = extractBashArray(content, "source")

	// Extract depends array
	info.Depends = extractBashArray(content, "depends")

	// Extract makedepends array
	info.MakeDepends = extractBashArray(content, "makedepends")

	packageNames := extractBashArray(content, "pkgname")
	for _, fn := range extractBashFunctions(content) {
		fn.Body = expandPKGBUILDVariables(fn.Body, variables)
		switch fn.Name {
		case "prepare":
			info.PrepareFunc = fn.Body
		case "build":
			info.BuildFunc = fn.Body
		case "package":
			info.PackageFunc = fn.Body
		default:
			if !strings.HasPrefix(fn.Name, "package_") {
				continue
			}
			suffix := strings.TrimPrefix(fn.Name, "package_")
			splitName := suffix
			for _, candidate := range packageNames {
				if candidate == suffix || strings.ReplaceAll(candidate, "-", "_") == suffix {
					splitName = candidate
					break
				}
			}
			fn.Package = splitName
			fn.Depends = extractBashArray(fn.Body, "depends")
			if splitName == pkgName && info.PackageFunc == "" {
				info.PackageFunc = fn.Body
				if len(fn.Depends) > 0 {
					info.Depends = append([]string(nil), fn.Depends...)
				}
				continue
			}
			info.SplitFuncs = append(info.SplitFuncs, fn)
		}
	}

	// Replace variable references in sources
	// Replace variable references in sources
	for i, src := range info.Sources {
		// Keep direct pkgver references tied to Hokuto's version placeholder.
		src = strings.ReplaceAll(src, "${pkgver}", "${version}")
		src = strings.ReplaceAll(src, "$pkgver", "${version}")
		src = expandPKGBUILDVariables(src, variables)
		if info.PkgBase != "" {
			first := string([]rune(info.PkgBase)[0])
			src = strings.ReplaceAll(src, "${pkgbase::1}", first)
			src = strings.ReplaceAll(src, "${pkgbase}", info.PkgBase)
			src = strings.ReplaceAll(src, "$pkgbase", info.PkgBase)
		}
		src = strings.ReplaceAll(src, "${pkgname}", pkgName)
		src = strings.ReplaceAll(src, "$pkgname", pkgName)

		// Convert Arch-style renaming "filename::URL" to Hokuto-style "URL -> filename"
		if filename, sourceURL, ok := splitArchRenamedSource(src); ok {
			src = fmt.Sprintf("%s -> %s", sourceURL, filename)
		}

		info.Sources[i] = src
	}

	return info, nil
}

func extractPKGBUILDVariables(content string) map[string]string {
	variables := make(map[string]string)
	re := regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_]*)=([^\n]*)$`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		value := strings.TrimSpace(match[2])
		if strings.HasPrefix(value, "(") {
			continue
		}
		value = strings.Trim(value, `"'`)
		variables[match[1]] = expandPKGBUILDVariables(value, variables)
	}
	// Resolve forward references and chained assignments with a bounded pass.
	for range 10 {
		changed := false
		for name, value := range variables {
			expanded := expandPKGBUILDVariables(value, variables)
			if expanded != value {
				variables[name] = expanded
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return variables
}

func expandPKGBUILDVariables(value string, variables map[string]string) string {
	substring := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)::([0-9]+)\}`)
	value = substring.ReplaceAllStringFunc(value, func(expr string) string {
		parts := substring.FindStringSubmatch(expr)
		resolved, ok := variables[parts[1]]
		if !ok {
			return expr
		}
		length := 0
		fmt.Sscanf(parts[2], "%d", &length)
		runes := []rune(resolved)
		if length < len(runes) {
			runes = runes[:length]
		}
		return string(runes)
	})

	replacement := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)/(\/)?([^/]*)/([^}]*)\}`)
	value = replacement.ReplaceAllStringFunc(value, func(expr string) string {
		parts := replacement.FindStringSubmatch(expr)
		resolved, ok := variables[parts[1]]
		if !ok {
			return expr
		}
		if parts[2] == "/" {
			return strings.ReplaceAll(resolved, parts[3], parts[4])
		}
		return strings.Replace(resolved, parts[3], parts[4], 1)
	})

	braced := regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	value = braced.ReplaceAllStringFunc(value, func(expr string) string {
		name := braced.FindStringSubmatch(expr)[1]
		if resolved, ok := variables[name]; ok {
			return resolved
		}
		return expr
	})
	unbraced := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	return unbraced.ReplaceAllStringFunc(value, func(expr string) string {
		name := expr[1:]
		if resolved, ok := variables[name]; ok {
			return resolved
		}
		return expr
	})
}

func extractBashScalar(content, name string) string {
	pattern := fmt.Sprintf(`(?m)^[ \t]*%s=([^\n#]+)`, regexp.QuoteMeta(name))
	match := regexp.MustCompile(pattern).FindStringSubmatch(content)
	if len(match) < 2 {
		return ""
	}
	return strings.Trim(strings.TrimSpace(match[1]), `"'`)
}

func splitArchRenamedSource(source string) (string, string, bool) {
	idx := strings.Index(source, "::")
	if idx <= 0 {
		return "", "", false
	}
	filename, sourceURL := source[:idx], source[idx+2:]
	if !isRemoteImportSource(sourceURL) {
		return "", "", false
	}
	return filename, sourceURL, true
}

func isRemoteImportSource(source string) bool {
	for _, prefix := range []string{"http://", "https://", "ftp://", "git+", "svn+", "hg+"} {
		if strings.HasPrefix(source, prefix) {
			return true
		}
	}
	return false
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
	for _, fn := range extractBashFunctions(content) {
		if fn.Name == funcName {
			return fn.Body
		}
	}
	return ""
}

func extractBashFunctions(content string) []PKGBUILDFunction {
	re := regexp.MustCompile(`(?m)^[ \t]*([A-Za-z0-9_+.-]+)[ \t]*\([ \t]*\)[ \t]*\{`)
	matches := re.FindAllStringSubmatchIndex(content, -1)
	var functions []PKGBUILDFunction
	for _, match := range matches {
		name := content[match[2]:match[3]]
		open := match[1] - 1
		depth := 0
		inSingle, inDouble, escaped, comment := false, false, false, false
		end := -1
		for i := open; i < len(content); i++ {
			ch := content[i]
			if comment {
				if ch == '\n' {
					comment = false
				}
				continue
			}
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' && !inSingle {
				escaped = true
				continue
			}
			if ch == '\'' && !inDouble {
				inSingle = !inSingle
				continue
			}
			if ch == '"' && !inSingle {
				inDouble = !inDouble
				continue
			}
			if inSingle || inDouble {
				continue
			}
			if ch == '#' && (i == 0 || content[i-1] == ' ' || content[i-1] == '\t' || content[i-1] == '\n') {
				comment = true
				continue
			}
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end > open {
			functions = append(functions, PKGBUILDFunction{Name: name, Body: dedentShellBody(content[open+1 : end])})
		}
	}
	return functions
}

func dedentShellBody(body string) string {
	lines := strings.Split(strings.Trim(body, "\n\r"), "\n")
	indent := -1
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		width := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == -1 || width < indent {
			indent = width
		}
	}
	if indent > 0 {
		for i, line := range lines {
			if len(line) >= indent {
				lines[i] = line[indent:]
			}
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
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
	if err := materializeArchLocalSources(info, info.PkgBase, source, pkgDir); err != nil {
		return fmt.Errorf("failed to import local PKGBUILD source: %w", err)
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
	sourcesContent := applySubstitutions(dotSourcesContent, info.Version, "1", pkgName, nil)
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
	for _, split := range info.SplitFuncs {
		splitDir := filepath.Join(pkgDir, "split", split.Package)
		if err := os.MkdirAll(splitDir, 0o755); err != nil {
			return fmt.Errorf("failed to create split package metadata for %s: %w", split.Package, err)
		}
		splitDepends := split.Depends
		if len(splitDepends) == 0 {
			splitDepends = info.Depends
		}
		content := strings.Join(splitDepends, "\n")
		if content != "" {
			content += "\n"
		}
		if err := os.WriteFile(filepath.Join(splitDir, "depends"), []byte(content), 0o644); err != nil {
			return fmt.Errorf("failed to create split depends file for %s: %w", split.Package, err)
		}
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
	if len(info.SplitFuncs) > 0 {
		colArrow.Print("-> ")
		colInfo.Printf("Split packages: %d preserved\n", len(info.SplitFuncs))
	}

	return nil
}

// generateBuildScript creates a build script from PKGBUILD functions
func generateBuildScript(info *PKGBUILDInfo, pkgName string) string {
	var script strings.Builder

	script.WriteString("#!/bin/sh -e\n")
	script.WriteString("# Auto-generated from PKGBUILD\n")
	script.WriteString("# You may need to adjust this script for Hokuto\n\n")
	if info.PrepareFunc != "" {
		script.WriteString("# Prepare phase\n")
		script.WriteString(translatePKGBUILDFunction(info.PrepareFunc, pkgName))
		script.WriteString("\n\n")
	}

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

	for _, split := range info.SplitFuncs {
		script.WriteString("\n# Split install phase: " + split.Package + "\n")
		dest := `${HOKUTO_SPLIT_DIR}/` + split.Package
		packageContent := translatePKGBUILDFunctionWithValues(split.Body, dest, split.Package)
		script.WriteString(packageContent)
		script.WriteString("\n")
	}

	if info.PrepareFunc == "" && info.BuildFunc == "" && info.PackageFunc == "" && len(info.SplitFuncs) == 0 {
		script.WriteString("# No build or package functions found in PKGBUILD\n")
		script.WriteString("# Add your build instructions here\n")
	}

	return script.String()
}

// translatePKGBUILDFunction translates PKGBUILD function body to Hokuto format
func translatePKGBUILDFunction(funcBody string, pkgName string) string {
	return translatePKGBUILDFunctionWithValues(funcBody, "${1}", "${3}")
}

func translatePKGBUILDFunctionWithValues(funcBody, pkgdirValue, pkgnameValue string) string {
	// Replace PKGBUILD variables with Hokuto equivalents
	// ${pkgdir} -> ${1}
	// ${pkgver} -> ${2}
	// ${pkgname} -> ${3}
	// Remove ${srcdir} references (hokuto builds in source dir)

	result := stripPKGBUILDFunctionMetadata(funcBody)

	// Replace pkgdir
	result = strings.ReplaceAll(result, "${pkgdir}", pkgdirValue)
	result = strings.ReplaceAll(result, "$pkgdir", pkgdirValue)

	// Replace pkgver
	result = strings.ReplaceAll(result, "${pkgver}", "${2}")
	result = strings.ReplaceAll(result, "$pkgver", "${2}")

	// Replace pkgname
	result = strings.ReplaceAll(result, "${pkgname}", pkgnameValue)
	result = strings.ReplaceAll(result, "$pkgname", pkgnameValue)

	// Remove srcdir references (just remove the variable, keep the path)
	result = regexp.MustCompile(`\$\{srcdir\}/`).ReplaceAllString(result, "")
	result = regexp.MustCompile(`\$srcdir/`).ReplaceAllString(result, "")
	result = strings.ReplaceAll(result, "${srcdir}", ".")
	result = strings.ReplaceAll(result, "$srcdir", ".")

	return dedentShellBody(result)
}

func stripPKGBUILDFunctionMetadata(body string) string {
	metadata := `(?:pkgdesc|arch|url|license|groups|depends|optdepends|provides|conflicts|replaces|backup|options|install|changelog)`
	arrayAssignment := regexp.MustCompile(`(?ms)^[ \t]*` + metadata + `\+?=\(.*?\)[ \t]*(?:\n|$)`)
	body = arrayAssignment.ReplaceAllString(body, "")
	scalarAssignment := regexp.MustCompile(`(?m)^[ \t]*` + metadata + `\+?=[^\n]*(?:\n|$)`)
	return scalarAssignment.ReplaceAllString(body, "")
}
