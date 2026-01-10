package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func applySubstitutions(content, version, pkgName string) string {
	sepFunc := func(r rune) bool {
		return r == '.' || r == '_' || r == '-'
	}
	parts := strings.FieldsFunc(version, sepFunc)

	major := ""
	majorMinor := ""
	if len(parts) > 0 {
		major = parts[0]
		majorMinor = parts[0]
		if len(parts) > 1 {
			majorMinor = parts[0] + "." + parts[1]
		}
	}

	// SQLite version format: Mmmppee (Major, Minor, Patch, Extra)
	// Example: 3.51.1 -> 3510100
	sqliteVer := ""
	if len(parts) > 0 {
		var v [4]int
		for i := 0; i < len(parts) && i < 4; i++ {
			fmt.Sscanf(parts[i], "%d", &v[i])
		}
		sqliteVer = fmt.Sprintf("%d%02d%02d%02d", v[0], v[1], v[2], v[3])
	}

	r := strings.NewReplacer(
		"${version}", version,
		"${version-clean}", strings.ReplaceAll(version, "_", "."),
		"${version_}", strings.ReplaceAll(version, ".", "_"),
		"${version-}", strings.ReplaceAll(version, ".", "-"),
		"${version-major}", major,
		"${version-major-minor}", majorMinor,
		"${version-sqlite}", sqliteVer,
		"${pkgname}", pkgName,
	)
	return r.Replace(content)
}

func runEditor(editor string, files ...string) error {
	if len(files) == 0 {
		return nil
	}
	cmd := exec.Command(editor, files...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func newPackage(pkgName string, targetDir string) error {
	var pkgDir string
	if targetDir != "" {
		// Use provided target directory (current working directory when -here is used)
		pkgDir = filepath.Join(targetDir, pkgName)
	} else {
		// Use default newPackageDir
		if newPackageDir == "" {
			return fmt.Errorf("newPackageDir is not set")
		}
		pkgDir = filepath.Join(newPackageDir, pkgName)
	}

	// Don't overwrite existing package dir
	if fi, err := os.Stat(pkgDir); err == nil {
		if fi.IsDir() {
			return fmt.Errorf("package %s already exists at %s", pkgName, pkgDir)
		}
		return fmt.Errorf("path %s exists and is not a directory", pkgDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat path %s: %w", pkgDir, err)
	}

	// Create package dir
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return fmt.Errorf("failed to create package directory %s: %w", pkgDir, err)
	}

	// 1) build file: mode 0755, content "#!/bin/sh -e\n"
	buildPath := filepath.Join(pkgDir, "build")
	buildContent := []byte("#!/bin/sh -e\n")
	if err := os.WriteFile(buildPath, buildContent, 0o755); err != nil {
		return fmt.Errorf("failed to create build file: %w", err)
	}

	// 2) version file: mode 0644, content " 1\n"
	versionPath := filepath.Join(pkgDir, "version")
	versionContent := []byte(" 1\n")
	if err := os.WriteFile(versionPath, versionContent, 0o644); err != nil {
		return fmt.Errorf("failed to create version file: %w", err)
	}

	// 3) sources file: mode 0644, empty
	sourcesPath := filepath.Join(pkgDir, "sources")
	if err := os.WriteFile(sourcesPath, []byte(""), 0o644); err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}

	// 4) .sources file: mode 0644, empty
	dotsourcesPath := filepath.Join(pkgDir, ".sources")
	if err := os.WriteFile(dotsourcesPath, []byte(""), 0o644); err != nil {
		return fmt.Errorf("failed to create sources file: %w", err)
	}

	// Success messages
	cPrintln(colInfo, "=> Creating build file.")
	cPrintln(colInfo, "=> Creating version file with ' 1'.")
	cPrintln(colInfo, "=> Creating sources file with ''.")
	cPrintf(colInfo, "=> Package %s created in %s.\n", pkgName, pkgDir)

	return nil
}

// editPackage searches for pkgName under the colon-separated repoPaths
// and opens version, sources, build, depends in the user's editor.

func editPackage(pkgName string, openAll bool) error {
	// Determine editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "nano"
	}

	// repoPaths is expected to be a colon-separated string of base paths,
	// for example "/repo/sauzeros/core:/repo/sauzeros/extra".
	paths := filepath.SplitList(repoPaths)
	if len(paths) == 0 {
		return fmt.Errorf("no repo paths configured")
	}

	// Find the first directory that contains the package dir
	var pkgDirEd string
	for _, base := range paths {
		candidate := filepath.Join(base, pkgName)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			pkgDirEd = candidate
			break
		}
	}

	if pkgDirEd == "" {
		return fmt.Errorf("package %s not found in any repo path", pkgName)
	}

	versionPath := filepath.Join(pkgDirEd, "version")
	sourcesPath := filepath.Join(pkgDirEd, "sources")
	dotSourcesPath := filepath.Join(pkgDirEd, ".sources")

	// 1. Open version file in editor (current behaviour)
	if _, err := os.Stat(versionPath); os.IsNotExist(err) {
		if err := os.WriteFile(versionPath, nil, 0o644); err != nil {
			return fmt.Errorf("failed to create %s: %v", versionPath, err)
		}
	}
	if err := runEditor(editor, versionPath); err != nil {
		return fmt.Errorf("editor failed for version file: %v", err)
	}

	// 2. Open .sources in editor
	if _, err := os.Stat(dotSourcesPath); os.IsNotExist(err) {
		// If .sources doesn't exist yet, try to create it by copying from sources
		if _, err := os.Stat(sourcesPath); err == nil {
			sourcesData, err := os.ReadFile(sourcesPath)
			if err == nil {
				if err := os.WriteFile(dotSourcesPath, sourcesData, 0o644); err != nil {
					return fmt.Errorf("failed to copy sources to %s: %v", dotSourcesPath, err)
				}
			}
		} else {
			// If sources also doesn't exist, create an empty .sources
			if err := os.WriteFile(dotSourcesPath, nil, 0o644); err != nil {
				return fmt.Errorf("failed to create %s: %v", dotSourcesPath, err)
			}
		}
	}
	if err := runEditor(editor, dotSourcesPath); err != nil {
		return fmt.Errorf("editor failed for .sources file: %v", err)
	}

	// 3. Read .sources and update sources if it exists
	if _, err := os.Stat(dotSourcesPath); err == nil {
		versionData, err := os.ReadFile(versionPath)
		if err != nil {
			return fmt.Errorf("failed to read version file: %v", err)
		}
		versionFields := strings.Fields(string(versionData))
		if len(versionFields) == 0 {
			return fmt.Errorf("version file is empty")
		}
		version := versionFields[0]

		dotSourcesData, err := os.ReadFile(dotSourcesPath)
		if err != nil {
			return fmt.Errorf("failed to read .sources file: %v", err)
		}

		updatedSources := applySubstitutions(string(dotSourcesData), version, pkgName)
		if err := os.WriteFile(sourcesPath, []byte(updatedSources), 0o644); err != nil {
			return fmt.Errorf("failed to write updated sources file: %v", err)
		}
	} else if _, err := os.Stat(sourcesPath); os.IsNotExist(err) {
		// Ensure sources exists even if no .sources
		if err := os.WriteFile(sourcesPath, nil, 0o644); err != nil {
			return fmt.Errorf("failed to create sources file: %v", err)
		}
	}

	// 4. Open sources file in editor for review (and others if openAll)
	var filesToOpen []string
	if openAll {
		filesToOpen = []string{sourcesPath, filepath.Join(pkgDirEd, "build"), filepath.Join(pkgDirEd, "depends")}
	} else {
		filesToOpen = []string{sourcesPath}
	}

	// Ensure files exist
	for _, f := range filesToOpen {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				return fmt.Errorf("failed to create %s: %v", f, err)
			}
		}
	}

	return runEditor(editor, filesToOpen...)
}
func handleBumpCommand(pkgsetName, oldVersion, newVersion string) error {
	sets, err := loadPkgsets()
	if err != nil {
		return fmt.Errorf("failed to load pkgsets: %v", err)
	}

	pkgs, ok := sets[pkgsetName]
	if !ok {
		return fmt.Errorf("pkgset %s not found in %s", pkgsetName, PkgsetFile)
	}

	var failed []string

	for _, pkgName := range pkgs {
		colArrow.Print("-> ")
		colSuccess.Printf("Bumping %s: %s -> %s\n", pkgName, oldVersion, newVersion)

		pkgDir, err := findPackageDir(pkgName)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: package not found", pkgName))
			continue
		}

		// 1) Verify .sources exists
		dotSourcesPath := filepath.Join(pkgDir, ".sources")
		if _, err := os.Stat(dotSourcesPath); os.IsNotExist(err) {
			failed = append(failed, fmt.Sprintf("%s: .sources file missing", pkgName))
			continue
		}

		// 2) Verify version file matches oldVersion
		versionPath := filepath.Join(pkgDir, "version")
		versionData, err := os.ReadFile(versionPath)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: could not read version file", pkgName))
			continue
		}
		fields := strings.Fields(string(versionData))
		if len(fields) == 0 {
			failed = append(failed, fmt.Sprintf("%s: version file empty", pkgName))
			continue
		}
		currentVer := fields[0]
		currentRev := "1"
		if len(fields) > 1 {
			currentRev = fields[1]
		}

		if currentVer != oldVersion {
			failed = append(failed, fmt.Sprintf("%s: wrong version (found %s, expected %s)", pkgName, currentVer, oldVersion))
			continue
		}

		// 3) Amend version to newVersion
		newVersionContent := fmt.Sprintf("%s %s\n", newVersion, currentRev)
		if err := os.WriteFile(versionPath, []byte(newVersionContent), 0o644); err != nil {
			failed = append(failed, fmt.Sprintf("%s: failed to update version file", pkgName))
			continue
		}

		// 4) Execute automatic version substitution
		dotSourcesData, err := os.ReadFile(dotSourcesPath)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: failed to read .sources", pkgName))
			continue
		}
		updatedSources := applySubstitutions(string(dotSourcesData), newVersion, pkgName)
		sourcesPath := filepath.Join(pkgDir, "sources")
		if err := os.WriteFile(sourcesPath, []byte(updatedSources), 0o644); err != nil {
			failed = append(failed, fmt.Sprintf("%s: failed to update sources file", pkgName))
			continue
		}

		// 5) Update checksums (fetchSources + verifyOrCreateChecksums)
		if err := fetchSources(pkgName, pkgDir, false); err != nil {
			failed = append(failed, fmt.Sprintf("%s: could not download sources: %v", pkgName, err))
			continue
		}
		if err := verifyOrCreateChecksums(pkgName, pkgDir, false); err != nil {
			failed = append(failed, fmt.Sprintf("%s: failed to generate checksums: %v", pkgName, err))
			continue
		}

		// 5) git add . (within pkgDir)
		gitAdd := exec.Command("git", "-C", pkgDir, "add", ".")
		if err := gitAdd.Run(); err != nil {
			failed = append(failed, fmt.Sprintf("%s: git add failed: %v", pkgName, err))
			continue
		}

		// 6) git commit (use hook for message)
		gitCommit := exec.Command("git", "-C", pkgDir, "commit", "--no-edit", ".")
		if err := gitCommit.Run(); err != nil {
			failed = append(failed, fmt.Sprintf("%s: git commit failed: %v", pkgName, err))
			continue
		}
	}

	if len(failed) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, f := range failed {
			colArrow.Print("-> ")
			colError.Printf("Failed %s\n", f)
		}
	}

	return nil
}
