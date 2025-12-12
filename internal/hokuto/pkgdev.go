package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func newPackage(pkgName string) error {
	if newPackageDir == "" {
		return fmt.Errorf("newPackageDir is not set")
	}

	pkgDir := filepath.Join(newPackageDir, pkgName)

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
		// Instead of creating, just return an error
		return fmt.Errorf("package %s not found in any repo path", pkgName)
	}

	// --- Files to open
	var relFiles []string
	if openAll {
		relFiles = []string{"version", "sources", "build", "depends"}
	} else {
		relFiles = []string{"version", "sources"}
	}

	var filesToOpen []string
	for _, f := range relFiles {
		full := filepath.Join(pkgDirEd, f)
		// Ensure file exists
		if _, err := os.Stat(full); os.IsNotExist(err) {
			if err := os.WriteFile(full, nil, 0o644); err != nil {
				return fmt.Errorf("failed to create %s: %v", full, err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to stat %s: %v", full, err)
		}
		filesToOpen = append(filesToOpen, full)
	}

	// Launch editor with all files
	cmd := exec.Command(editor, filesToOpen...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// newHttpClient creates and returns an http.Client.
