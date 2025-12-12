package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gookit/color"
)

func pkgUninstall(pkgName string, cfg *Config, execCtx *Executor, force, yes bool) error {
	// Resolve HOKUTO_ROOT (fall back to "/")
	hRoot := cfg.Values["HOKUTO_ROOT"]
	if hRoot == "" {
		hRoot = "/"
	}

	installedDir := filepath.Join(hRoot, "var", "db", "hokuto", "installed", pkgName)
	manifestPath := filepath.Join(installedDir, "manifest")

	// Path prefix for internal metadata files that should skip the b3sum check.
	internalFilePrefix := filepath.Join(hRoot, "var", "db", "hokuto", "installed")

	// 1. Verify package exists
	if _, err := os.Stat(installedDir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("package %s is not installed", pkgName)
		}
		return fmt.Errorf("failed to stat package metadata: %v", err)
	}

	// 2. Read manifest as root
	manifestBytes, err := readFileAsRoot(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest for %s: %v", pkgName, err)
	}

	// 3. Build list of files and directories from manifest.
	var files []fileMetadata // CHANGED: Use new struct to store B3Sum
	var dirs []string
	var fileCount int // Track only installable files for confirmation message

	sc := bufio.NewScanner(strings.NewReader(string(manifestBytes)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// Use strings.Fields for robust parsing ---
		pathInManifest := ""
		expectedSum := ""

		if strings.HasSuffix(line, "/") {
			// This is a directory entry
			pathInManifest = line
		} else {
			// Use strings.Fields() to robustly handle any amount of whitespace
			fields := strings.Fields(line)
			if len(fields) > 0 {
				pathInManifest = fields[0]
			}
			if len(fields) > 1 {
				expectedSum = fields[1]
			}
		}

		// If after parsing, path is empty, it was a malformed line.
		if pathInManifest == "" {
			continue
		}

		// Absolute path on disk
		var absPath string
		if filepath.IsAbs(pathInManifest) {
			if hRoot != "/" {
				absPath = filepath.Join(hRoot, pathInManifest[1:])
			} else {
				absPath = pathInManifest
			}
		} else {
			absPath = filepath.Join(hRoot, pathInManifest)
		}

		if strings.HasSuffix(pathInManifest, "/") {
			dirs = append(dirs, absPath)
			continue
		}

		fileCount++
		files = append(files, fileMetadata{AbsPath: absPath, B3Sum: expectedSum})
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("error parsing manifest: %v", err)
	}

	// 4. Check reverse dependencies (unchanged)
	// ... (Original Step 4 code) ...
	dependents := []string{}
	dbRoot := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(dbRoot)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			other := e.Name()
			if other == pkgName {
				continue
			}
			depFile := filepath.Join(dbRoot, other, "depends")
			b, err := readFileAsRoot(depFile)
			if err != nil {
				continue
			}
			lines := strings.Split(string(b), "\n")
			for _, L := range lines {
				L = strings.TrimSpace(L)
				if L == "" {
					continue
				}
				parts := strings.Fields(L)
				if len(parts) == 0 {
					continue
				}
				if parts[0] == pkgName {
					dependents = append(dependents, other)
					break
				}
			}
		}
	}
	if len(dependents) > 0 && !force {
		return fmt.Errorf("cannot uninstall %s: other packages depend on it: %s", pkgName, strings.Join(dependents, ", "))
	}

	// 5. Confirm with user unless 'yes' is set
	if !yes {
		colArrow.Print("-> ")
		color.Danger.Printf("About to remove package %s and %d file(s). Continue? [Y/n]: ", pkgName, fileCount)
		var answer string
		fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "" && answer != "y" {
			return fmt.Errorf("aborted by user")
		}
	}

	// 6. Run pre-uninstall if present (unchanged)
	preScript := filepath.Join(installedDir, "pre-uninstall")
	if fi, err := os.Stat(preScript); err == nil && !fi.IsDir() {
		cmd := exec.Command(preScript)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := execCtx.Run(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: pre-uninstall script failed: %v\n", err)
		}
	}

	// 7. Remove files (with optional b3sum check)
	var failed []string
	var filesToRemove []string
	var filesToCheck []fileMetadata

	// Separate files that need checksum verification from those that don't
	for _, meta := range files {
		p := meta.AbsPath // The full HOKUTO_ROOT prefixed path

		// Safety check: don't remove root
		clean := filepath.Clean(p)
		if clean == "/" || clean == hRoot {
			failed = append(failed, fmt.Sprintf("%s: refused to remove root", p))
			continue
		}

		// Always check b3sums for files in /etc (critical system files)
		// Skip checksum verification if force=true or if it's internal metadata, but not for /etc files
		isEtcFile := strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, filepath.Join(hRoot, "etc/"))

		if (force || strings.HasPrefix(p, internalFilePrefix) || meta.B3Sum == "") && !isEtcFile {
			filesToRemove = append(filesToRemove, clean)
		} else {
			filesToCheck = append(filesToCheck, meta)
		}
	}

	// Check files that need verification
	for _, meta := range filesToCheck {
		p := meta.AbsPath
		clean := filepath.Clean(p)

		currentSum, err := b3sum(p, execCtx)
		if err != nil {
			// Treat inability to check as a failure to remove for safety
			failed = append(failed, fmt.Sprintf("%s: failed to compute b3sum: %v", p, err))
			continue
		}

		// Skip modification warning for files with 000000 checksum
		if currentSum != meta.B3Sum && meta.B3Sum != "000000" {
			cPrintf(colWarn, "\nWARNING: File %s has been modified (expected %s, found %s).\n", p, meta.B3Sum, currentSum)

			// Prompt user unless 'yes' is set
			if !yes {
				fmt.Printf("File content mismatch. Remove anyway? [Y/n]: ")
				var answer string
				fmt.Scanln(&answer)
				answer = strings.ToLower(strings.TrimSpace(answer))
				if answer == "" {
					answer = "y" // default to Yes if user just presses Enter
				}
				if answer != "y" {
					failed = append(failed, fmt.Sprintf("%s: content mismatch, removal skipped by user", p))
					continue // Skip removal
				}
			}
		}

		filesToRemove = append(filesToRemove, clean)
	}

	// Batch remove all files at once
	if len(filesToRemove) > 0 {
		// Use rm with multiple files for better performance
		rmCmd := exec.Command("rm", "-f")
		rmCmd.Args = append(rmCmd.Args, filesToRemove...)

		if err := execCtx.Run(rmCmd); err != nil {
			// If batch removal fails, try individual removals
			colArrow.Print("-> ")
			colSuccess.Println("Batch removal failed, trying individual removals")
			for _, file := range filesToRemove {
				rmCmd := exec.Command("rm", "-f", file)
				if err := execCtx.Run(rmCmd); err != nil {
					failed = append(failed, fmt.Sprintf("%s: %v", file, err))
				} else {
					debugf("Removed %s\n", file)
				}
			}
		} else {
			colArrow.Print("-> ")
			colSuccess.Printf("Removed %d files\n", len(filesToRemove))
		}
	}

	// 8. Try to rmdir directories recorded in manifest, deepest first (unchanged)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		clean := filepath.Clean(d)

		// Safety check 1: Don't attempt to rmdir outside HOKUTO_ROOT.
		if !strings.HasPrefix(clean, filepath.Clean(hRoot)) {
			continue
		}

		// Safety check 2: Check against forbidden system directories.
		relToHRoot := strings.TrimPrefix(clean, filepath.Clean(hRoot))
		if relToHRoot == "" {
			relToHRoot = "/"
		}

		if !strings.HasPrefix(relToHRoot, "/") {
			relToHRoot = "/" + relToHRoot
		}

		isForbidden := false

		// A. Check 1: Forbidden Recursive Directories (Prefix Check)
		for forbiddenPath := range forbiddenSystemDirsRecursive {
			// Trim the trailing slash for comparison, unless the path itself is "/"
			recursiveRoot := forbiddenPath

			// The path is forbidden if it's an exact match OR starts with the forbidden path + '/'
			if relToHRoot == recursiveRoot {
				isForbidden = true
				break
			}

			if strings.HasPrefix(relToHRoot, recursiveRoot+"/") {
				isForbidden = true
				break
			}
		}

		// B. Check 2: Forbidden Exact Directories (Map Lookup)
		if !isForbidden {
			if _, found := forbiddenSystemDirs[relToHRoot]; found {
				isForbidden = true
			}
		}

		if isForbidden {
			debugf("Skipping removal of protected system directory: %s\n", clean)
			continue
		}

		rmdirCmd := exec.Command("rmdir", clean)
		rmdirCmd.Stderr = io.Discard // Silence stderr to avoid "Directory not empty" warnings
		if err := execCtx.Run(rmdirCmd); err == nil {
			debugf("Removed empty directory %s\n", clean)
		}
	}

	// 9. Remove package metadata directory (unchanged)
	rmMetaCmd := exec.Command("rm", "-rf", installedDir)
	if err := execCtx.Run(rmMetaCmd); err != nil {
		failed = append(failed, fmt.Sprintf("failed to remove metadata %s: %v", installedDir, err))
	} else {
		debugf("Removed package metadata: %s\n", installedDir)
	}

	// 10. Run post-uninstall hook if present (unchanged)
	postScript := filepath.Join(installedDir, "post-uninstall")
	if fi, err := os.Stat(postScript); err == nil && !fi.IsDir() {
		cmd := exec.Command(postScript)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := execCtx.Run(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "warning: post-uninstall script failed: %v\n", err)
		}
	}

	// 11. Report failures if any (unchanged)
	if len(failed) > 0 {
		return fmt.Errorf("some removals failed:\n%s", strings.Join(failed, "\n"))
	}
	return nil
}

// handleBuildCommand orchestrates the entire build process, intelligently selecting the
// correct dependency resolution strategy based on the build mode (normal, bootstrap, or alldeps).
