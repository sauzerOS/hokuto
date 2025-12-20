package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/gookit/color"
)

func addToWorld(pkgName string) error {
	// 1. Read existing world
	content, err := os.ReadFile(WorldFile)
	// It's okay if file doesn't exist yet
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == pkgName {
			return nil // Already in world
		}
	}

	// 2. Append new package
	f, err := os.OpenFile(WorldFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Try with root if permission denied
		if os.IsPermission(err) {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> %s", pkgName, WorldFile))
			return RootExec.Run(cmd)
		}
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(pkgName + "\n"); err != nil {
		return err
	}
	return nil
}

// removeFromWorld removes a package from the world file.

func removeFromWorld(pkgName string) error {
	content, err := os.ReadFile(WorldFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	changed := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == pkgName {
			changed = true
			continue
		}
		if trimmed != "" {
			newLines = append(newLines, trimmed)
		}
	}

	if !changed {
		return nil
	}

	// Write back
	newContent := strings.Join(newLines, "\n") + "\n"

	// Attempt direct write
	if err := os.WriteFile(WorldFile, []byte(newContent), 0644); err != nil {
		// Fallback to root write
		if os.IsPermission(err) {
			tmpFile, _ := os.CreateTemp("", "world-tmp")
			tmpFile.WriteString(newContent)
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())

			cmd := exec.Command("cp", tmpFile.Name(), WorldFile)
			return RootExec.Run(cmd)
		}
		return err
	}
	return nil
}

// addToWorldMake adds a package to the world_make file.

func addToWorldMake(pkgName string) error {
	// 1. Check if already in world_make
	content, err := os.ReadFile(WorldMakeFile)
	if err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == pkgName {
				return nil
			}
		}
	}

	// 2. Append
	f, err := os.OpenFile(WorldMakeFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsPermission(err) {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> %s", pkgName, WorldMakeFile))
			return RootExec.Run(cmd)
		}
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(pkgName + "\n"); err != nil {
		return err
	}
	return nil
}

// removeFromWorldMake removes a package from the world_make file.

func removeFromWorldMake(pkgName string) error {
	content, err := os.ReadFile(WorldMakeFile)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	changed := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == pkgName {
			changed = true
			continue
		}
		if trimmed != "" {
			newLines = append(newLines, trimmed)
		}
	}

	if !changed {
		return nil
	}

	newContent := strings.Join(newLines, "\n") + "\n"

	if err := os.WriteFile(WorldMakeFile, []byte(newContent), 0644); err != nil {
		if os.IsPermission(err) {
			tmpFile, _ := os.CreateTemp("", "worldmake-tmp")
			tmpFile.WriteString(newContent)
			tmpFile.Close()
			defer os.Remove(tmpFile.Name())
			cmd := exec.Command("cp", tmpFile.Name(), WorldMakeFile)
			return RootExec.Run(cmd)
		}
		return err
	}
	return nil
}

// findMakeOrphans identifies build-only dependencies that are no longer needed.

func findMakeOrphans() ([]string, error) {
	// 1. Read World Make (Candidates)
	makeData, err := os.ReadFile(WorldMakeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	candidates := make(map[string]bool)
	for _, line := range strings.Split(string(makeData), "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			candidates[t] = true
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// 2. Read World (Explicitly wanted packages)
	worldData, _ := os.ReadFile(WorldFile)
	for _, line := range strings.Split(string(worldData), "\n") {
		t := strings.TrimSpace(line)
		// If user explicitly installed it later, remove from candidates
		if candidates[t] {
			delete(candidates, t)
		}
	}

	// 3. Build set of ALL current runtime requirements
	// Scan every installed package, read its depends, add to required set.
	requiredRuntime := make(map[string]bool)

	entries, err := os.ReadDir(Installed)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			pkg := e.Name()

			// Get runtime deps (this excludes 'make' deps automatically via parseDepends logic)
			deps, err := getInstalledDeps(pkg)
			if err != nil {
				continue
			}

			for _, dep := range deps {
				requiredRuntime[dep] = true
			}
		}
	}

	// 4. Filter Candidates
	var orphans []string
	for pkg := range candidates {
		// If it's not required for runtime, and it's installed, it's a make orphan
		if !requiredRuntime[pkg] && checkPackageExactMatch(pkg) {
			orphans = append(orphans, pkg)
		}
	}

	return orphans, nil
}

// getInstalledDeps returns the list of dependencies for an *installed* package
// by reading the /var/db/hokuto/installed/<pkg>/depends file.

func findOrphans() ([]string, error) {
	// 1. Read World File
	worldData, err := os.ReadFile(WorldFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	worldPkgs := make(map[string]bool)
	for _, line := range strings.Split(string(worldData), "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			worldPkgs[t] = true
		}
	}

	// 2. Build the "Keep" set (World + all recursive dependencies)
	keepSet := make(map[string]bool)
	queue := []string{}

	// Initialize with World packages that are actually installed
	for pkg := range worldPkgs {
		if checkPackageExactMatch(pkg) {
			keepSet[pkg] = true
			queue = append(queue, pkg)
		}
	}

	// BFS traversal
	head := 0
	for head < len(queue) {
		curr := queue[head]
		head++

		deps, err := getInstalledDeps(curr)
		if err != nil {
			continue
		}

		for _, dep := range deps {
			// If dependency is installed and not yet kept
			if !keepSet[dep] && checkPackageExactMatch(dep) {
				keepSet[dep] = true
				queue = append(queue, dep)
			}
		}
	}

	// 3. Find Orphans (All Installed - Keep Set)
	var orphans []string
	entries, err := os.ReadDir(Installed)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg := e.Name()
		if !keepSet[pkg] {
			orphans = append(orphans, pkg)
		}
	}

	return orphans, nil
}

// handleOrphanCleanup finds orphans and prompts the user to remove them individually.

func handleOrphanCleanup(cfg *Config) {
	// --- STAGE 1: Normal Orphans (Runtime) ---
	colArrow.Print("-> ")
	colSuccess.Println("Checking for runtime orphan packages")

	orphans, err := findOrphans()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to calculate orphans: %v\n", err)
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		colArrow.Print("-> ")
		colWarn.Printf("Found %d runtime orphan package(s).\n", len(orphans))

		for _, pkg := range orphans {
			if askForConfirmation(colWarn, "Remove runtime orphan %s?", pkg) {
				colArrow.Print("-> ")
				colSuccess.Printf("Removing: ")
				colNote.Printf("%s\n", pkg)
				if err := pkgUninstall(pkg, cfg, RootExec, true, true); err != nil {
					color.Danger.Printf("Failed to remove %s: %v\n", pkg, err)
				} else {
					removeFromWorld(pkg)
					removeFromWorldMake(pkg) // Remove from make world too if present
				}
			} else {
				cPrintf(colInfo, "Skipped %s\n", pkg)
			}
		}
	} else {
		colArrow.Print("-> ")
		colSuccess.Println("No runtime orphans found.")
	}

	// --- STAGE 2: Make Orphans (Build Dependencies) ---
	colArrow.Print("\n-> ")
	colSuccess.Println("Checking for unneeded build dependencies")

	makeOrphans, err := findMakeOrphans()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to calculate make orphans: %v\n", err)
		return
	}

	if len(makeOrphans) > 0 {
		sort.Strings(makeOrphans)
		colArrow.Print("-> ")
		colWarn.Printf("Found %d unneeded build dependency package(s).\n", len(makeOrphans))

		for _, pkg := range makeOrphans {
			if askForConfirmation(colWarn, "Remove build dependency %s?", pkg) {
				colArrow.Print("-> ")
				colSuccess.Printf("Removing: ")
				colNote.Printf("%s\n", pkg)
				if err := pkgUninstall(pkg, cfg, RootExec, true, true); err != nil {
					color.Danger.Printf("Failed to remove %s: %v\n", pkg, err)
				} else {
					removeFromWorldMake(pkg)
					// Also try to remove from world just in case of state desync
					removeFromWorld(pkg)
				}
			} else {
				cPrintf(colInfo, "Skipped %s\n", pkg)
			}
		}
	} else {
		colArrow.Print("-> ")
		colSuccess.Println("No unneeded build dependencies found.")
	}
}
