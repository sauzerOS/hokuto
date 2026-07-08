package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func handleCleanupCommand(args []string, cfg *Config) error {
	cleanupCmd := flag.NewFlagSet("cleanup", flag.ExitOnError)
	cleanSources := cleanupCmd.Bool("sources", false, "Remove all cached source files.")
	cleanBins := cleanupCmd.Bool("bins", false, "Remove all built binary packages.")
	cleanOrphans := cleanupCmd.Bool("orphans", false, "Check and remove orphaned packages.")
	cleanKernels := cleanupCmd.Bool("kernel", false, "Prompt to remove old kernels and related out-of-tree modules.")
	cleanTmp := cleanupCmd.Bool("tmp", false, "Remove temporary build directories.")
	cleanAll := cleanupCmd.Bool("all", false, "sources, binaries, orphans and temporary build dirs.")
	packageNumbers := cleanupCmd.String("number", "", "Pre-select packages by number (e.g. 1,2 or -3)")

	if err := cleanupCmd.Parse(args); err != nil {
		return err // Should not happen with flag.ExitOnError
	}

	// If no flags are provided, show help and exit
	if !*cleanSources && !*cleanBins && !*cleanAll && !*cleanOrphans && !*cleanKernels && !*cleanTmp {
		fmt.Println("Usage: hokuto cleanup [flag]")
		fmt.Println("You must specify what to clean up. Use one of the following flags:")
		cleanupCmd.PrintDefaults()
		return nil
	}

	// If -all is used, it implies both sources, bins, orphans, and tmp
	if *cleanAll {
		*cleanSources = true
		*cleanBins = true
		*cleanOrphans = true
		*cleanTmp = true
	}

	if *cleanSources {
		colArrow.Print("-> ")
		cPrintf(colWarn, "Deleting sources cache at %s.\n", SourcesDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing source cache directory: %s\n", SourcesDir)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(SourcesDir); err != nil {
					return fmt.Errorf("failed to remove source cache natively: %w", err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", SourcesDir)
				if err := RootExec.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove source cache: %w", err)
				}
			}
			colArrow.Print("-> ")
			colSuccess.Println("Source cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of source cache canceled.")
		}
	}

	if *cleanBins {
		cPrintf(colWarn, "This will permanently delete all built binary packages at %s.\n", BinDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing binary cache directory: %s\n", BinDir)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(BinDir); err != nil {
					return fmt.Errorf("failed to remove binary cache natively: %w", err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", BinDir)
				if err := RootExec.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove binary cache: %w", err)
				}
			}
			colArrow.Print("-> ")
			colSuccess.Println("Binary cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of binary cache canceled.")
		}
	}

	if *cleanOrphans {
		handleOrphanCleanup(cfg, *packageNumbers)
	}

	if *cleanKernels {
		if err := handleKernelCleanup(cfg); err != nil {
			return err
		}
	}

	if *cleanTmp {
		// Get HOKUTO_ROOT if set
		hokutoRoot := os.Getenv("HOKUTO_ROOT")

		tmpDir1 := cfg.Values["TMPDIR"]
		if tmpDir1 == "" {
			tmpDir1 = "/tmp"
		}
		if hokutoRoot != "" {
			tmpDir1 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir1, "/"))
		}

		tmpDir2 := cfg.Values["TMPDIR2"]
		if tmpDir2 == "" {
			tmpDir2 = "/var/tmpdir"
		}
		if hokutoRoot != "" {
			tmpDir2 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir2, "/"))
		}

		var allPaths []string

		if entries, err := os.ReadDir(tmpDir1); err == nil {
			for _, entry := range entries {
				allPaths = append(allPaths, filepath.Join(tmpDir1, entry.Name()))
			}
		}

		if entries, err := os.ReadDir(tmpDir2); err == nil {
			for _, entry := range entries {
				allPaths = append(allPaths, filepath.Join(tmpDir2, entry.Name()))
			}
		}

		if len(allPaths) == 0 {
			colArrow.Print("-> ")
			colSuccess.Println("No temporary build directories or files found to clean.")
		} else {
			colArrow.Print("-> ")
			cPrintf(colWarn, "Found %d items in temporary build directories to delete:\n", len(allPaths))
			for _, path := range allPaths {
				cPrintf(colInfo, "  - %s\n", path)
			}

			if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
				for _, path := range allPaths {
					debugf("Removing temporary build item: %s\n", path)
					if os.Geteuid() == 0 {
						if err := os.RemoveAll(path); err != nil {
							cPrintf(colWarn, "Warning: failed to remove %s natively: %v\n", path, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-rf", path)
						if err := RootExec.Run(rmCmd); err != nil {
							cPrintf(colWarn, "Warning: failed to remove %s: %v\n", path, err)
						}
					}
				}
				colArrow.Print("-> ")
				colSuccess.Println("Temporary build directories cleaned successfully.")
			} else {
				colArrow.Print("-> ")
				colSuccess.Println("Cleanup of temporary build directories canceled.")
			}
		}
	}

	return nil
}

type kernelCleanupCandidate struct {
	Release  string
	Packages []string
	Paths    []string
}

func handleKernelCleanup(cfg *Config) error {
	candidates, err := findKernelCleanupCandidates(cfg)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No removable old kernels found.")
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	for i, cand := range candidates {
		colArrow.Print("-> ")
		colWarn.Printf("%d. Remove kernel %s", i+1, cand.Release)
		if len(cand.Packages) > 0 {
			colWarn.Printf(", %s", strings.Join(cand.Packages, ", "))
		}
		colWarn.Print(" [y/N]: ")
		answer, _ := reader.ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			continue
		}

		for _, pkg := range cand.Packages {
			if err := pkgUninstall(pkg, cfg, RootExec, true, true, nil); err != nil {
				colWarn.Printf("Warning: failed to uninstall %s: %v\n", pkg, err)
			} else {
				removeFromWorld(pkg)
				removeFromWorldMake(pkg)
			}
		}
		if err := removeKernelLeftovers(cfg, cand); err != nil {
			colWarn.Printf("Warning: failed to remove leftovers for %s: %v\n", cand.Release, err)
		}
	}
	return nil
}

func findKernelCleanupCandidates(cfg *Config) ([]kernelCleanupCandidate, error) {
	hRoot := cfg.Values["HOKUTO_ROOT"]
	if hRoot == "" {
		hRoot = "/"
	}

	releases := installedKernelReleases(hRoot)
	if len(releases) <= 1 {
		return nil, nil
	}
	current := newestKernelRelease(releases)
	owners := packagesByKernelRelease(hRoot, releases)

	var candidates []kernelCleanupCandidate
	for _, release := range releases {
		if release == current {
			continue
		}
		pkgs := owners[release]
		sort.Strings(pkgs)
		candidates = append(candidates, kernelCleanupCandidate{
			Release:  release,
			Packages: pkgs,
			Paths:    kernelReleasePaths(hRoot, release),
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Release < candidates[j].Release
	})
	return candidates, nil
}

func installedKernelReleases(hRoot string) []string {
	seen := make(map[string]bool)
	var releases []string
	for _, base := range []string{"usr/lib/modules", "lib/modules"} {
		dir := filepath.Join(hRoot, base)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isSauzerosKernelRelease(name) || seen[name] {
				continue
			}
			seen[name] = true
			releases = append(releases, name)
		}
	}
	sort.Strings(releases)
	return releases
}

func isSauzerosKernelRelease(name string) bool {
	return strings.HasSuffix(name, "-sauzerOS") || strings.HasSuffix(name, "-sauzerOS_C")
}

func newestKernelRelease(releases []string) string {
	if len(releases) == 0 {
		return ""
	}
	sorted := append([]string(nil), releases...)
	sort.Slice(sorted, func(i, j int) bool {
		return compareVersions(sorted[i], sorted[j]) < 0
	})
	return sorted[len(sorted)-1]
}

func packagesByKernelRelease(hRoot string, releases []string) map[string][]string {
	result := make(map[string][]string)
	releaseSet := make(map[string]bool)
	for _, release := range releases {
		releaseSet[release] = true
	}

	dbRoot := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(dbRoot)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pkg := entry.Name()
		manifestPath := filepath.Join(dbRoot, pkg, "manifest")
		data, err := readFileAsRoot(manifestPath)
		if err != nil {
			continue
		}
		matches := make(map[string]bool)
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			path := manifestPathFromLine(sc.Text())
			for release := range releaseSet {
				if pathMentionsKernelRelease(path, release) {
					matches[release] = true
				}
			}
		}
		for release := range matches {
			result[release] = append(result[release], pkg)
		}
	}
	return result
}

func manifestPathFromLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if strings.HasSuffix(line, "/") {
		return strings.Trim(line, "/")
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	if len(fields) == 1 {
		return strings.Trim(fields[0], "/")
	}
	return strings.Trim(strings.Join(fields[:len(fields)-1], " "), "/")
}

func pathMentionsKernelRelease(path, release string) bool {
	return strings.Contains(path, "lib/modules/"+release+"/") ||
		strings.Contains(path, "boot/vmlinuz-"+release) ||
		strings.Contains(path, "boot/initramfs-"+release) ||
		strings.Contains(path, "boot/System.map-"+release) ||
		strings.Contains(path, "boot/config-"+release)
}

func kernelReleasePaths(hRoot, release string) []string {
	relPaths := []string{
		filepath.Join("usr/lib/modules", release),
		filepath.Join("lib/modules", release),
		filepath.Join("boot", "vmlinuz-"+release),
		filepath.Join("boot", "initramfs-"+release+".img"),
		filepath.Join("boot", "initramfs-"+release+"-fallback.img"),
		filepath.Join("boot", "System.map-"+release),
		filepath.Join("boot", "config-"+release),
		filepath.Join("boot", "loader", "entries", "sauzeros-"+release+".conf"),
	}
	paths := make([]string, 0, len(relPaths))
	for _, rel := range relPaths {
		paths = append(paths, filepath.Join(hRoot, rel))
	}
	return paths
}

func removeKernelLeftovers(cfg *Config, cand kernelCleanupCandidate) error {
	for _, path := range cand.Paths {
		if err := removeKernelPath(path); err != nil {
			return err
		}
	}
	if err := removeKernelBootloaderEntries(cfg, cand.Release); err != nil {
		return err
	}
	return nil
}

func removeKernelPath(path string) error {
	clean := filepath.Clean(path)
	if clean == "/" {
		return fmt.Errorf("refusing to remove root")
	}
	if os.Geteuid() == 0 {
		return os.RemoveAll(clean)
	}
	cmd := exec.Command("rm", "-rf", clean)
	return RootExec.Run(cmd)
}

func removeKernelBootloaderEntries(cfg *Config, release string) error {
	hRoot := cfg.Values["HOKUTO_ROOT"]
	if hRoot == "" {
		hRoot = "/"
	}
	if err := removeMarkedBlock(filepath.Join(hRoot, "boot", "limine.conf"), release); err != nil {
		return err
	}
	if err := removeMarkedBlock(filepath.Join(hRoot, "boot", "EFI", "BOOT", "limine.conf"), release); err != nil {
		return err
	}
	if err := removeMarkedBlock(filepath.Join(hRoot, "boot", "refind_linux.conf"), release); err != nil {
		return err
	}
	entriesDir := filepath.Join(hRoot, "boot", "loader", "entries")
	if err := filepath.WalkDir(entriesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), release) {
			return removeKernelPath(path)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeMarkedBlock(path, release string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	start := "# hokuto kernel " + release + " begin"
	end := "# hokuto kernel " + release + " end"
	lines := strings.Split(string(data), "\n")
	var out []string
	skipping := false
	changed := false
	for _, line := range lines {
		switch strings.TrimSpace(line) {
		case start:
			skipping = true
			changed = true
			continue
		case end:
			skipping = false
			continue
		}
		if !skipping {
			out = append(out, line)
		}
	}
	if !changed {
		return nil
	}
	newData := []byte(strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n")
	if os.Geteuid() == 0 {
		return os.WriteFile(path, newData, 0644)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hokuto-kernel-cleanup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(newData); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	mvCmd := exec.Command("mv", tmpPath, path)
	return RootExec.Run(mvCmd)
}
