package hokuto

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/gookit/color"
)

// getRepoVersion reads pkgname/version from repoPaths and returns the version string.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// We only care about the first field (the version).

func getRepoVersion(pkgName string) (string, error) {
	pkgDir, err := findPackageMetadataDir(pkgName)
	if err != nil {
		return "", fmt.Errorf("package %s not found in HOKUTO_PATH: %v", pkgName, err)
	}

	versionFile := filepath.Join(pkgDir, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", fmt.Errorf("could not read version file for %s at %s: %w", pkgName, versionFile, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("invalid version file format (empty file) for %s at %s", pkgName, versionFile)
	}
	return fields[0], nil
}

// getRepoVersion2 reads pkgname/version from repoPaths and returns the version string,
// the revision string, and an error.
// The version file format is: "<version> <revision>", e.g. "1.0 1".
// used for the update check

func getRepoVersion2(pkgName string) (version string, revision string, err error) {
	// If pkgName contains @version, strip it for the directory lookup
	// but we might want to return that version if it's what was requested.
	// Actually, getRepoVersion2 is usually for getting the CURRENT repo version.
	// If we have @version, we should probably just return that?
	// No, the caller wants to know what the current version in the repo is.
	lookupName := pkgName
	if idx := strings.Index(pkgName, "@"); idx != -1 {
		lookupName = pkgName[:idx]
	}

	pkgDir, err := findPackageMetadataDir(lookupName)
	if err != nil {
		return "", "", fmt.Errorf("package %s not found in HOKUTO_PATH: %v", lookupName, err)
	}

	versionFile := filepath.Join(pkgDir, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", "", fmt.Errorf("could not read version file for %s at %s: %w", pkgName, versionFile, err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "", "", fmt.Errorf("invalid version file format (missing version) for %s at %s", pkgName, versionFile)
	}
	pkgVersion := fields[0]
	pkgRevision := "1" // Default revision if only one field is present
	if len(fields) >= 2 {
		pkgRevision = fields[1]
	}

	return pkgVersion, pkgRevision, nil
}

func currentBinaryOutputVariants(sourcePkg, outputPkg string, cfg *Config) []string {
	variant := ""
	if outputPkg == getOutputPackageName(sourcePkg, cfg) {
		variant = GetSystemVariantForPackage(cfg, sourcePkg)
	} else {
		pkgDir, _ := findPackageMetadataDir(sourcePkg)
		options := loadBuildOptions(pkgDir)
		isGeneric := cfg.Values["HOKUTO_GENERIC"] == "1" || options["generic"]
		variant = IdentifyVariant(outputPkg, isGeneric, isMultilibPackage(outputPkg))
	}
	variants := []string{variant}
	if variant == "optimized" {
		variants = append(variants, "generic")
	} else if variant == "multi-optimized" {
		variants = append(variants, "multi-generic")
	}
	return variants
}

func currentBinaryOutputAvailable(sourcePkg, outputPkg, version, revision string, cfg *Config, remoteIndex []RepoEntry) bool {
	arch := GetSystemArchForPackage(cfg, sourcePkg)
	for _, variant := range currentBinaryOutputVariants(sourcePkg, outputPkg, cfg) {
		tarballPath := filepath.Join(BinDir, StandardizeRemoteName(outputPkg, version, revision, arch, variant))
		if _, err := os.Stat(tarballPath); err == nil {
			return true
		}
		for _, entry := range remoteIndex {
			if entry.Type != "meta" && entry.Name == outputPkg && entry.Version == version &&
				entry.Revision == revision && entry.Arch == arch && entry.Variant == variant {
				return true
			}
		}
	}
	return false
}

type repositoryBinaryStatus struct {
	Missing         []string
	PreviousVersion string
	PreviousRev     string
}

func newerBinaryRelease(version, revision, bestVersion, bestRevision string) bool {
	return bestVersion == "" || compareVersions(version, bestVersion) > 0 ||
		(compareVersions(version, bestVersion) == 0 && revisionCompare(revision, bestRevision) > 0)
}

func newestAvailableBinaryRelease(sourcePkg string, outputPkgs []string, cfg *Config, remoteIndex []RepoEntry) (string, string) {
	arch := GetSystemArchForPackage(cfg, sourcePkg)
	outputs := make(map[string]bool, len(outputPkgs))
	variants := make(map[string]bool)
	for _, outputPkg := range outputPkgs {
		outputs[outputPkg] = true
		for _, variant := range currentBinaryOutputVariants(sourcePkg, outputPkg, cfg) {
			variants[variant] = true
		}
	}

	bestVersion, bestRevision := "", ""
	for _, entry := range remoteIndex {
		if entry.Type == "meta" || !outputs[entry.Name] || entry.Arch != arch || !variants[entry.Variant] {
			continue
		}
		if newerBinaryRelease(entry.Version, entry.Revision, bestVersion, bestRevision) {
			bestVersion, bestRevision = entry.Version, entry.Revision
		}
	}

	return bestVersion, bestRevision
}

func cachedBinaryIndex() []RepoEntry {
	entries, err := os.ReadDir(BinDir)
	if err != nil {
		return nil
	}
	index := make([]RepoEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.zst") {
			continue
		}
		metadata, _, err := scanTarballMetadata(filepath.Join(BinDir, entry.Name()))
		if err != nil || metadata["name"] == "" || metadata["version"] == "" {
			continue
		}
		revision := metadata["revision"]
		if revision == "" {
			revision = "1"
		}
		index = append(index, RepoEntry{
			Name: metadata["name"], Version: metadata["version"], Revision: revision,
			Arch:    metadata["arch"],
			Variant: IdentifyVariant(metadata["name"], metadata["generic"] == "1", metadata["multilib"] == "1"),
		})
	}
	return index
}

func repositoryBinaryStatuses(cfg *Config, remoteIndex []RepoEntry) (map[string]repositoryBinaryStatus, error) {
	missing, err := missingRepositoryBinaryPackages(cfg, remoteIndex)
	if err != nil {
		return nil, err
	}
	statuses := make(map[string]repositoryBinaryStatus, len(missing))
	availableIndex := append([]RepoEntry(nil), remoteIndex...)
	availableIndex = append(availableIndex, cachedBinaryIndex()...)
	for sourcePkg, missingOutputs := range missing {
		pkgDir, err := findPackageMetadataDir(sourcePkg)
		if err != nil {
			return nil, err
		}
		outputs := []string{getOutputPackageName(sourcePkg, cfg)}
		outputs = append(outputs, splitPackageNamesFromDir(pkgDir)...)
		version, revision := newestAvailableBinaryRelease(sourcePkg, outputs, cfg, availableIndex)
		statuses[sourcePkg] = repositoryBinaryStatus{Missing: missingOutputs, PreviousVersion: version, PreviousRev: revision}
	}
	return statuses, nil
}

func askMissingBinaryScope() (bool, bool) {
	interactiveMu.Lock()
	defer interactiveMu.Unlock()
	scanner := bufio.NewScanner(os.Stdin)
	for {
		colArrow.Print("-> ")
		colNote.Print("Check (a)ll repository packages or only packages with an existing binary? [E/a]: ")
		if !scanner.Scan() {
			return false, false
		}
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "", "e", "existing":
			return false, true
		case "a", "all":
			return true, true
		default:
			colWarn.Println("Please enter 'e' for existing binaries or 'a' for all packages.")
		}
	}
}

func binaryVersionTransition(status repositoryBinaryStatus, currentVersion, currentRevision string) string {
	if status.PreviousVersion == "" {
		return ""
	}
	oldRelease, newRelease := status.PreviousVersion, currentVersion
	if status.PreviousVersion == currentVersion && status.PreviousRev != currentRevision {
		oldRelease += "-" + status.PreviousRev
		newRelease += "-" + currentRevision
	}
	return oldRelease + " -> " + newRelease
}

func missingRepositoryBinaryPackages(cfg *Config, remoteIndex []RepoEntry) (map[string][]string, error) {
	missing := make(map[string][]string)
	seen := make(map[string]bool)
	for _, repoPath := range filepath.SplitList(repoPaths) {
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read repository %s: %w", repoPath, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || seen[entry.Name()] {
				continue
			}
			pkgName := entry.Name()
			pkgDir := filepath.Join(repoPath, pkgName)
			if _, err := os.Stat(filepath.Join(pkgDir, "build")); err != nil {
				continue
			}
			if _, err := os.Stat(filepath.Join(pkgDir, "version")); err != nil {
				continue
			}
			seen[pkgName] = true

			version, revision, err := getRepoVersion2(pkgName)
			if err != nil {
				return nil, err
			}
			outputs := []string{getOutputPackageName(pkgName, cfg)}
			outputs = append(outputs, splitPackageNamesFromDir(pkgDir)...)
			for _, outputPkg := range outputs {
				if !currentBinaryOutputAvailable(pkgName, outputPkg, version, revision, cfg, remoteIndex) {
					missing[pkgName] = append(missing[pkgName], outputPkg)
				}
			}
		}
	}
	return missing, nil
}

func buildMissingRepositoryBinaries(cfg *Config, buildArgs []string, yes bool) error {
	var remoteIndex []RepoEntry
	if BinaryMirror != "" {
		index, err := GetCachedRemoteIndex(cfg)
		if err != nil {
			return fmt.Errorf("cannot determine remote binary availability: %w", err)
		}
		remoteIndex = index
	}

	colArrow.Print("-> ")
	colSuccess.Println("Checking repository packages for missing current binaries")
	statuses, err := repositoryBinaryStatuses(cfg, remoteIndex)
	if err != nil {
		return err
	}
	if len(statuses) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("All current repository packages have an available binary.")
		return nil
	}

	includeNeverBuilt := false
	if !yes {
		var ok bool
		includeNeverBuilt, ok = askMissingBinaryScope()
		if !ok {
			colNote.Println("Missing binary check canceled by user.")
			return nil
		}
	}

	packages := make([]string, 0, len(statuses))
	for pkgName, status := range statuses {
		if !includeNeverBuilt && status.PreviousVersion == "" {
			continue
		}
		packages = append(packages, pkgName)
	}
	sort.Strings(packages)
	if len(packages) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("All packages with existing binaries are current.")
		return nil
	}
	colArrow.Print("-> ")
	colWarn.Printf("Found %d source package(s) with missing binaries:\n", len(packages))
	for i, pkgName := range packages {
		status := statuses[pkgName]
		sort.Strings(status.Missing)
		colArrow.Print("-> ")
		fmt.Printf("%2d) ", i+1)
		color.Bold.Printf("%s", pkgName)
		fmt.Print(": ")
		currentVersion, currentRevision, _ := getRepoVersion2(pkgName)
		if transition := binaryVersionTransition(status, currentVersion, currentRevision); transition != "" {
			colNote.Printf("%s", transition)
			fmt.Print(" (")
			colNote.Printf("%s", strings.Join(status.Missing, ", "))
			fmt.Println(")")
		} else {
			colNote.Printf("%s\n", strings.Join(status.Missing, ", "))
		}
	}

	var selected []string
	if yes {
		selected = packages
	} else {
		indices, ok := AskForSelection("Build (a)ll, (q)uit, or select missing binary packages (numbers or -numbers):", len(packages))
		if !ok {
			colNote.Println("Missing binary build canceled by user.")
			return nil
		}
		for _, index := range indices {
			selected = append(selected, packages[index])
		}
	}
	if len(selected) == 0 {
		colNote.Println("No packages selected for building.")
		return nil
	}

	buildArgs = append(buildArgs, selected...)
	return handleBuildCommand(buildArgs, cfg)
}

// getBaseRepoPath extracts the base repository path (e.g., "/repo/reponame1")
// from a longer path (e.g., "/repo/reponame1/one").

func getBaseRepoPath(fullPath string) string {
	parts := strings.Split(fullPath, "/")

	// Example: for "/repo/reponame1/one", parts is ["", "repo", "reponame1", "one"]

	// We need at least parts for "", "repo", "reponameX". Length >= 3.
	if len(parts) < 3 {
		return fullPath
	}

	// We explicitly construct the path to ensure the leading '/' is present.
	// parts[0] is "", parts[1] is "repo", parts[2] is "reponame1"
	// We want to join "repo" and "reponame1" and prepend "/"

	// Check if the path is absolute (starts with '/')
	isAbs := strings.HasPrefix(fullPath, "/")

	// The components we want to join are parts[1] and parts[2]
	repoDir := path.Join(parts[1], parts[2])

	if isAbs {
		// Prepend the "/" to make it absolute again
		return "/" + repoDir
	}

	return repoDir // Return the relative path if the original wasn't absolute (though it should be)
}

func updateRepoWithSystemGit(dir string) {
	cmd := exec.Command("git", "pull")
	cmd.Dir = dir

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		if strings.Contains(outputStr, "would be overwritten by merge") {
			colArrow.Print("-> ")
			colWarn.Printf("Repository %s has local changes that would be overwritten.\n", dir)
			colArrow.Print("-> ")
			fmt.Printf("Output:\n%s\n", outputStr)

			if askForConfirmation(colWarn, "Discard local changes and pull updates from remote?") {
				resetCmd := exec.Command("git", "reset", "--hard", "HEAD")
				resetCmd.Dir = dir
				resetOutput, resetErr := resetCmd.CombinedOutput()
				if resetErr != nil {
					fmt.Printf("Error resetting repository %s: %v\nOutput:\n%s\n", dir, resetErr, strings.TrimSpace(string(resetOutput)))
					return
				}

				cleanCmd := exec.Command("git", "clean", "-fd")
				cleanCmd.Dir = dir
				cleanOutput, cleanErr := cleanCmd.CombinedOutput()
				if cleanErr != nil {
					fmt.Printf("Warning: Error cleaning repository %s: %v\nOutput:\n%s\n", dir, cleanErr, strings.TrimSpace(string(cleanOutput)))
				}

				retryCmd := exec.Command("git", "pull")
				retryCmd.Dir = dir
				retryOutput, retryErr := retryCmd.CombinedOutput()
				retryOutputStr := strings.TrimSpace(string(retryOutput))

				if retryErr != nil {
					fmt.Printf("Error pulling repo %s after reset: %v\nOutput:\n%s\n", dir, retryErr, retryOutputStr)
				} else {
					colArrow.Print("-> ")
					colSuccess.Printf("Successfully pulled repo %s after discarding local changes\nOutput:\n%s\n", dir, retryOutputStr)
				}
			} else {
				colArrow.Print("-> ")
				colWarn.Printf("Skipping repository %s (local changes preserved)\n", dir)
			}
		} else {
			fmt.Printf("Error pulling repo %s: %v\nOutput:\n%s\n", dir, err, outputStr)
		}
	} else {
		colArrow.Print("-> ")
		colSuccess.Printf("Successfully pulled repo %s\nOutput:\n%s\n", dir, outputStr)
	}
}

func updateRepoWithGoGit(dir string) {
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		fmt.Printf("Error opening repo %s with go-git: %v\n", dir, err)
		return
	}

	wt, err := repo.Worktree()
	if err != nil {
		fmt.Printf("Error opening worktree for repo %s: %v\n", dir, err)
		return
	}

	localChangesBeforePull, changesErr := localChangesToDiscard(repo, wt, dir)
	if changesErr != nil {
		debugf("Failed to snapshot local changes for %s before pull: %v\n", dir, changesErr)
	}
	lfsOnlyBeforePull, preservedLFS, lfsErr := preserveHydratedLFSChanges(repo, wt, dir)
	if lfsErr != nil {
		debugf("Failed to snapshot hydrated LFS assets for %s before pull: %v\n", dir, lfsErr)
		preservedLFS = nil
	}
	defer cleanupPreservedLFS(preservedLFS)

	if err := pullRepoWithGoGit(wt, dir); err != nil {
		if !isGoGitDirtyWorktreeError(err) {
			fmt.Printf("Error pulling repo %s with go-git: %v\n", dir, err)
			return
		}

		hasLocalChanges := changesErr != nil || len(localChangesBeforePull) > 0
		if hasLocalChanges && !lfsOnlyBeforePull {
			colArrow.Print("-> ")
			colWarn.Printf("Repository %s has local changes that would be overwritten.\n", dir)
			printGoGitDiscardedChanges(localChangesBeforePull, changesErr)
			if !askForConfirmation(colWarn, "Discard local changes and pull updates from remote?") {
				cleanupPreservedLFS(preservedLFS)
				colArrow.Print("-> ")
				colWarn.Printf("Skipping repository %s (local changes preserved)\n", dir)
				return
			}
		} else if len(preservedLFS) > 0 {
			colArrow.Print("-> ")
			colInfo.Printf("Preserving %d hydrated LFS asset(s) during go-git update\n", len(preservedLFS))
		} else {
			debugf("go-git reported dirty worktree for %s, but no pre-pull local changes were found\n", dir)
		}

		if err := wt.Reset(&gogit.ResetOptions{Mode: gogit.HardReset}); err != nil {
			cleanupPreservedLFS(preservedLFS)
			fmt.Printf("Error resetting repository %s with go-git: %v\n", dir, err)
			return
		}
		if err := wt.Clean(&gogit.CleanOptions{Dir: true}); err != nil {
			fmt.Printf("Warning: Error cleaning repository %s with go-git: %v\n", dir, err)
		}
		if err := pullRepoWithGoGit(wt, dir); err != nil {
			cleanupPreservedLFS(preservedLFS)
			fmt.Printf("Error pulling repo %s with go-git after reset: %v\n", dir, err)
			return
		}
		if err := restorePreservedLFS(repo, dir, preservedLFS); err != nil {
			cleanupPreservedLFS(preservedLFS)
			fmt.Printf("Warning: failed to restore preserved LFS assets for %s: %v\n", dir, err)
		}
		colArrow.Print("-> ")
		if lfsOnlyBeforePull {
			colSuccess.Printf("Successfully pulled repo %s while preserving LFS assets (go-git)\n", dir)
		} else if hasLocalChanges {
			colSuccess.Printf("Successfully pulled repo %s after discarding local changes (go-git)\n", dir)
		} else {
			colSuccess.Printf("Successfully pulled repo %s after retrying go-git update (go-git)\n", dir)
		}
	}

	resolveUpdatedRepoLFS(repo, dir)
}

func getHeadTree(repo *gogit.Repository) (*object.Tree, error) {
	ref, err := repo.Head()
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, err
	}
	return commit.Tree()
}

func treeLFSPointer(tree *object.Tree, relPath string) (lfsPointer, bool) {
	file, err := tree.File(filepath.ToSlash(relPath))
	if err != nil {
		return lfsPointer{}, false
	}
	if file.Size > 1024 {
		return lfsPointer{}, false
	}
	contents, err := file.Contents()
	if err != nil {
		return lfsPointer{}, false
	}
	ptr, ok := parseLFSPointer([]byte(contents))
	return ptr, ok
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func workingFileMatchesLFSPointer(path string, ptr lfsPointer) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != ptr.Size {
		return false
	}
	sum, err := sha256File(path)
	return err == nil && sum == ptr.OID
}

func preserveHydratedLFSChanges(repo *gogit.Repository, wt *gogit.Worktree, repoPath string) (bool, map[string]string, error) {
	status, err := wt.Status()
	if err != nil {
		return false, nil, err
	}
	tree, err := getHeadTree(repo)
	if err != nil {
		return false, nil, err
	}

	preserved := make(map[string]string)
	hasNonLFSChanges := false
	for relPath, fileStatus := range status {
		if fileStatus.Worktree == gogit.Unmodified && fileStatus.Staging == gogit.Unmodified {
			continue
		}
		ptr, ok := treeLFSPointer(tree, relPath)
		if !ok {
			hasNonLFSChanges = true
			continue
		}
		absPath := filepath.Join(repoPath, filepath.FromSlash(relPath))
		if !workingFileMatchesLFSPointer(absPath, ptr) {
			hasNonLFSChanges = true
			continue
		}

		cachePath := filepath.Join(os.TempDir(), fmt.Sprintf("hokuto-lfs-preserve-%d-%s", os.Getpid(), ptr.OID))
		if _, exists := preserved[relPath]; !exists {
			if err := copyFile(absPath, cachePath); err != nil {
				return false, preserved, err
			}
			preserved[relPath] = cachePath
		}
	}

	return len(preserved) > 0 && !hasNonLFSChanges, preserved, nil
}

func localChangesToDiscard(repo *gogit.Repository, wt *gogit.Worktree, repoPath string) ([]string, error) {
	status, err := wt.Status()
	if err != nil {
		return nil, err
	}
	tree, treeErr := getHeadTree(repo)

	var changes []string
	for relPath, fileStatus := range status {
		if fileStatus.Worktree == gogit.Unmodified && fileStatus.Staging == gogit.Unmodified {
			continue
		}
		if treeErr == nil {
			ptr, ok := treeLFSPointer(tree, relPath)
			if ok {
				absPath := filepath.Join(repoPath, filepath.FromSlash(relPath))
				if workingFileMatchesLFSPointer(absPath, ptr) {
					continue
				}
			}
		}
		changes = append(changes, fmt.Sprintf("%c%c %s", fileStatus.Staging, fileStatus.Worktree, relPath))
	}
	sort.Strings(changes)
	return changes, nil
}

func printGoGitDiscardedChanges(changes []string, err error) {
	if err != nil {
		colArrow.Print("-> ")
		colWarn.Printf("Warning: failed to list local changes: %v\n", err)
		return
	}
	if len(changes) == 0 {
		return
	}

	colArrow.Print("-> ")
	colWarn.Println("Local changes that would be discarded:")
	for _, change := range changes {
		colWarn.Printf("   %s\n", change)
	}
}

func restorePreservedLFS(repo *gogit.Repository, repoPath string, preserved map[string]string) error {
	if len(preserved) == 0 {
		return nil
	}
	defer cleanupPreservedLFS(preserved)

	tree, err := getHeadTree(repo)
	if err != nil {
		return err
	}
	restored := 0
	for relPath, cachePath := range preserved {
		ptr, ok := treeLFSPointer(tree, relPath)
		if !ok {
			continue
		}
		if !workingFileMatchesLFSPointer(cachePath, ptr) {
			continue
		}
		targetPath := filepath.Join(repoPath, filepath.FromSlash(relPath))
		if err := copyFile(cachePath, targetPath); err != nil {
			return err
		}
		restored++
	}
	if restored > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("Restored %d existing LFS asset(s)\n", restored)
	}
	return nil
}

func cleanupPreservedLFS(preserved map[string]string) {
	for _, path := range preserved {
		_ = os.Remove(path)
	}
}

func pullRepoWithGoGit(wt *gogit.Worktree, dir string) error {
	err := wt.Pull(&gogit.PullOptions{
		RemoteName: "origin",
		Progress:   os.Stderr,
	})
	if errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		colArrow.Print("-> ")
		colSuccess.Printf("Repository %s is already up to date (go-git)\n", dir)
		return nil
	}
	if err != nil {
		return err
	}
	colArrow.Print("-> ")
	colSuccess.Printf("Successfully pulled repo %s (go-git)\n", dir)
	return nil
}

func isGoGitDirtyWorktreeError(err error) bool {
	return errors.Is(err, gogit.ErrWorktreeNotClean) || errors.Is(err, gogit.ErrUnstagedChanges)
}

func resolveUpdatedRepoLFS(repo *gogit.Repository, dir string) {
	remote, err := repo.Remote("origin")
	if err != nil {
		debugf("Skipping LFS resolution for %s: missing origin remote: %v\n", dir, err)
		return
	}
	cfg := remote.Config()
	if len(cfg.URLs) == 0 {
		debugf("Skipping LFS resolution for %s: origin has no URL\n", dir)
		return
	}
	checkoutLFS := false
	askedLFS := false
	if err := maybeResolveRepositoryLFS(filepath.Base(dir), cfg.URLs[0], dir, &checkoutLFS, &askedLFS); err != nil {
		colArrow.Print("-> ")
		colWarn.Printf("Warning: failed to download LFS assets for %s: %v\n", dir, err)
	}
}

// updateRepos updates each unique repository found in repoPaths

func updateRepos() {
	// 1. Split the global repoPaths string by the path separator ":"
	paths := strings.Split(repoPaths, ":")
	_, gitErr := exec.LookPath("git")
	useGoGit := gitErr != nil
	if useGoGit {
		colArrow.Print("-> ")
		colWarn.Println("git not found; updating repositories with internal go-git")
	}

	// 2. Determine the unique base repository directories
	uniqueRepoDirs := make(map[string]struct{})
	for _, p := range paths {
		// Clean the path to get the base repository directory
		repoDir := getBaseRepoPath(p)

		if repoDir != "" {
			uniqueRepoDirs[repoDir] = struct{}{}
		}
	}
	colArrow.Print("-> ")
	colSuccess.Println("Unique repositories to update:")
	for dir := range uniqueRepoDirs {
		colArrow.Print("-> ")
		colSuccess.Printf("%s\n", dir)

		if useGoGit {
			updateRepoWithGoGit(dir)
		} else {
			updateRepoWithSystemGit(dir)
		}
	}
}

// checkPackageExists checks if a specific package directory exists in the Installed path.
// It returns true if the package directory exists and is a directory, false otherwise.
// This is a direct, silent check, ideal for internal dependency resolution.

func checkPackageExists(pkgName string) bool {
	// Determine the full path to the package's installed directory
	pkgPath := filepath.Join(Installed, pkgName)

	// Check if the path exists and is a directory.
	info, err := os.Stat(pkgPath)
	if err != nil {
		// os.IsNotExist(err) covers the most common failure,
		// any other error (permission, etc.) is treated as "not installed" for safety.
		return false
	}

	// Ensure it's actually a directory (to exclude possible stray files)
	return info.IsDir()
}

// getInstalledPackageOutput reads installed package versions from the filesystem,
// filters them by searchTerm, and returns the list as a formatted byte slice.

func getInstalledPackageOutput(searchTerm string) ([]byte, error) {
	var outputBuilder strings.Builder

	// Step 1: Get the full list of installed package directories.
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			// If the directory doesn't exist, treat it as empty, no error.
			return []byte(""), nil
		}
		return nil, fmt.Errorf("failed to read installed directory %s: %w", Installed, err)
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
		for _, pkg := range allPkgs {
			if strings.Contains(pkg, searchTerm) {
				pkgsToShow = append(pkgsToShow, pkg)
			}
		}
	} else {
		// If no search term, show everything.
		pkgsToShow = allPkgs
	}

	// Step 3: Format and collect the information (instead of printing).
	// The format is expected to be: "<pkgName> <version> [revision]"
	for _, p := range pkgsToShow {
		versionFile := filepath.Join(Installed, p, "version")
		versionInfo := "unknown 0" // Default for unreadable file

		if data, err := os.ReadFile(versionFile); err == nil {
			// Use the full content of the version file (e.g., "1.0 1")
			versionInfo = strings.TrimSpace(string(data))
		}

		// Write the package name and its full version info to the buffer
		// Example line: "fcron 3.4.0 1"
		outputBuilder.WriteString(fmt.Sprintf("%s %s\n", p, versionInfo))
	}

	// Return the collected data as a byte slice.
	return []byte(outputBuilder.String()), nil
}

// Struct to hold package information
type Package struct {
	Name              string
	InstalledVersion  string
	InstalledRevision string
	RepoVersion       string
	RepoRevision      string
}

// parsePackageList converts the output of getInstalledPackageOutput into a map of packages.

func parsePackageList(output []byte) (map[string]Package, error) {
	packages := make(map[string]Package)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		// Expecting at least 3 parts: <name> <version> <revision>
		if len(parts) < 3 {
			// Allow for packages with missing revision (assume 0 or 1 for simplicity)
			// For now, let's strictly require 3 fields for accurate comparison
			return nil, fmt.Errorf("invalid package list format (expected name, version, revision): %s", line)
		}

		pkgName := parts[0]
		pkgVersion := parts[1]
		pkgRevision := parts[2] // EXTRACT THE REVISION

		packages[pkgName] = Package{
			Name:              pkgName,
			InstalledVersion:  pkgVersion,
			InstalledRevision: pkgRevision, // Store the revision
		}
	}
	return packages, scanner.Err()
}

// checkDependencyBlocks checks if any installed package depends on a lower version
// of the package being updated. Returns the blocking package name if found, empty string otherwise.

func checkDependencyBlocks(pkgName string, newVersion string, installedPackages map[string]Package, cfg *Config) string {
	// Iterate through all installed packages
	for installedPkgName := range installedPackages {
		// Skip the package itself
		if installedPkgName == pkgName {
			continue
		}

		// Use findPackageMetadataDir to locate the package metadata without re-extracting
		// for versioned/renamed packages.
		pkgDir, err := findPackageMetadataDir(installedPkgName)
		if err != nil {
			// If we can't find metadata, skip it.
			continue
		}

		// Parse the dependencies using the established helper
		deps, err := parseDependsFile(pkgDir)
		if err != nil {
			continue
		}

		for _, dep := range deps {
			// FILTER: skip cross dependencies if not cross-compiling
			if dep.Cross && cfg.Values["HOKUTO_CROSS_ARCH"] == "" {
				continue
			}

			// FILTER: skip crossnative dependencies unless we are in a cross-native build
			if dep.CrossNative {
				if cfg.Values["HOKUTO_CROSS_ARCH"] == "" || cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
					continue
				}
			}

			if dep.Name != pkgName {
				continue
			}

			// If there's a version constraint, check if the new version violates it
			if dep.Op != "" && dep.Version != "" {
				// We check if the new version satisfies the constraint.
				// If not, it's blocked.
				if !versionSatisfies(newVersion, dep.Op, dep.Version) {
					return installedPkgName
				}
			}
		}
	}

	return ""
}

// checkForUpgrades is the main function for the upgrade logic.

func checkForUpgrades(_ context.Context, cfg *Config, maxJobs int, yes bool) error {
	defer flushPackageSuggestions(os.Stdout, cfg, false, true, yes)
	defer binaryOnlyRuntimeDependencyInstallScope()()

	colArrow.Print("-> ")
	colSuccess.Println("Checking for Package Upgrades")

	// 1. Get list of installed packages
	output, err := getInstalledPackageOutput("")
	if err != nil {
		return fmt.Errorf("could not retrieve installed packages: %w", err)
	}

	installedPackages, err := parsePackageList(output)
	if err != nil {
		return fmt.Errorf("failed to parse package list: %w", err)
	}

	var upgradeList []Package

	// 2. Compare installed version + revision vs. repo version + revision
	for name, pkg := range installedPackages {
		// Updated call to getRepoVersion to capture both version and revision
		repoVersion, repoRevision, err := getRepoVersion2(name)
		if err != nil {
			// Log error but continue to the next package
			debugf("Warning: Could not get repo version for %s: %v\n", name, err)
			continue
		}

		// Store repo information on the package struct
		pkg.RepoVersion = repoVersion
		pkg.RepoRevision = repoRevision

		// Comparison Logic: Check for a mismatch in either version OR revision
		isVersionMismatch := pkg.InstalledVersion != pkg.RepoVersion
		isRevisionMismatch := pkg.InstalledRevision != pkg.RepoRevision

		// NOTE: A more complex system would compare versions numerically,
		// but for simple string equality checks, this is sufficient:
		if isVersionMismatch || isRevisionMismatch {
			// Add to upgrade list
			upgradeList = append(upgradeList, pkg)
		}
	}

	// 2.5. Filter upgrade list based on dependencies and lock file
	lockedPackages := readLockFile()
	var filteredUpgradeList []Package
	var blockedPackages []string

	for _, pkg := range upgradeList {
		shouldSkip := false
		blockReason := ""

		// Check if blocked by installed package dependencies
		blockingPkg := checkDependencyBlocks(pkg.Name, pkg.RepoVersion, installedPackages, cfg)
		if blockingPkg != "" {
			shouldSkip = true
			blockReason = fmt.Sprintf("%s update blocked by %s", pkg.Name, blockingPkg)
		}

		// Check if locked in /etc/hokuto/hokuto.lock
		if lockedVersion, isLocked := lockedPackages[pkg.Name]; isLocked {
			// If locked version is lower than the new version, block the update
			if compareVersions(lockedVersion, pkg.RepoVersion) < 0 {
				shouldSkip = true
				if blockReason != "" {
					blockReason += " and lock file"
				} else {
					blockReason = fmt.Sprintf("%s update blocked by lock file (locked at %s)", pkg.Name, lockedVersion)
				}
			}
		}

		if shouldSkip {
			blockedPackages = append(blockedPackages, blockReason)
		} else {
			filteredUpgradeList = append(filteredUpgradeList, pkg)
		}
	}

	// Print blocked packages if any
	if len(blockedPackages) > 0 {
		cPrintf(colWarn, "\n--- %d Package(s) Blocked from Update ---\n", len(blockedPackages))
		for _, reason := range blockedPackages {
			cPrintf(colWarn, "  - %s\n", reason)
		}
	}

	// 3. Handle upgrade list
	if len(filteredUpgradeList) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No packages to upgrade.")
		return nil
	}

	// Sort upgrade list alphabetically
	sort.SliceStable(filteredUpgradeList, func(i, j int) bool {
		return filteredUpgradeList[i].Name < filteredUpgradeList[j].Name
	})

	fmt.Println()
	colSuccess.Printf("--- %d Package(s) to Upgrade ---\n", len(filteredUpgradeList))
	for i, pkg := range filteredUpgradeList {
		colArrow.Print("-> ")
		fmt.Printf("%2d) ", i+1)
		color.Bold.Printf("%s", pkg.Name)
		fmt.Print(": ")
		colNote.Printf("%s %s -> %s %s\n",
			pkg.InstalledVersion, pkg.InstalledRevision,
			pkg.RepoVersion, pkg.RepoRevision)
	}

	// 4. Prompt user for upgrade
	var indices []int
	var ok bool
	if yes {
		// Auto-select all
		for i := range filteredUpgradeList {
			indices = append(indices, i)
		}
		ok = true
	} else {
		indices, ok = AskForSelection("Update (a)ll, (q)uit, or pick packages to update/ignore (numbers or -numbers):", len(filteredUpgradeList))
	}
	if !ok {
		colNote.Println("Upgrade canceled by user.")
		return nil
	}

	var pkgNames []string
	for _, idx := range indices {
		pkgNames = append(pkgNames, filteredUpgradeList[idx].Name)
	}

	// 5. Build order and dependency resolution for the updates
	userRequestedMap := make(map[string]bool)
	hokutoInUpdates := false
	for _, pkg := range pkgNames {
		userRequestedMap[pkg] = true
		if pkg == "hokuto" {
			hokutoInUpdates = true
		}
	}

	// If hokuto is in the list, we prioritize it and stop afterwards
	if hokutoInUpdates {
		colArrow.Printf("-> ")
		colSuccess.Println("Updating Hokuto")
		pkgNames = []string{"hokuto"}
		// Re-initialize userRequestedMap for just hokuto
		userRequestedMap = map[string]bool{"hokuto": true}
	}

	// 4.5. Pre-check for available binaries to avoid pulling in build dependencies
	binaryAvailable := make(map[string]bool)

	// Fetch remote index once for all checks (pre-check, sequential, parallel)
	var remoteIndex []RepoEntry
	if BinaryMirror != "" {
		// Use the shared cache here because build-dependency fallback lookups also
		// call GetCachedRemoteIndex. A direct fetch left the cache uninitialized,
		// causing a second fetch to print in the middle of the progress bar.
		if idx, err := GetCachedRemoteIndex(cfg); err == nil {
			remoteIndex = idx
		}
	}

	if len(pkgNames) > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("Checking for binary availability\n")
		// Use fetching logic to populate binaryAvailable
		for _, pkgName := range pkgNames {
			version, revision, err := getRepoVersion2(pkgName)
			if err != nil {
				continue
			}

			outputPkgName := getOutputPackageName(pkgName, cfg)
			arch := GetSystemArchForPackage(cfg, pkgName)
			variant := GetSystemVariantForPackage(cfg, pkgName)
			tarballName := StandardizeRemoteName(outputPkgName, version, revision, arch, variant)
			tarballPath := filepath.Join(BinDir, tarballName)

			// 1. Check local cache
			if _, err := os.Stat(tarballPath); err == nil {
				binaryAvailable[pkgName] = true
				continue
			}

			if BinaryMirror != "" && len(remoteIndex) > 0 {
				// Lookup checksum and verify the package exists in the index
				var expectedSum string
				foundInIndex := false
				targetArch := GetSystemArchForPackage(cfg, pkgName)
				preferredVariant := GetSystemVariantForPackage(cfg, pkgName)
				fallbackVariant := ""
				if !strings.Contains(preferredVariant, "generic") {
					fallbackVariant = "generic"
					if strings.HasPrefix(preferredVariant, "multi-") {
						fallbackVariant = "multi-generic"
					}
				}

				var bestEntry *RepoEntry
				for _, entry := range remoteIndex {
					if entry.Name == pkgName && entry.Version == version &&
						entry.Revision == revision && entry.Arch == targetArch {
						if entry.Variant == preferredVariant {
							e := entry
							bestEntry = &e
							break
						}
						if fallbackVariant != "" && entry.Variant == fallbackVariant {
							e := entry
							bestEntry = &e
						}
					}
				}

				if bestEntry != nil {
					expectedSum = bestEntry.B3Sum
					foundInIndex = true
				}

				// Only attempt download if the package was found in the remote index
				if foundInIndex {
					// Use quiet mode for check
					if err := fetchBinaryPackage(pkgName, version, revision, cfg, true, expectedSum, false); err == nil {
						binaryAvailable[pkgName] = true
					}
				}
			}
		}
	}

	// Snapshot before any update build dependency is installed. Cleanup happens
	// once at function exit, after every selected update has finished or failed.
	quietDependencyInstalls := true
	installedAtUpdateStart := snapshotInstalledPackageNames()
	endBuildSession := registerHokutoBuildSession()
	defer endBuildSession()
	defer func() {
		installedAfterUpdate := snapshotInstalledPackageNames()
		temporaryBuildDeps := temporaryUpdatePackages(installedAtUpdateStart, installedAfterUpdate, userRequestedMap)
		uninstallBuildDependenciesWithOptions(temporaryBuildDeps, cfg, quietDependencyInstalls)
	}()

	plan, err := resolveBuildPlan(pkgNames, userRequestedMap, false, cfg, binaryAvailable)
	if err != nil {
		return fmt.Errorf("failed to resolve upgrade plan: %w", err)
	}
	updateTargets := append([]string(nil), pkgNames...)
	acceptedBinaryDeps := make(map[string]bool)
	for {
		installedBinaryDeps, installErr := installAvailableBinaryBuildDeps(plan, userRequestedMap, acceptedBinaryDeps, cfg, func(string) {}, false, false, quietDependencyInstalls)
		if installErr != nil {
			return fmt.Errorf("failed to install update build dependencies: %w", installErr)
		}
		if !installedBinaryDeps {
			break
		}
		plan, err = resolveBuildPlan(updateTargets, userRequestedMap, false, cfg, binaryAvailable)
		if err != nil {
			return fmt.Errorf("failed to refresh upgrade plan after installing build dependencies: %w", err)
		}
	}
	// Use the ordered plan instead of the unordered list
	pkgNames = plan.Order

	// Apply user-specified update order from /etc/hokuto/hokuto.update
	var manualPrereqs map[string][]string
	pkgNames, manualPrereqs = applyUpdateOrder(pkgNames)
	splitDepsBySource := prepareUpdateBuildPlan(plan, pkgNames, manualPrereqs, cfg)

	// Launch background prefetcher for SUBSEQUENT packages.
	if len(pkgNames) > 1 {
		go prefetchSources(pkgNames[1:])
	}

	includeMultilibDevel := packageSetHasBuildOption(pkgNames, "multilib")
	if _, err := ensureDevelPackagesInstalledWithOptions(cfg, includeMultilibDevel, false, quietDependencyInstalls); err != nil {
		return fmt.Errorf("failed to prepare devel packages before update: %w", err)
	}

	// --- PARALLEL EXECUTION PATH ---
	if maxJobs > 1 {
		colArrow.Print("-> ")
		colSuccess.Printf("Executing parallel update (jobs: %d)\n", maxJobs)

		// Retain the complete dependency metadata from resolution. In particular,
		// PostRebuilds carries optional split dependencies such as lib32-* outputs.
		updatePlan := plan

		// Use a custom builder that incorporates binary checks
		smartBuilder := func(pkgName string, cfg *Config, exec *Executor, opts BuildOptions) (time.Duration, error) {
			// 1. Check for binary (cache or mirror)
			version, revision, err := getRepoVersion2(pkgName)
			if err != nil {
				return 0, fmt.Errorf("failed to get version: %w", err)
			}

			// Skip binary check for rebuild packages (e.g. DKMS triggers).
			// These must be built from source against the current system state
			// (e.g. new kernel headers), so a cached binary would be stale.
			isRebuild := updatePlan.RebuildPackages != nil && updatePlan.RebuildPackages[pkgName]
			if isRebuild {
				return pkgBuild(pkgName, cfg, exec, opts)
			}

			// Try to fetch binary if configured (mirror check logic reused logic from sequential)
			if BinaryMirror != "" && len(remoteIndex) > 0 {
				// Lookup checksum and verify the package exists in the index
				var expectedSum string
				foundInIndex := false
				targetArch := GetSystemArchForPackage(cfg, pkgName)
				preferredVariant := GetSystemVariantForPackage(cfg, pkgName)
				fallbackVariant := ""
				if !strings.Contains(preferredVariant, "generic") {
					fallbackVariant = "generic"
					if strings.HasPrefix(preferredVariant, "multi-") {
						fallbackVariant = "multi-generic"
					}
				}

				var bestEntry *RepoEntry
				for _, entry := range remoteIndex {
					if entry.Name == pkgName && entry.Version == version &&
						entry.Revision == revision && entry.Arch == targetArch {
						if entry.Variant == preferredVariant {
							e := entry
							bestEntry = &e
							break
						}
						if fallbackVariant != "" && entry.Variant == fallbackVariant {
							e := entry
							bestEntry = &e
						}
					}
				}

				if bestEntry != nil {
					expectedSum = bestEntry.B3Sum
					foundInIndex = true
				}

				// Only attempt download if the package was found in the remote index
				if foundInIndex {
					// Errors here are ignored, we just fail to find binary and proceed to build
					// Parallel mode: pass quiet=true
					_ = fetchBinaryPackage(pkgName, version, revision, cfg, true, expectedSum, false)
				}
			}

			outputPkgName := getOutputPackageName(pkgName, cfg)
			arch := GetSystemArchForPackage(cfg, pkgName)
			variant := GetSystemVariantForPackage(cfg, pkgName)
			tarballPath := filepath.Join(BinDir, StandardizeRemoteName(outputPkgName, version, revision, arch, variant))

			// If we found a different variant in the index and it was successfully fetched,
			// we need to check for that path instead.
			// Actually, we can just check if any variant exists in the loop below.
			// But for consistency with sequential mode:
			if BinaryMirror != "" && len(remoteIndex) > 0 {
				// Re-verify which variant we actually have
				targetArch := GetSystemArchForPackage(cfg, pkgName)

				for _, entry := range remoteIndex {
					if entry.Name == pkgName && entry.Version == version &&
						entry.Revision == revision && entry.Arch == targetArch {
						// Check if this variant's tarball exists
						testPath := filepath.Join(BinDir, StandardizeRemoteName(outputPkgName, version, revision, targetArch, entry.Variant))
						if _, err := os.Stat(testPath); err == nil {
							tarballPath = testPath
							break
						}
					}
				}
			}

			if _, err := os.Stat(tarballPath); err == nil {
				// Found binary! Return success with 0 duration to signal "skipped build" (ready for install)
				return 0, nil
			}

			// 2. Not found ? Build it.
			return pkgBuild(pkgName, cfg, exec, opts)
		}

		if _, err := installAvailableBinaryDependenciesForPlanWithOptions(updatePlan, cfg, false, true); err != nil {
			return err
		}
		if _, err := RunParallelBuilds(updatePlan, cfg, maxJobs, userRequestedMap, yes, true, splitDepsBySource, smartBuilder); err != nil {
			return err
		}

		if err := PostInstallTasks(RootExec, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Global post-install tasks failed: %v\n", err)
		}

		// Recheck specific condition: Hokuto itself updated?
		if hokutoInUpdates && len(filteredUpgradeList) > 1 {
			colArrow.Print("-> ")
			colSuccess.Println("Hokuto has been updated. Run 'hokuto update' again to complete the remaining updates.")
			return nil
		}

		colArrow.Print("-> ")
		colSuccess.Printf("System update completed successfully.\n")
		return nil
	}

	// --- SEQUENTIAL EXECUTION LOGIC ---
	var failedPackages []string
	var totalUpdateDuration time.Duration // Accumulator for the whole update process
	totalToUpdate := len(pkgNames)

	for i, pkgName := range pkgNames {
		colArrow.Print("\n-> ")
		if userRequestedMap[pkgName] {
			colSuccess.Printf("Executing update for:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, totalToUpdate)
		} else {
			colSuccess.Printf("Installing dependency:")
			colNote.Printf(" %s (%d/%d)\n", pkgName, i+1, totalToUpdate)
		}

		// 0. Check for binary package first (Local Cache or Mirror)
		version, revision, err := getRepoVersion2(pkgName)
		if err != nil {
			color.Danger.Printf("Failed to get version/revision for %s: %v\n", pkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}

		outputPkgName := getOutputPackageName(pkgName, cfg)
		arch := GetSystemArchForPackage(cfg, pkgName)
		variant := GetSystemVariantForPackage(cfg, pkgName)
		tarballName := StandardizeRemoteName(outputPkgName, version, revision, arch, variant)
		tarballPath := filepath.Join(BinDir, tarballName)

		foundBinary := false
		if _, err := os.Stat(tarballPath); err == nil {
			colArrow.Print("-> ")
			colSuccess.Printf("Using cached binary package: %s\n", tarballName)
			foundBinary = true
		} else if BinaryMirror != "" && len(remoteIndex) > 0 {
			// Lookup checksum and verify the package exists in the index
			var expectedSum string
			foundInIndex := false
			targetArch := GetSystemArchForPackage(cfg, pkgName)
			preferredVariant := GetSystemVariantForPackage(cfg, pkgName)
			fallbackVariant := ""
			if !strings.Contains(preferredVariant, "generic") {
				fallbackVariant = "generic"
				if strings.HasPrefix(preferredVariant, "multi-") {
					fallbackVariant = "multi-generic"
				}
			}

			var bestEntry *RepoEntry
			for _, entry := range remoteIndex {
				if entry.Name == pkgName && entry.Version == version &&
					entry.Revision == revision && entry.Arch == targetArch {
					if entry.Variant == preferredVariant {
						e := entry
						bestEntry = &e
						break
					}
					if fallbackVariant != "" && entry.Variant == fallbackVariant {
						e := entry
						bestEntry = &e
					}
				}
			}

			if bestEntry != nil {
				expectedSum = bestEntry.B3Sum
				foundInIndex = true
				// If we are using a fallback, update the tarball path
				if bestEntry.Variant != preferredVariant {
					tarballName = StandardizeRemoteName(outputPkgName, version, revision, targetArch, bestEntry.Variant)
					tarballPath = filepath.Join(BinDir, tarballName)
				}
			}

			if foundInIndex {
				// Sequential mode: output is fine (quiet=false)
				if err := fetchBinaryPackage(pkgName, version, revision, cfg, false, expectedSum, false); err == nil {
					foundBinary = true
				} else {
					colArrow.Print("-> ")
					colSuccess.Println("Binary not found on mirror, building package locally")
				}
			}
		}

		if foundBinary {
			isCriticalAtomic.Store(1)
			handlePreInstallUninstall(outputPkgName, cfg, RootExec, false, nil)
			colArrow.Print("-> ")
			colSuccess.Printf("Installing")
			colNote.Printf(" %s\n", outputPkgName)
			if _, err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, false, false, false, nil); err != nil {
				isCriticalAtomic.Store(0)
				color.Danger.Printf("Binary installation failed for %s: %v. Falling back to build.\n", outputPkgName, err)
			} else {
				isCriticalAtomic.Store(0)
				colArrow.Print("-> ")
				if userRequestedMap[pkgName] {
					colSuccess.Printf("Package")
					colNote.Printf(" %s ", outputPkgName)
					colSuccess.Printf("updated from binary successfully.\n")
				} else {
					colSuccess.Printf("Dependency")
					colNote.Printf(" %s ", outputPkgName)
					colSuccess.Printf("installed successfully.\n")
				}
				// If it was a requested update, add to world
				if userRequestedMap[pkgName] {
					addToWorld(pkgName)
				}
				continue // Successfully updated from binary, move to next package
			}
		}

		// A. Fallback: Directly call pkgBuild within the current process
		duration, err := pkgBuild(pkgName, cfg, UserExec, BuildOptions{
			Bootstrap:    false,
			CurrentIndex: i + 1,
			TotalCount:   totalToUpdate,
		})
		if err != nil {
			color.Danger.Printf("Build failed for %s: %v\n", pkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}
		totalUpdateDuration += duration

		// B. If build is successful, install the package
		isCriticalAtomic.Store(1)
		handlePreInstallUninstall(outputPkgName, cfg, RootExec, false, nil)
		colArrow.Print("-> ")
		colSuccess.Printf("Installing")
		colNote.Printf(" %s\n", outputPkgName)
		if _, err := pkgInstall(tarballPath, outputPkgName, cfg, RootExec, false, false, false, nil); err != nil {
			isCriticalAtomic.Store(0)
			color.Danger.Printf("Installation failed for %s: %v\n", outputPkgName, err)
			failedPackages = append(failedPackages, pkgName)
			continue
		}
		isCriticalAtomic.Store(0)

		colArrow.Print("-> ")
		if userRequestedMap[pkgName] {
			colSuccess.Printf("Package")
			colNote.Printf(" %s ", outputPkgName)
			colSuccess.Printf("updated successfully.\n")
		} else {
			colSuccess.Printf("Dependency")
			colNote.Printf(" %s ", outputPkgName)
			colSuccess.Printf("installed successfully.\n")
		}

		// Add to World if it was a requested update
		if userRequestedMap[pkgName] {
			addToWorld(pkgName)
		}
	}

	if len(failedPackages) > 0 {
		return fmt.Errorf("some packages failed to update: %s", strings.Join(failedPackages, ", "))
	}

	if hokutoInUpdates && len(filteredUpgradeList) > 1 {
		colArrow.Print("-> ")
		colSuccess.Println("Hokuto has been updated. Run 'hokuto update' again to complete the remaining updates.")
		return nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("System update completed successfully (%d/%d) Total Time: %s\n", totalToUpdate, totalToUpdate, totalUpdateDuration.Truncate(time.Second))
	return nil
}

// applyUpdateOrder reorders the package list based on /etc/hokuto/hokuto.update
func applyUpdateOrder(pkgNames []string) ([]string, map[string][]string) {
	updateOrderFile := filepath.Join(rootDir, "etc", "hokuto", "hokuto.update")
	data, err := os.ReadFile(updateOrderFile)
	if err != nil {
		// If file doesn't exist or can't be read, return original order and nil prereqs
		return pkgNames, nil
	}

	// Map to store the priority of packages.
	// We use the order of appearance in the file to determine priority.
	priority := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	rank := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Each line can contain one or more packages separated by spaces
		pkgs := strings.Fields(line)
		for _, p := range pkgs {
			// Only assign priority if not already assigned (first occurrence wins)
			if _, exists := priority[p]; !exists {
				priority[p] = rank
				rank++
			}
		}
	}

	if len(priority) == 0 {
		return pkgNames, nil
	}

	// Create a copy to avoid modifying the input slice
	result := make([]string, len(pkgNames))
	copy(result, pkgNames)

	// Sort the packages. We use a stable sort to maintain the relative order
	// provided by the dependency resolver for packages not mentioned in the update file
	// or for which no relative order is specified.
	sort.SliceStable(result, func(i, j int) bool {
		p1, ok1 := priority[result[i]]
		p2, ok2 := priority[result[j]]

		// If both packages are in the update order file, use their relative order.
		if ok1 && ok2 {
			return p1 < p2
		}

		// If only one is in the file or neither is, we preserve their original
		// relative order from the topological sort to avoid breaking dependencies.
		return false
	})

	// Generate manual prerequisites for parallel builds
	manualPrereqs := make(map[string][]string)

	// Create a map for quick lookup of packages in the current update list
	inUpdateList := make(map[string]bool)
	for _, p := range pkgNames {
		inUpdateList[p] = true
	}

	// Re-scan to generate prerequisites based on per-line ordering
	scanner = bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		pkgs := strings.Fields(line)
		var lastPkgInUpdate string
		for _, p := range pkgs {
			if inUpdateList[p] {
				if lastPkgInUpdate != "" {
					manualPrereqs[p] = append(manualPrereqs[p], lastPkgInUpdate)
				}
				lastPkgInUpdate = p
			}
		}
	}

	return result, manualPrereqs
}

func prepareUpdateBuildPlan(plan *BuildPlan, order []string, manualPrereqs map[string][]string, cfg *Config) map[string][]string {
	plan.Order = order
	plan.ManualPrereqs = manualPrereqs
	splitDepsBySource := collectSplitDependenciesForPlan(plan, cfg)
	addPostRebuildSplitDependencies(plan, splitDepsBySource)
	return splitDepsBySource
}

func temporaryUpdatePackages(installedBefore, installedAfter, userRequested map[string]bool) []string {
	var temporary []string
	for pkgName := range installedAfter {
		if installedBefore[pkgName] || userRequested[pkgName] {
			continue
		}
		temporary = append(temporary, pkgName)
	}
	sort.Strings(temporary)
	return temporary
}

// resolveMissingDeps recursively finds all missing dependencies for a package.
// It assumes cfg is passed in, as it's needed for the recursive call.

func isPackageInstalled(pkgName string) bool {
	// Exact package names still work for ABI-suffixed packages such as pkg-MAJOR,
	// but a base name only matches the base package unless a caller supplies an
	// explicit version constraint through findInstalledSatisfying.
	return findInstalledSatisfying(pkgName, "", "") != ""
}
