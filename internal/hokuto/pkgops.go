package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

func copyDirContentsFallback(src, dst string) error {
	walkRoot, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	return filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(walkRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}

		target := filepath.Join(dst, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}

		switch {
		case info.IsDir():
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chtimes(target, info.ModTime(), info.ModTime())
		case info.Mode()&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(linkTarget, target)
		case info.Mode().IsRegular():
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := copyFile(path, target); err != nil {
				return err
			}
			return os.Chtimes(target, info.ModTime(), info.ModTime())
		default:
			debugf("Skipping unsupported source entry type %s: %s\n", info.Mode().Type(), path)
			return nil
		}
	})
}

func copySourceContents(srcPath, targetDir, sourceKind string, execCtx *Executor) error {
	if _, err := exec.LookPath("rsync"); err == nil {
		rsyncCmd := exec.Command("rsync", "-a", srcPath+"/", targetDir)
		if err := execCtx.Run(rsyncCmd); err == nil {
			return nil
		} else {
			debugf("rsync failed while copying %s source %s to %s, falling back to internal copy: %v\n", sourceKind, srcPath, targetDir, err)
		}
	} else {
		debugf("rsync not found, using internal copy for %s source %s\n", sourceKind, srcPath)
	}

	if err := copyDirContentsFallback(srcPath, targetDir); err != nil {
		return fmt.Errorf("internal copy failed for %s source contents from %s to %s: %w", sourceKind, srcPath, targetDir, err)
	}
	return nil
}

func prepareSources(pkgName, pkgDir, buildDir string, execCtx *Executor) error {
	// Assuming CacheDir, SourcesDir, Executor, etc. are available in scope.
	srcDir := filepath.Join(CacheDir, "sources", pkgName)

	// Read sources list
	sourcesFile := filepath.Join(pkgDir, "sources")
	sourcesData, err := os.ReadFile(sourcesFile)
	if err != nil {
		return fmt.Errorf("failed to read sources file: %v", err)
	}

	for _, line := range strings.Split(string(sourcesData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into tokens: path, optional subdir, optional flags
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		relPath := tokens[0]

		filenameOverride := ""
		if len(tokens) >= 3 && tokens[1] == "->" {
			filenameOverride = tokens[2]
			// Shift tokens so the rest of the logic (subdir, noextract) works
			tokens = append([]string{tokens[0]}, tokens[3:]...)
		}

		targetSubdir := ""
		noExtract := false
		for _, tok := range tokens[1:] {
			switch tok {
			case "noextract":
				noExtract = true
			default:
				// treat as target subdir if not a flag
				if targetSubdir == "" {
					targetSubdir = tok
				}
			}
		}

		// 2. Determine the final target directory
		targetDir := buildDir
		if targetSubdir != "" {
			targetDir = filepath.Join(buildDir, targetSubdir)
			if err := os.MkdirAll(targetDir, 0o755); err != nil {
				return fmt.Errorf("failed to create target subdir %s: %v", targetDir, err)
			}
		}

		// 3. Determine the source path on disk (srcPath) based on relPath type

		var srcPath string

		isGitSource := strings.HasPrefix(relPath, "git+")
		isSvnSource := strings.HasPrefix(relPath, "svn+")
		isHgSource := strings.HasPrefix(relPath, "hg+")
		isUrlSource := strings.HasPrefix(relPath, "http://") || strings.HasPrefix(relPath, "https://") || strings.HasPrefix(relPath, "ftp://")

		switch {
		case strings.HasPrefix(relPath, "files/"):
			// Local files in package directory
			srcPath = filepath.Join(pkgDir, relPath)
		case isGitSource:
			// Git sources: Source path is the cloned directory in the cache (SourcesDir/pkgName/repoName)
			gitURL := strings.TrimPrefix(relPath, "git+")
			parsedURL, err := url.Parse(gitURL)
			if err != nil {
				return fmt.Errorf("invalid git URL in sources file: %w", err)
			}
			repoBase := filepath.Base(parsedURL.Path)
			repoBase = strings.TrimSuffix(repoBase, ".git")
			// srcDir is SourcesDir/pkgName. We look for the cloned repo name inside it.
			srcPath = filepath.Join(srcDir, repoBase)

			// Check if source exists *before* deciding to copy its contents
			info, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("git source %s listed but missing: stat %s: %v", relPath, srcPath, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("git source %s exists but is not a directory: %s", relPath, srcPath)
			}

			if err := copySourceContents(srcPath, targetDir, "git", execCtx); err != nil {
				return fmt.Errorf("failed to copy git source contents from %s to %s: %v", srcPath, targetDir, err)
			}
			// Git source handled, move to the next line
			continue

		case isSvnSource:
			// SVN sources: Source path is the checkout directory in the cache (SourcesDir/pkgName/dirName)
			dirName := svnDirName(relPath)
			srcPath = filepath.Join(srcDir, dirName)

			// Check if source exists
			info, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("SVN source %s listed but missing: stat %s: %v", relPath, srcPath, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("SVN source %s exists but is not a directory: %s", relPath, srcPath)
			}

			if err := copySourceContents(srcPath, targetDir, "SVN", execCtx); err != nil {
				return fmt.Errorf("failed to copy SVN source contents from %s to %s: %v", srcPath, targetDir, err)
			}
			// SVN source handled, move to the next line
			continue

		case isHgSource:
			// HG sources: Source path is the cloned directory in the cache (SourcesDir/pkgName/dirName)
			dirName := hgDirName(relPath)
			srcPath = filepath.Join(srcDir, dirName)

			// Check if source exists
			info, err := os.Stat(srcPath)
			if err != nil {
				return fmt.Errorf("HG source %s listed but missing: stat %s: %v", relPath, srcPath, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("HG source %s exists but is not a directory: %s", relPath, srcPath)
			}

			if err := copySourceContents(srcPath, targetDir, "HG", execCtx); err != nil {
				return fmt.Errorf("failed to copy HG source contents from %s to %s: %v", srcPath, targetDir, err)
			}
			// HG source handled, move to the next line
			continue

		case isUrlSource:
			// Other URL sources (archives): Source path is the symlink in the cache dir (SourcesDir/pkgName/filename)
			filenameOnDisk := filepath.Base(relPath)
			if filenameOverride != "" {
				filenameOnDisk = filenameOverride
			}
			// srcDir is SourcesDir/pkgName. Files are symlinked here by fetchSources.
			srcPath = filepath.Join(srcDir, filenameOnDisk)

		default:
			// Default/Local files: Look up using the provided relPath
			srcPath = filepath.Join(srcDir, relPath)
		}

		// --- All source types are now resolved to a final srcPath (file or directory) ---

		info, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("source %s listed but missing: stat %s: %v", relPath, srcPath, err)
		}

		// At this point, destPath is no longer needed, we use targetDir for destination

		if info.IsDir() {
			// This handles "files/" or other local source directories that need to be copied.
			// Copy directory recursively (this creates a subdirectory, which is the desired behavior for files/)
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := copyDir(srcPath, destPath); err != nil {
				return fmt.Errorf("failed to copy directory %s: %v", relPath, err)
			}
			continue
		}

		// Resolve symlinks (needed for cached archives which are symlinks)
		realPath, err := filepath.EvalSymlinks(srcPath)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink %s: %v", relPath, err)
		}

		// If flagged noextract, just copy the file
		if noExtract {
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %v", destPath, err)
			}
			if err := copyFile(realPath, destPath); err != nil {
				return fmt.Errorf("failed to copy file %s: %v", relPath, err)
			}
			continue
		}

		// Extract archives or copy file (using realPath)
		switch {
		case strings.HasSuffix(realPath, ".tar.gz"),
			strings.HasSuffix(realPath, ".tgz"),
			strings.HasSuffix(realPath, ".tar.xz"),
			strings.HasSuffix(realPath, ".tar.bz2"),
			strings.HasSuffix(realPath, ".tar.zst"),
			strings.HasSuffix(realPath, ".tar.lz"),
			strings.HasSuffix(realPath, ".tar"):
			// Extraction goes into targetDir (buildDir or buildDir/subdir)
			if err := extractTar(realPath, targetDir); err != nil {
				return fmt.Errorf("failed to extract tar %s into %s: %v", relPath, targetDir, err)
			}
		case strings.HasSuffix(realPath, ".zip"):
			// Check if the "unzip" command is available in the system's PATH.
			unzipPath, err := exec.LookPath("unzip")
			if err == nil {
				// If "unzip" is found, use it for extraction.
				cmd := exec.Command(unzipPath, "-q", "-o", realPath, "-d", targetDir)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("failed to unzip %s into %s: %v", relPath, targetDir, err)
				}
			} else {
				// If "unzip" is not found, fall back to the internal Go zip library.
				debugf("unzip command not found, using internal extractor for %s\n", relPath)
				if err := unzipGo(realPath, targetDir); err != nil {
					return fmt.Errorf("internal unzip of %s into %s failed: %v", relPath, targetDir, err)
				}
			}
		default:
			// Copy file (e.g., patches/, simple local files)
			destPath := filepath.Join(targetDir, filepath.Base(relPath))
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				return fmt.Errorf("failed to create parent dir for %s: %v", destPath, err)
			}
			if err := copyFile(realPath, destPath); err != nil {
				return fmt.Errorf("failed to copy file %s: %v", relPath, err)
			}
		}
	}

	return nil
}

func generateLibDeps(outputDir, libdepsFile string, execCtx *Executor) error {
	elfABI := func(fileDesc string) string {
		switch {
		case strings.Contains(fileDesc, "ELF 32-bit"):
			return "elf32"
		case strings.Contains(fileDesc, "ELF 64-bit"):
			return "elf64"
		default:
			return ""
		}
	}

	// --- FIX: Use a privileged 'find' command to discover executable files ---
	var findOutput bytes.Buffer
	// Find files (-type f) with at least one executable bit set (-perm /111)
	findCmd := exec.Command("find", outputDir, "-type", "f", "-perm", "/111")
	findCmd.Stdout = &findOutput
	findCmd.Stderr = io.Discard

	// Must use a privileged executor to find root-owned files
	if err := execCtx.Run(findCmd); err != nil {
		return fmt.Errorf("failed to execute find command to locate executables: %w", err)
	}

	files := strings.Fields(findOutput.String())
	if len(files) == 0 {
		debugf("No executable files found in %s\n", outputDir)
		// Write an empty libdeps file and return successfully
		_ = os.WriteFile(libdepsFile, []byte{}, 0644)
		return nil
	}

	// Build a map of filenames provided by this package to avoid self-dependencies
	providedFiles := make(map[string]struct{})
	var findFilesOutput bytes.Buffer
	findFilesCmd := exec.Command("find", outputDir, "-type", "f")
	findFilesCmd.Stdout = &findFilesOutput
	findFilesCmd.Stderr = io.Discard
	if err := execCtx.Run(findFilesCmd); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(findFilesOutput.Bytes()))
		for scanner.Scan() {
			path := scanner.Text()
			base := filepath.Base(path)
			if pathIs32BitLibrary(path) {
				providedFiles["elf32:"+base] = struct{}{}
			} else {
				providedFiles["elf64:"+base] = struct{}{}
			}
		}
	}

	debugf("Found %d executable files to check for dependencies.\n", len(files))

	type result struct{ libs []string }
	numWorkers := runtime.NumCPU()
	fileCh := make(chan string, len(files))
	resultCh := make(chan result, len(files))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for file := range fileCh {
			var fileOut, readelfOut bytes.Buffer

			// 1. Check if file is an ELF binary (must use a privileged executor)
			cmdFile := exec.Command("file", "--brief", file)
			cmdFile.Stdout = &fileOut
			cmdFile.Stderr = io.Discard

			if err := execCtx.Run(cmdFile); err != nil {
				continue
			}

			fileDesc := fileOut.String()
			if !strings.Contains(fileDesc, "ELF") {
				continue
			}
			abi := elfABI(fileDesc)

			// 2. Run readelf -d to find direct dependencies (must use a privileged executor)
			readelfCmd := exec.Command("readelf", "-d", file)
			readelfCmd.Stdout = &readelfOut
			readelfCmd.Stderr = io.Discard

			if err := execCtx.Run(readelfCmd); err != nil {
				continue
			}

			var libs []string
			scanner := bufio.NewScanner(bytes.NewReader(readelfOut.Bytes()))
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.Contains(line, "(NEEDED)") {
					continue
				}

				// Format: 0x0000000000000001 (NEEDED)             Shared library: [libassuan.so.9]
				idxStart := strings.Index(line, "[")
				idxEnd := strings.Index(line, "]")
				if idxStart != -1 && idxEnd != -1 && idxEnd > idxStart {
					libName := line[idxStart+1 : idxEnd]
					// Filter out libraries provided by this package.
					_, provided := providedFiles[abi+":"+libName]
					if !provided {
						if abi != "" {
							libs = append(libs, abi+":"+libName)
						} else {
							libs = append(libs, libName)
						}
					}
				}
			}

			if len(libs) > 0 {
				resultCh <- result{libs: libs}
			}
		}
	}

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}

	for _, f := range files {
		fileCh <- f
	}
	close(fileCh)

	wg.Wait()
	close(resultCh)

	seen := make(map[string]struct{})
	for res := range resultCh {
		for _, lib := range res.libs {
			seen[lib] = struct{}{}
		}
	}

	// Create a sorted slice for deterministic output
	sortedLibs := make([]string, 0, len(seen))
	for lib := range seen {
		sortedLibs = append(sortedLibs, lib)
	}
	sort.Strings(sortedLibs)

	// --- FIX: Use native os.WriteFile if running as root, otherwise fallback to tee ---
	if len(sortedLibs) > 0 {
		content := strings.Join(sortedLibs, "\n") + "\n"
		if os.Geteuid() == 0 {
			if err := os.WriteFile(libdepsFile, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write libdeps file natively: %w", err)
			}
		} else {
			cmd := exec.Command("tee", libdepsFile)
			cmd.Stdin = strings.NewReader(content)
			cmd.Stdout = io.Discard
			if err := execCtx.Run(cmd); err != nil {
				return fmt.Errorf("failed to write libdeps file via tee: %w", err)
			}
		}
	} else {
		// If there are no dependencies, create an empty file.
		if os.Geteuid() == 0 {
			if err := os.WriteFile(libdepsFile, []byte{}, 0644); err != nil {
				return fmt.Errorf("failed to create empty libdeps file natively: %w", err)
			}
		} else {
			touchCmd := exec.Command("touch", libdepsFile)
			if err := execCtx.Run(touchCmd); err != nil {
				return fmt.Errorf("failed to create empty libdeps file: %w", err)
			}
		}
	}

	debugf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(seen))
	return nil
}

type libDepRef struct {
	ABI  string
	Name string
}

func (d libDepRef) String() string {
	if d.ABI != "" {
		return d.ABI + ":" + d.Name
	}
	return d.Name
}

func parseLibDepRef(line string) (libDepRef, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return libDepRef{}, false
	}
	if abi, name, ok := strings.Cut(line, ":"); ok && (abi == "elf32" || abi == "elf64") && name != "" {
		return libDepRef{ABI: abi, Name: name}, true
	}
	return libDepRef{Name: line}, true
}

type libDepIgnores struct {
	packages map[string]struct{}
	libs     map[string]struct{}
}

func loadLibDepIgnores(path string) libDepIgnores {
	ignores := libDepIgnores{
		packages: make(map[string]struct{}),
		libs:     make(map[string]struct{}),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ignores
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if cut, _, ok := strings.Cut(line, "#"); ok {
			line = strings.TrimSpace(cut)
		}
		if line == "" {
			continue
		}
		if dep, ok := parseLibDepRef(line); ok && (dep.ABI != "" || strings.Contains(dep.Name, ".so")) {
			ignores.libs[dep.String()] = struct{}{}
			continue
		}
		ignores.packages[line] = struct{}{}
	}

	return ignores
}

func (i libDepIgnores) ignoresPackage(pkgName string) bool {
	_, ok := i.packages[pkgName]
	return ok
}

func (i libDepIgnores) ignoresLib(dep libDepRef) bool {
	_, ok := i.libs[dep.String()]
	return ok
}

func pathIs32BitLibrary(path string) bool {
	path = filepath.ToSlash(path)
	return strings.Contains(path, "/lib32/") ||
		strings.Contains(path, "/i686-w64-mingw32/") ||
		strings.Contains(path, "/i686-unknown-linux-gnu/")
}

func isSharedObjectName(name string) bool {
	base := filepath.Base(filepath.ToSlash(name))
	idx := strings.Index(base, ".so")
	if idx == -1 {
		return false
	}
	tail := base[idx+len(".so"):]
	return tail == "" || strings.HasPrefix(tail, ".")
}

func libraryPathMatchesDep(path string, dep libDepRef) bool {
	if dep.Name == "" {
		return false
	}

	path = filepath.ToSlash(path)
	depName := filepath.ToSlash(dep.Name)

	if strings.HasPrefix(depName, "/") {
		if path != depName {
			return false
		}
	} else if filepath.Base(path) != depName {
		return false
	}

	if isSharedObjectName(depName) && !isSharedObjectName(filepath.Base(path)) {
		return false
	}

	switch dep.ABI {
	case "elf32":
		return pathIs32BitLibrary(path)
	case "elf64":
		return !pathIs32BitLibrary(path)
	default:
		return true
	}
}

func splitMetadataCandidates(pkgName, baseName string) []string {
	names := []string{pkgName}
	for _, prefix := range []string{"aarch64-", "x86_64-"} {
		if strings.HasPrefix(pkgName, prefix) {
			names = append(names, strings.TrimPrefix(pkgName, prefix))
			break
		}
	}

	var candidates []string
	seen := make(map[string]bool)
	for _, name := range names {
		for _, candidate := range []string{
			baseName + "." + name,
			filepath.Join("split", name, baseName),
		} {
			if !seen[candidate] {
				candidates = append(candidates, candidate)
				seen[candidate] = true
			}
		}
	}
	candidates = append(candidates, baseName)
	return candidates
}

func findPackageMetadataFile(pkgDir, pkgName, baseName string) string {
	for _, rel := range splitMetadataCandidates(pkgName, baseName) {
		path := filepath.Join(pkgDir, rel)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return path
		}
	}
	return filepath.Join(pkgDir, baseName)
}

func isBootstrapOnlyPackageName(name string) bool {
	return len(name) > 3 &&
		name[0] >= '0' && name[0] <= '9' &&
		name[1] >= '0' && name[1] <= '9' &&
		name[2] == '-'
}

func generateDepends(pkgName, pkgDir, outputDir, rootDir string, execCtx *Executor, bootstrap bool) error {
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	dependsFile := filepath.Join(installedDir, "depends")
	runtimeDBRoot := filepath.Join(rootDir, "var", "db", "hokuto", "installed")
	libDepIgnores := loadLibDepIgnores(findPackageMetadataFile(pkgDir, pkgName, "libdeps.ignore"))

	// Track library dependencies (auto-detected, just package names)
	libDepSet := make(map[string]struct{})
	// Track repo dependencies (from depends file, preserve full specs with version constraints)
	repoDepLines := make(map[string]string) // package name -> full dependency line
	suggestLines := make(map[string]string)
	formatDepLine := func(name, op, ver string) string {
		if op == "" {
			return name
		}
		return name + op + ver
	}
	formatSuggestLine := func(name, op, ver, text string) string {
		line := formatDepLine(name, op, ver) + " suggest"
		if text != "" {
			line += " " + text
		}
		return line
	}
	formatSuggestDep := func(dep DepSpec) string {
		if len(dep.Alternatives) > 1 {
			line := strings.Join(dep.Alternatives, " | ") + " suggest"
			if dep.SuggestText != "" {
				line += " " + dep.SuggestText
			}
			return line
		}
		return formatSuggestLine(dep.Name, dep.Op, dep.Version, dep.SuggestText)
	}
	cleanManualDepName := func(name string) string {
		if isBootstrapOnlyPackageName(name) {
			return ""
		}
		return name
	}

	// --- Part 1: Process automatically detected library dependencies ---
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if libdepsData, err := os.ReadFile(libdepsFile); err == nil {
		var libdeps []libDepRef
		for _, line := range strings.Split(string(libdepsData), "\n") {
			if dep, ok := parseLibDepRef(line); ok {
				if libDepIgnores.ignoresLib(dep) {
					continue
				}
				libdeps = append(libdeps, dep)
			}
		}
		if len(libdeps) > 0 {
			// Scan all installed packages for matching libs
			dbRoot := runtimeDBRoot

			entries, err := os.ReadDir(dbRoot)
			if err != nil {
				return fmt.Errorf("failed to read installed db at %s: %v", dbRoot, err)
			}

			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				otherPkg := e.Name()
				if otherPkg == pkgName {
					continue
				}
				if isBootstrapOnlyPackageName(otherPkg) {
					continue
				}

				// Check if package is marked as binary in options
				otherPkgDir := filepath.Join(dbRoot, otherPkg)
				otherOpts := loadBuildOptions(otherPkgDir)
				if otherOpts["binary"] {
					continue // Skip binary packages (prevent false dependencies)
				}

				manifestFile := filepath.Join(dbRoot, otherPkg, "manifest")
				data, err := os.ReadFile(manifestFile)
				if err != nil {
					continue
				}
				lines := strings.Split(string(data), "\n")

				for _, lib := range libdeps {
					for _, line := range lines {
						// --- FIX: Isolate the path from the checksum/placeholder ---
						// Split the line by whitespace. The path is always the first part.
						fields := strings.Fields(line)
						if len(fields) == 0 {
							// Skip empty or malformed lines
							continue
						}
						pathInManifest := fields[0]

						if libraryPathMatchesDep(pathInManifest, lib) {
							if libDepIgnores.ignoresPackage(otherPkg) {
								break
							}
							libDepSet[otherPkg] = struct{}{}
							break // Found the owner, move to the next library
						}
					}
				}
			}
		}
	}
	// --- End of Part 1 ---

	// --- Part 2: Merge manually specified dependencies from the repo file ---
	// Preserve full dependency specifications including version constraints
	repoDepends := findPackageMetadataFile(pkgDir, pkgName, "depends")
	if data, err := os.ReadFile(repoDepends); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				if strings.Contains(line, "|") {
					deps, err := parseDependsData([]byte(line))
					if err != nil {
						return fmt.Errorf("failed to parse dependencies for %s: %w", pkgName, err)
					}
					if len(deps) > 0 && deps[0].Suggest {
						suggestLines[strings.Join(deps[0].Alternatives, "|")] = formatSuggestDep(deps[0])
						continue
					}
				}

				// Extract package name to use as key in the map
				name, op, ver, optional, rebuild, makeDep, _, _, runtimeOnly, suggest, suggestText := parseDepToken(line)
				if name != "" {
					cleanName := cleanManualDepName(name)
					if cleanName == "" {
						continue
					}
					if cleanName != name {
						name = cleanName
						line = formatDepLine(name, op, ver)
					}

					if suggest {
						suggestLines[name] = formatSuggestLine(name, op, ver, suggestText)
						continue
					}

					// Skip non-runtime dependency hints. If an optional feature is
					// actually linked, libdeps above will add the real runtime owner.
					if makeDep || optional || rebuild {
						continue
					}

					if runtimeOnly {
						line = formatDepLine(name, op, ver)
					}

					// Constrained dependencies may resolve to a parallel-installable
					// ABI package (foo-1 satisfying foo<2). Store that real runtime
					// identity so it deduplicates an auto-detected library owner and
					// does not later request the repository's current foo release.
					if op != "" && ver != "" {
						if resolved := findInstalledSatisfyingIn(runtimeDBRoot, name, op, ver); resolved != "" && resolved != name {
							name = resolved
							line = resolved
						}
					}

					// Store the full line to preserve version constraints
					repoDepLines[name] = line
				}
			}
		}
	}
	// --- End of Part 2 ---

	// --- Part 3: Build the final depends file content ---
	// First, add all repo dependencies (with their full specs)
	var deps []string
	for name, line := range repoDepLines {
		deps = append(deps, line)
		// Remove from libDepSet if it's also a repo dep (repo deps take precedence)
		delete(libDepSet, name)
	}

	// Then, add library-only dependencies (just package names)
	for dep := range libDepSet {
		// Ignore aarch64- and bootstrap-only packages in auto-detected dependencies (Part 1/libdeps)
		// unless they were explicitly listed in the repo depends file (Part 2).
		// repoDepLines packages have already been removed from libDepSet at this point.
		if strings.HasPrefix(dep, "aarch64-") || isBootstrapOnlyPackageName(dep) {
			continue
		}
		deps = append(deps, dep)
	}

	if len(suggestLines) > 0 {
		var suggestions []string
		for _, line := range suggestLines {
			suggestions = append(suggestions, line)
		}
		sort.Strings(suggestions)
		suggestsFile := filepath.Join(installedDir, "suggests")
		content := strings.Join(suggestions, "\n")
		if os.Geteuid() == 0 {
			if err := os.WriteFile(suggestsFile, []byte(content+"\n"), 0644); err != nil {
				return fmt.Errorf("failed to write suggests file natively: %w", err)
			}
		} else {
			cmd := exec.Command("tee", suggestsFile)
			cmd.Stdin = strings.NewReader(content + "\n")
			cmd.Stdout = io.Discard
			if err := execCtx.Run(cmd); err != nil {
				return fmt.Errorf("failed to write suggests file via tee: %w", err)
			}
		}
	}

	// If no dependencies at all, exit early
	if len(deps) == 0 {
		return nil
	}

	// Sort dependencies for consistent output
	sort.Strings(deps)
	content := strings.Join(deps, "\n")

	// --- FIX: Use native os.WriteFile if running as root, otherwise fallback to tee ---
	if os.Geteuid() == 0 {
		if err := os.WriteFile(dependsFile, []byte(content+"\n"), 0644); err != nil {
			return fmt.Errorf("failed to write depends file natively: %w", err)
		}
	} else {
		cmd := exec.Command("tee", dependsFile)
		cmd.Stdin = strings.NewReader(content + "\n")
		cmd.Stdout = io.Discard
		if err := execCtx.Run(cmd); err != nil {
			return fmt.Errorf("failed to write depends file via tee: %w", err)
		}
	}

	return nil
}

// isDirectoryPrivileged uses the Executor to check if a path is a directory.
// helper for listOutputFilesWithTypes

func executePostInstall(pkgName, rootDir string, execCtx *Executor, cfg *Config, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}

	// absolute path inside the chroot
	const relScript = "/var/db/hokuto/installed"
	scriptPath := filepath.Join(relScript, pkgName, "post-install")
	// Construct host path by joining rootDir with the relative portion (without leading slash)
	hostScript := filepath.Join(rootDir, strings.TrimPrefix(scriptPath, "/"))

	// nothing to do if the file doesn't exist on host
	if fi, err := os.Stat(hostScript); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat post-install script %s: %v", hostScript, err)
	} else if fi.IsDir() {
		return fmt.Errorf("post-install path %s is a directory", hostScript)
	}

	var cmd *exec.Cmd
	if rootDir == "/" {
		cmd = exec.Command(hostScript)
	} else {
		// run the same absolute path inside the chroot
		cmd = exec.Command("chroot", rootDir, scriptPath)
	}

	// Inject MULTILIB environment variable
	cmd.Env = os.Environ() // Start with system environment
	if cfg.Values["HOKUTO_MULTILIB"] == "1" {
		cmd.Env = append(cmd.Env, "MULTILIB=1")
	}

	// Get the user who invoked sudo (SUDO_USER) or current user
	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		realUser = os.Getenv("USER")
	}
	cmd.Env = append(os.Environ(), fmt.Sprintf("HOKUTO_REAL_USER=%s", realUser))

	if logger != nil {
		cmd.Stdout = logger
		cmd.Stderr = logger
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if execCtx.Interactive {
		cmd.Stdin = os.Stdin
	} else {
		cmd.Stdin = nil
	}

	// If chroot is used, we must mount communicating filesystems (/dev, /proc, /sys)
	// to ensure scripts like make-ca (which interacts with /dev/stdin) work correctly.
	if rootDir != "/" {
		mounts := []struct {
			src     string
			dst     string
			fsType  string
			options []string
			isBind  bool
		}{
			{src: "/dev", dst: filepath.Join(rootDir, "dev"), isBind: true},
			{src: "proc", dst: filepath.Join(rootDir, "proc"), fsType: "proc"},
			{src: "sysfs", dst: filepath.Join(rootDir, "sys"), fsType: "sysfs"},
		}

		var mountedPaths []string

		// Ensure cleanup happens even if execution fails
		defer func() {
			if len(mountedPaths) > 0 {
				execCtx.UnmountFilesystems(mountedPaths)
			}
		}()

		for _, m := range mounts {
			// Create mountpoint
			// We use a simple MkdirAll here. Ideally we should use privileged execution if needed,
			// but since mounting requires root, we assume we can create dirs in rootDir too (or mount will fail).
			// Use RootExec-like logic or just rely on mount failing if dir missing?
			// Best to try creating it.
			if err := execCtx.Run(exec.Command("mkdir", "-p", m.dst)); err != nil {
				debugf("Warning: failed to create mountpoint %s: %v\n", m.dst, err)
				continue
			}

			var mCmd *exec.Cmd
			if m.isBind {
				mCmd = exec.Command("mount", "--bind", m.src, m.dst)
			} else {
				mCmd = exec.Command("mount", "-t", m.fsType, m.src, m.dst)
			}

			if err := execCtx.Run(mCmd); err != nil {
				debugf("Warning: failed to mount %s to %s: %v\n", m.src, m.dst, err)
			} else {
				mountedPaths = append(mountedPaths, m.dst)
			}
		}

		if err := execCtx.Run(cmd); err != nil {
			fmt.Fprintf(logger, "Warning: chroot to %s failed or post-install could not run: %v\n", rootDir, err)
			return nil
		}
		return nil
	}

	if err := execCtx.Run(cmd); err != nil {
		return fmt.Errorf("post-install script %s failed: %v", hostScript, err)
	}
	return nil
}

func getPackageDependenciesToUninstall(name string) []string {
	switch name {
	case "gcc":
		return []string{"02-gcc-1", "20-gcc-2", "05-libstdc++"}
	case "binutils":
		return []string{"01-binutils-1", "19-binutils-2"}
	case "m4":
		return []string{"06-m4"}
	case "ncurses":
		return []string{"07-ncurses"}
	case "bash":
		return []string{"08-bash"}
	case "coreutils":
		return []string{"09-coreutils"}
	case "diffutils":
		return []string{"10-diffutils"}
	case "file":
		return []string{"11-file"}
	case "findutils":
		return []string{"12-findutils"}
	case "gawk":
		return []string{"13-gawk"}
	case "grep":
		return []string{"14-grep"}
	case "gzip":
		return []string{"15-gzip"}
	case "make":
		return []string{"16-make"}
	case "patch":
		return []string{"17-patch"}
	case "sed":
		return []string{"18-sed"}
	case "hokuto":
		return []string{"21-hokuto"}
	case "nano":
		return []string{"23-nano"}
	case "bzip2":
		return []string{"24-bzip2"}
	case "mingw":
		return []string{"mingw-headers"}
	case "mingw-gcc":
		return []string{"mingw-gcc-static"}
	case "cython":
		return []string{name}
	case "dbus-python":
		return []string{name}
	case "meson":
		return []string{name}
	case "libvirt-python":
		return []string{name}
	case "protontricks":
		return []string{name}
	case "pyqt-build":
		return []string{name}
	case "refind-btrfs":
		return []string{name}
	case "streamlink":
		return []string{name}
	case "umu-launcher":
		return []string{name}
	case "btrfs-progs":
		return []string{name}
	case "arandr":
		return []string{name}
	case "cursor":
		return []string{name}
	case "kapidox":
		return []string{name}
	case "mercurial":
		return []string{name}
	case "pdfarranger":
		return []string{name}
	default:
		if strings.HasPrefix(name, "python-") || strings.HasPrefix(name, "cython-") {
			return []string{name}
		}
		return nil // No dependencies to uninstall
	}
}

// handlePreInstallUninstall checks for and removes packages that must be uninstalled
// before a new package can be installed. It now verifies packages are installed
// before attempting removal.
// forceYes: if true, skips the confirmation prompt.
func handlePreInstallUninstall(pkgName string, cfg *Config, execCtx *Executor, forceYes bool, logger io.Writer) {
	if logger == nil {
		logger = os.Stdout
	}
	// 1. Check if a -bin version of this package is already installed
	// (e.g., if we are installing 'make', check for 'make-bin')
	binPkgName := pkgName + "-bin"
	if !strings.HasSuffix(pkgName, "-bin") && checkPackageExactMatch(binPkgName) {
		shouldUninstall := forceYes
		if !shouldUninstall {
			shouldUninstall = askForConfirmation(colWarn, "-> Uninstall conflicting package '%s'?", binPkgName)
		}

		if shouldUninstall {
			// In parallel mode (forceYes=true), we might not want to print interactive prompts,
			// but we still print status.
			// If forceYes implies skipping prompt, we proceed.
			if err := pkgUninstall(binPkgName, cfg, execCtx, true, true, logger); err != nil {
				cPrintf(colWarn, "Warning: failed to uninstall conflicting package %s: %v\n", binPkgName, err)
			} else {
				fcPrintf(logger, colArrow, "-> ")
				fcPrintf(logger, colSuccess, "Uninstalled conflicting package %s successfully.\n", binPkgName)
				removeFromWorld(binPkgName)
			}
		}
	}

	potentialDepsToUninstall := getPackageDependenciesToUninstall(pkgName)

	// --- FIX: Filter the list to only include packages that are actually installed ---
	var depsToActuallyUninstall []string
	if len(potentialDepsToUninstall) > 0 {
		for _, dep := range potentialDepsToUninstall {
			// Use the existing silent check to see if the package is installed.
			if checkPackageExactMatch(dep) {
				depsToActuallyUninstall = append(depsToActuallyUninstall, dep)
			}
		}
	}

	// --- Now, only proceed if there are real packages to uninstall ---
	if len(depsToActuallyUninstall) > 0 {
		// Only print if not in parallel/force mode to avoid terminal clutter
		if !forceYes || logger == os.Stdout {
			fcPrintf(logger, colArrow, "-> ")
			// The message is now more accurate, as it only lists packages we KNOW are installed.
			fcPrintf(logger, colSuccess, "Uninstalling")
			fcPrintf(logger, colNote, " %v", strings.Join(depsToActuallyUninstall, ", "))
			fcPrintf(logger, colSuccess, " to avoid install conflicts\n")
		}

		removingSet := make(map[string]bool, len(depsToActuallyUninstall))
		for _, dep := range depsToActuallyUninstall {
			removingSet[dep] = true
		}

		for _, dep := range depsToActuallyUninstall {
			// Use force and yes flags to ensure silent, non-interactive uninstallation.
			if err := pkgUninstallWithRemovalSet(dep, cfg, execCtx, true, true, logger, removingSet); err != nil {
				// This is a non-fatal warning. The installation should proceed.
				debugf("Warning: failed to uninstall conflicting package %s: %v\n", dep, err)
			} else {
				debugf("Uninstalled conflicting package %s successfully.\n", dep)
			}
		}
	}
}

// prepareVersionedPackage handles package requests with a version (e.g., pkg@1.0.0).
// It searches the Git history for the specified version, extracts the package files
// to a temporary directory, and sets an override in versionedPkgDirs.
func prepareVersionedPackage(arg string) (string, error) {
	if !strings.Contains(arg, "@") {
		return arg, nil
	}
	parts := strings.SplitN(arg, "@", 2)
	pkgName := parts[0]
	targetVersionStr := parts[1]

	// Parse operator and version from targetVersionStr
	// e.g. "<=5.0.0" -> op="<=", ver="5.0.0"
	// e.g. "5.0.0" -> op="", ver="5.0.0" (implied ==)
	op := ""
	ver := targetVersionStr
	ops := []string{"<=", ">=", "==", "<", ">"}
	for _, o := range ops {
		if strings.HasPrefix(targetVersionStr, o) {
			op = o
			ver = strings.TrimPrefix(targetVersionStr, o)
			break
		}
	}
	// If no operator found, assume exact match if it looks like a version,
	// but if it was passed without one, we treat it as strict string equality
	// unless we want to enforce "==" logic. Using versionSatisfies with "=="
	// is robust.
	if op == "" {
		op = "=="
	}

	// 1. Find the current package directory to identify the repo
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return arg, fmt.Errorf("could not find base package %s: %w", pkgName, err)
	}

	// 2. Identify the Git root and relative path
	gitRootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	gitRootCmd.Dir = pkgDir
	gitRootOut, err := gitRootCmd.Output()
	if err != nil {
		return arg, fmt.Errorf("package directory %s is not in a Git repository: %w", pkgDir, err)
	}
	gitRoot := strings.TrimSpace(string(gitRootOut))

	relPath, err := filepath.Rel(gitRoot, pkgDir)
	if err != nil {
		return arg, fmt.Errorf("failed to determine relative path for package: %w", err)
	}

	// 3. Search Git history for the newest commit that has this version
	// We list all commits that touched the package directory, newest first.
	logCmd := exec.Command("git", "log", "--all", "--format=%H", "--", relPath)
	logCmd.Dir = gitRoot
	logOut, err := logCmd.Output()
	if err != nil {
		return arg, fmt.Errorf("failed to search git history for %s: %w", arg, err)
	}

	commits := strings.Fields(string(logOut))
	var foundCommit string
	var foundVersion string
	for _, commit := range commits {
		// Check the version file at this commit
		showCmd := exec.Command("git", "show", fmt.Sprintf("%s:%s/version", commit, relPath))
		showCmd.Dir = gitRoot
		showOut, err := showCmd.Output()
		if err != nil {
			continue
		}
		fields := strings.Fields(string(showOut))
		if len(fields) > 0 {
			commitVer := fields[0]
			// Check if this version satisfies the constraint
			if versionSatisfies(commitVer, op, ver) {
				foundCommit = commit
				foundVersion = commitVer
				break
			}
		}
	}

	if foundCommit == "" {
		return arg, fmt.Errorf("version %s for package %s not found in Git history", targetVersionStr, pkgName)
	}

	// Rename the package to pkgname-MAJOR for parallel version installation
	major := strings.Split(foundVersion, ".")[0]
	renamedPkgName := pkgName
	if major != "" {
		suffix := "-" + major
		if !strings.HasSuffix(pkgName, suffix) {
			renamedPkgName = fmt.Sprintf("%s-%s", pkgName, major)
		}
	}

	// 4. Extract the package files from the commit
	tmpBase := filepath.Join(HokutoTmpDir, "tmprepo")
	os.MkdirAll(tmpBase, 0o755)

	finalTmpDir := filepath.Join(tmpBase, fmt.Sprintf("%s-%s-%s", pkgName, ver, foundCommit[:8]))
	// If already extracted, we can reuse it
	if _, err := os.Stat(finalTmpDir); err == nil {
		versionedPkgDirs[renamedPkgName] = finalTmpDir
		return renamedPkgName, nil
	}

	if err := os.MkdirAll(finalTmpDir, 0755); err != nil {
		return arg, fmt.Errorf("failed to create temporary directory %s: %w", finalTmpDir, err)
	}

	// 5. Extract all tracked files using git ls-tree and git show
	// This avoids issues with .gitattributes export-ignore or archive settings.
	lsCmd := exec.Command("git", "ls-tree", "-r", foundCommit+":"+relPath)
	lsCmd.Dir = gitRoot
	lsOut, err := lsCmd.Output()
	if err != nil {
		return arg, fmt.Errorf("failed to list files in git history for %s: %w", relPath, err)
	}

	// Check if git-lfs is available for resolving LFS pointers
	hasGitLFS := false
	if _, lfsErr := exec.LookPath("git-lfs"); lfsErr == nil {
		hasGitLFS = true
	}

	scanner := bufio.NewScanner(bytes.NewReader(lsOut))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: <mode> <type> <hash>\t<file>
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) < 2 {
			continue
		}
		infoFields := strings.Fields(parts[0])
		if len(infoFields) < 3 {
			continue
		}
		modeStr := infoFields[0]
		fileName := parts[1]

		targetFilePath := filepath.Join(finalTmpDir, fileName)
		os.MkdirAll(filepath.Dir(targetFilePath), 0o755)

		showCmd := exec.Command("git", "show", fmt.Sprintf("%s:%s/%s", foundCommit, relPath, fileName))
		showCmd.Dir = gitRoot

		outF, err := os.Create(targetFilePath)
		if err != nil {
			return arg, fmt.Errorf("failed to create file %s: %w", targetFilePath, err)
		}

		showCmd.Stdout = outF
		if err := showCmd.Run(); err != nil {
			outF.Close()
			return arg, fmt.Errorf("failed to extract file %s from git: %w", fileName, err)
		}
		outF.Close()

		// Check if the extracted file is a Git LFS pointer and resolve it
		if hasGitLFS {
			if isLFSPointer(targetFilePath) {
				debugf("Resolving LFS pointer for %s\n", fileName)
				if err := smudgeLFSFile(targetFilePath, gitRoot); err != nil {
					colWarn.Printf("Warning: failed to resolve LFS file %s: %v\n", fileName, err)
				}
			}
		}

		// Set execution bits if the file was executable in Git
		// Git file modes: 100644 (normal), 100755 (executable)
		if modeStr == "100755" {
			os.Chmod(targetFilePath, 0o755)
		} else {
			os.Chmod(targetFilePath, 0o644)
		}
	}

	if err := scanner.Err(); err != nil {
		return arg, fmt.Errorf("error reading git ls-tree output: %w", err)
	}

	versionedPkgDirs[renamedPkgName] = finalTmpDir
	colArrow.Print("-> ")
	colSuccess.Printf("Extracted %s@%s (as %s) from commit %s into temporary directory\n", pkgName, foundVersion, renamedPkgName, foundCommit[:8])

	return renamedPkgName, nil
}

// deriveVersionedPackageDir attempts to find the sources for an installed package
// by deriving its original versioned request (e.g., pkg@1.2.3 from pkg-1).
// Returns the directory path if successful, and a boolean indicating success.
func deriveVersionedPackageDir(pkgName string) (string, bool) {
	installedVersionFile := filepath.Join(Installed, pkgName, "version")
	data, err := os.ReadFile(installedVersionFile)
	if err != nil {
		return "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", false
	}
	ver := fields[0]
	major := strings.Split(ver, ".")[0]
	if major != "" && strings.HasSuffix(pkgName, "-"+major) {
		baseName := strings.TrimSuffix(pkgName, "-"+major)
		req := fmt.Sprintf("%s@%s", baseName, ver)
		debugf("Attempting to derive sources for %s using request %s\n", pkgName, req)

		// Use prepareVersionedPackage to get the temp dir
		newPkgName, err := prepareVersionedPackage(req)
		if err == nil {
			if dir, ok := versionedPkgDirs[newPkgName]; ok {
				return dir, true
			}
		} else {
			debugf("Failed to prepare derived request %s: %v\n", req, err)
		}
	}
	return "", false
}

// isLFSPointer checks if a file is a Git LFS pointer by reading its first line.
// LFS pointers start with "version https://git-lfs.github.com/spec/v1".
func isLFSPointer(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	// LFS pointers are small text files (typically ~130 bytes).
	// Read just enough to check the header.
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}
	return strings.HasPrefix(string(buf[:n]), "version https://git-lfs.github.com/spec/v1")
}

// smudgeLFSFile resolves a Git LFS pointer file to its actual content.
// It reads the pointer, pipes it through "git lfs smudge", and overwrites
// the file with the real content.
func smudgeLFSFile(filePath, gitRoot string) error {
	// Read the LFS pointer content
	pointerData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read LFS pointer: %w", err)
	}

	// Run git lfs smudge with the pointer as stdin
	smudgeCmd := exec.Command("git", "lfs", "smudge")
	smudgeCmd.Dir = gitRoot
	smudgeCmd.Stdin = bytes.NewReader(pointerData)

	var out bytes.Buffer
	var errBuf bytes.Buffer
	smudgeCmd.Stdout = &out
	smudgeCmd.Stderr = &errBuf

	if err := smudgeCmd.Run(); err != nil {
		return fmt.Errorf("git lfs smudge failed: %w (%s)", err, errBuf.String())
	}

	// Overwrite the pointer file with the actual content
	if err := os.WriteFile(filePath, out.Bytes(), 0o644); err != nil {
		return fmt.Errorf("failed to write resolved LFS content: %w", err)
	}

	return nil
}
