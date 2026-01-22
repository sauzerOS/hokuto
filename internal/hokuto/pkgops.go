package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

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

			// ACTION: Copy CONTENTS of srcPath into targetDir
			// We use rsync -a src/ dest/ to copy contents without creating a subdir
			rsyncCmd := exec.Command("rsync", "-a", srcPath+"/", targetDir)
			if err := execCtx.Run(rsyncCmd); err != nil {
				return fmt.Errorf("failed to copy git source contents from %s to %s: %v", srcPath, targetDir, err)
			}
			// Git source handled, move to the next line
			continue

		case isUrlSource:
			// Other URL sources (archives): Source path is the symlink in the cache dir (SourcesDir/pkgName/filename)
			urlPath, err := url.Parse(relPath)
			if err != nil {
				return fmt.Errorf("invalid URL in sources file: %v", err)
			}
			filenameOnDisk := filepath.Base(urlPath.Path)
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
	ignorePatterns := []string{
		"ld-*", "libc.so*", "libm.so*", "libpthread.so*", "libdl.so*",
		"libgcc_s.so*", "libstdc++.so*", "libcrypt.so*", "libc++.so*",
		"libc++abi.so*", "libmvec.so*", "libresolv.so*", "librt.so*",
		"libtrace.so*", "libunwind.so*", "libutil.so*", "libxnet.so*", "ldd",
	}

	matchesIgnore := func(lib string) bool {
		for _, pat := range ignorePatterns {
			if ok, _ := filepath.Match(pat, filepath.Base(lib)); ok {
				return true
			}
		}
		return false
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

	debugf("Found %d executable files to check for dependencies.\n", len(files))

	type result struct{ libs []string }
	numWorkers := runtime.NumCPU()
	fileCh := make(chan string, len(files))
	resultCh := make(chan result, len(files))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for file := range fileCh {
			var fileOut, lddOut bytes.Buffer

			// 1. Check if file is an ELF binary (must use a privileged executor)
			cmdFile := exec.Command("file", "--brief", file)
			cmdFile.Stdout = &fileOut
			cmdFile.Stderr = io.Discard

			if err := execCtx.Run(cmdFile); err != nil {
				continue
			}

			if !strings.Contains(fileOut.String(), "ELF") {
				continue
			}

			// 2. Run ldd to find dependencies (must use a privileged executor)
			lddCmd := exec.Command("ldd", file)
			lddCmd.Stdout = &lddOut
			lddCmd.Stderr = io.Discard

			if err := execCtx.Run(lddCmd); err != nil {
				continue
			}

			var libs []string
			scanner := bufio.NewScanner(bytes.NewReader(lddOut.Bytes()))
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Fields(line)
				if len(parts) >= 3 && parts[1] == "=>" {
					libPath := parts[2]
					if strings.HasPrefix(libPath, "/") &&
						!strings.HasPrefix(libPath, outputDir) &&
						!matchesIgnore(libPath) {
						libs = append(libs, filepath.Base(libPath))
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

	// --- FIX: Use a privileged 'tee' command to write the file ---
	// This ensures the write succeeds even if the staging directory is root-owned (from an asroot build).
	if len(sortedLibs) > 0 {
		content := strings.Join(sortedLibs, "\n") + "\n"
		cmd := exec.Command("tee", libdepsFile)
		cmd.Stdin = strings.NewReader(content)
		// Discard tee's stdout to prevent it from printing the content to the console.
		cmd.Stdout = io.Discard

		// Use the privileged RootExec to ensure the write is successful.
		if err := execCtx.Run(cmd); err != nil {
			return fmt.Errorf("failed to write libdeps file via tee: %w", err)
		}
	} else {
		// If there are no dependencies, create an empty file.
		touchCmd := exec.Command("touch", libdepsFile)
		if err := execCtx.Run(touchCmd); err != nil {
			return fmt.Errorf("failed to create empty libdeps file: %w", err)
		}
	}

	debugf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(seen))
	return nil
}

func generateDepends(pkgName, pkgDir, outputDir, rootDir string, execCtx *Executor, bootstrap bool) error {
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	dependsFile := filepath.Join(installedDir, "depends")

	// Track library dependencies (auto-detected, just package names)
	libDepSet := make(map[string]struct{})
	// Track repo dependencies (from depends file, preserve full specs with version constraints)
	repoDepLines := make(map[string]string) // package name -> full dependency line

	// --- Part 1: Process automatically detected library dependencies ---
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if libdepsData, err := os.ReadFile(libdepsFile); err == nil {
		libdeps := strings.Fields(string(libdepsData))
		if len(libdeps) > 0 {
			// Scan all installed packages for matching libs
			dbRoot := filepath.Join(rootDir, "var", "db", "hokuto", "installed")

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

						// Now, check the suffix of the path, not the whole line.
						if strings.HasSuffix(pathInManifest, lib) {
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
	repoDepends := filepath.Join(pkgDir, "depends")
	if data, err := os.ReadFile(repoDepends); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				// Extract package name to use as key in the map
				name, op, ver, optional, rebuild, makeDep := parseDepToken(line)
				if name != "" {
					// Skip build-time only dependencies
					if makeDep {
						continue
					}

					if !bootstrap {
						// Cleanup bootstrap names in normal mode
						if name == "19-binutils-2" {
							continue
						}

						newName := ""
						switch name {
						case "08-bash":
							newName = "bash"
						case "11-file":
							newName = "file"
						case "07-ncurses":
							newName = "ncurses"
						}

						if newName != "" {
							// Rebuild the line with the new name but preserve everything else
							line = newName
							if op != "" {
								line += op + ver
							}
							if optional {
								line += " optional"
							}
							if rebuild {
								line += " rebuild"
							}
							name = newName // update key for the map
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
		// Also apply cleanup to auto-detected library dependencies if in normal mode
		if !bootstrap {
			if dep == "19-binutils-2" {
				continue
			}
			switch dep {
			case "08-bash":
				dep = "bash"
			case "11-file":
				dep = "file"
			case "07-ncurses":
				dep = "ncurses"
			}
		}
		deps = append(deps, dep)
	}

	// If no dependencies at all, exit early
	if len(deps) == 0 {
		return nil
	}

	// Sort dependencies for consistent output
	sort.Strings(deps)
	content := strings.Join(deps, "\n")

	// --- FIX: Use a privileged 'tee' command to write the depends file ---
	// This ensures the write succeeds even in a root-owned staging directory.
	cmd := exec.Command("tee", dependsFile)
	cmd.Stdin = strings.NewReader(content + "\n")
	cmd.Stdout = io.Discard // Don't print the file content to the console

	// Use RootExec, which is guaranteed to have the necessary permissions.
	if err := execCtx.Run(cmd); err != nil {
		return fmt.Errorf("failed to write depends file via tee: %w", err)
	}

	return nil
}

// isDirectoryPrivileged uses the Executor to check if a path is a directory.
// helper for listOutputFiles

func executePostInstall(pkgName, rootDir string, execCtx *Executor, cfg *Config) error {

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

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// If chroot is used and fails, print a warning and continue (non-fatal).
	if rootDir != "/" {
		if err := execCtx.Run(cmd); err != nil {
			cPrintf(colWarn, "Warning: chroot to %s failed or post-install could not run: %v\n", rootDir, err)
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
	case "linux-headers":
		return []string{"03-linux-headers"}
	case "mingw":
		return []string{"mingw-headers"}
	case "mingw-gcc":
		return []string{"mingw-gcc-static"}
	case "m4":
		return []string{"06-m4"}
	case "ncurses":
		return []string{"07-ncurses"}
	case "bash":
		return []string{"08-bash"}
	case "diffutils":
		return []string{"10-diffutils"}
	case "file":
		return []string{"11-file"}
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

func handlePreInstallUninstall(pkgName string, cfg *Config, execCtx *Executor) {
	// 1. Check if a -bin version of this package is already installed
	// (e.g., if we are installing 'make', check for 'make-bin')
	binPkgName := pkgName + "-bin"
	if !strings.HasSuffix(pkgName, "-bin") && checkPackageExactMatch(binPkgName) {
		if askForConfirmation(colWarn, "-> Uninstall conflicting package '%s'?", binPkgName) {
			if err := pkgUninstall(binPkgName, cfg, execCtx, true, true); err != nil {
				cPrintf(colWarn, "Warning: failed to uninstall conflicting package %s: %v\n", binPkgName, err)
			} else {
				colArrow.Print("-> ")
				colSuccess.Printf("Uninstalled conflicting package %s successfully.\n", binPkgName)
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
		colArrow.Print("-> ")
		// The message is now more accurate, as it only lists packages we KNOW are installed.
		colSuccess.Printf("Uninstalling")
		colNote.Printf(" %v", strings.Join(depsToActuallyUninstall, ", "))
		colSuccess.Printf(" to avoid install conflicts\n")

		for _, dep := range depsToActuallyUninstall {
			// Use force and yes flags to ensure silent, non-interactive uninstallation.
			if err := pkgUninstall(dep, cfg, execCtx, true, true); err != nil {
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
		renamedPkgName = fmt.Sprintf("%s-%s", pkgName, major)
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
