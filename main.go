package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

const (
	CacheDir   = "/var/cache/hokuto"
	SourcesDir = CacheDir + "/sources"
	BinDir     = CacheDir + "/bin"
	CacheStore = SourcesDir + "/_cache"
	Installed  = "/var/db/hokuto/installed"
	ConfigFile = "/etc/hokuto.conf"
)

// Config struct
type Config struct {
	Values map[string]string
}

// Load /etc/hokuto.conf and apply defaults
func loadConfig(path string) (*Config, error) {
	cfg := &Config{Values: make(map[string]string)}

	// Attempt to read the file
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)
			cfg.Values[key] = val
		}
		if err := scanner.Err(); err != nil {
			return cfg, err
		}
	}

	// Merge HOKUTO_* env overrides
	mergeEnvOverrides(cfg)

	// Ensure TMPDIR has a default
	if tmp := cfg.Values["TMPDIR"]; tmp == "" {
		cfg.Values["TMPDIR"] = "/tmp"
	}

	return cfg, nil
}

// Merge HOKUTO_* env overrides
func mergeEnvOverrides(cfg *Config) {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "HOKUTO_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				cfg.Values[parts[0]] = parts[1]
			}
		}
	}
}

// List installed packages with version
func listPackages(pkgName string) error {
	var pkgs []string
	if pkgName != "" {
		if _, err := os.Stat(filepath.Join(Installed, pkgName)); err == nil {
			pkgs = []string{pkgName}
		} else {
			return fmt.Errorf("package not found: %s", pkgName)
		}
	} else {
		entries, err := os.ReadDir(Installed)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				pkgs = append(pkgs, e.Name())
			}
		}
	}
	for _, p := range pkgs {
		versionFile := filepath.Join(Installed, p, "version")
		version := "unknown"
		if data, err := os.ReadFile(versionFile); err == nil {
			version = strings.TrimSpace(string(data))
		}
		fmt.Printf("%s %s\n", p, version)
	}
	return nil
}

// Hashing helper for cached filenames
func hashString(s string) string {
	cmd := exec.Command("b3sum")
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.Output()
	if err != nil {
		return "hashfail"
	}
	return strings.Fields(string(out))[0]
}

// downloadFile downloads a URL into the hokuto cache
func downloadFile(url, destFile string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(CacheStore, 0o755); err != nil {
		return err
	}

	// destFile is the filename only (without path)
	destFile = filepath.Base(destFile)
	fmt.Printf("Downloading %s -> %s/%s\n", url, CacheStore, destFile)

	// Try aria2c first
	cmd := exec.Command("aria2c", "-x", "4", "-s", "4", "-d", CacheStore, "-o", destFile, url)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("aria2c failed, falling back to curl")

		absPath := filepath.Join(CacheStore, destFile)
		cmd = exec.Command("curl", "-L", "-o", absPath, url)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return nil
}

// Fetch sources (HTTP/FTP + Git)
func fetchSources(pkgName, pkgDir string) error {
	data, err := os.ReadFile(filepath.Join(pkgDir, "sources"))
	if err != nil {
		return fmt.Errorf("could not read sources file: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	pkgLinkDir := filepath.Join(SourcesDir, pkgName)

	if err := os.MkdirAll(pkgLinkDir, 0o755); err != nil {
		return fmt.Errorf("failed to create pkg source dir: %v", err)
	}
	if err := os.MkdirAll(CacheStore, 0o755); err != nil {
		return fmt.Errorf("failed to create _cache dir: %v", err)
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip local files
		if strings.HasPrefix(line, "files/") {
			continue
		}

		if strings.HasPrefix(line, "git+") {
			// Git repo handling (unchanged)
			gitURL := strings.TrimPrefix(line, "git+")
			ref := ""
			if strings.Contains(gitURL, "#") {
				parts := strings.SplitN(gitURL, "#", 2)
				gitURL = parts[0]
				ref = parts[1]
			}
			parts := strings.Split(strings.TrimSuffix(gitURL, ".git"), "/")
			repoName := parts[len(parts)-1]
			destPath := filepath.Join(pkgLinkDir, repoName)

			if _, err := os.Stat(destPath); os.IsNotExist(err) {
				fmt.Printf("Cloning git repository %s into %s\n", gitURL, destPath)
				cmd := exec.Command("git", "clone", gitURL, destPath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("git clone failed: %v", err)
				}
			} else if ref == "" {
				cmd := exec.Command("git", "-C", destPath, "pull")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}

			// Disable detached HEAD advice
			exec.Command("git", "-C", destPath, "config", "advice.detachedHead", "false").Run()

			if ref != "" {
				checkBranch := exec.Command("git", "-C", destPath, "rev-parse", "--verify", "refs/heads/"+ref)
				if err := checkBranch.Run(); err == nil {
					// branch → checkout + pull
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
					cmd = exec.Command("git", "-C", destPath, "pull")
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				} else {
					// tag/commit → checkout only
					cmd := exec.Command("git", "-C", destPath, "checkout", ref)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Run()
				}
			}
			fmt.Printf("Git repository ready: %s\n", destPath)
			continue
		}

		// HTTP/FTP sources
		parts := strings.Split(line, "/")
		origFilename := parts[len(parts)-1]
		hashName := fmt.Sprintf("%s-%s", hashString(line+origFilename), origFilename)
		cachePath := filepath.Join(CacheStore, hashName)

		if _, err := os.Stat(cachePath); os.IsNotExist(err) {
			if err := downloadFile(line, cachePath); err != nil {
				return fmt.Errorf("failed to download %s: %v", line, err)
			}
		} else {
			fmt.Printf("Already in cache: %s\n", cachePath)
		}

		linkPath := filepath.Join(pkgLinkDir, origFilename)
		if _, err := os.Lstat(linkPath); err == nil {
			os.Remove(linkPath)
		}
		if err := os.Symlink(cachePath, linkPath); err != nil {
			return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, linkPath, err)
		}
		fmt.Printf("Linked %s -> %s\n", linkPath, cachePath)
	}

	return nil
}

func verifyOrCreateChecksums(pkgName, pkgDir string) error {
	pkgSrcDir := filepath.Join(SourcesDir, pkgName)
	checksumFile := filepath.Join(pkgDir, "checksums") // repo package dir

	existing := make(map[string]string)
	if f, err := os.Open(checksumFile); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				existing[parts[1]] = parts[0]
			} else {
				existing["single"] = parts[0]
			}
		}
		f.Close()
	}

	files, err := os.ReadDir(pkgSrcDir)
	if err != nil {
		return fmt.Errorf("cannot read source dir: %v", err)
	}

	var summary []string
	var updatedChecksums []string

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		filePath := filepath.Join(pkgSrcDir, f.Name())

		hashValid := false
		mismatch := false
		skipped := false

		if oldSum, ok := existing[f.Name()]; ok {
			cmd := exec.Command("b3sum", "-c")
			cmd.Stdin = strings.NewReader(fmt.Sprintf("%s  %s\n", oldSum, filePath))
			if err := cmd.Run(); err == nil {
				hashValid = true
			} else {
				mismatch = true
			}
		}

		if mismatch {
			fmt.Printf("Checksum mismatch for %s. Redownload and regenerate checksum? [y/N]: ", f.Name())
			var response string
			fmt.Scanln(&response)
			if strings.ToLower(strings.TrimSpace(response)) == "y" {
				// Redownload
				sourceLines, _ := os.ReadFile(filepath.Join(pkgDir, "sources"))
				for _, line := range strings.Split(string(sourceLines), "\n") {
					if strings.Contains(line, f.Name()) {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}

						// Compute hash filename for _cache
						hashName := fmt.Sprintf("%s-%s", hashString(line+f.Name()), f.Name())
						cachePath := filepath.Join(CacheStore, hashName)

						// Remove old cache file if exists
						if _, err := os.Stat(cachePath); err == nil {
							os.Remove(cachePath)
						}

						// Remove old symlink/file in source dir
						if _, err := os.Lstat(filePath); err == nil {
							os.Remove(filePath)
						}

						// Download into _cache
						if err := downloadFile(line, cachePath); err != nil {
							return fmt.Errorf("failed to redownload %s: %v", f.Name(), err)
						}

						// Create symlink in pkg dir
						if err := os.Symlink(cachePath, filePath); err != nil {
							return fmt.Errorf("failed to symlink %s -> %s: %v", cachePath, filePath, err)
						}

						hashValid = false // recompute checksum
					}
				}
			} else {
				fmt.Printf("Skipping update for %s\n", f.Name())
				// Remove invalid symlink
				if _, err := os.Lstat(filePath); err == nil {
					os.Remove(filePath)
				}

				// Remove cache file as well
				sourceLines, _ := os.ReadFile(filepath.Join(pkgDir, "sources"))
				for _, line := range strings.Split(string(sourceLines), "\n") {
					if strings.Contains(line, f.Name()) {
						line = strings.TrimSpace(line)
						if line == "" || strings.HasPrefix(line, "#") {
							continue
						}
						hashName := fmt.Sprintf("%s-%s", hashString(line+f.Name()), f.Name())
						cachePath := filepath.Join(CacheStore, hashName)
						if _, err := os.Stat(cachePath); err == nil {
							os.Remove(cachePath)
						}
					}
				}

				skipped = true
				hashValid = false
			}
		}

		if !hashValid {
			if !skipped {
				fmt.Printf("Updating checksum for %s\n", f.Name())
				cmd := exec.Command("b3sum", filePath)
				out, err := cmd.Output()
				if err != nil {
					return fmt.Errorf("failed to compute checksum: %v", err)
				}
				sum := strings.Fields(string(out))[0]
				updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", sum, f.Name()))
				summary = append(summary, fmt.Sprintf("%s: updated", f.Name()))
			} else {
				// User skipped → mark as mismatch
				updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", existing[f.Name()], f.Name()))
				summary = append(summary, fmt.Sprintf("%s: mismatch (skipped)", f.Name()))
			}
		} else {
			updatedChecksums = append(updatedChecksums, fmt.Sprintf("%s  %s", existing[f.Name()], f.Name()))
			summary = append(summary, fmt.Sprintf("%s: ok", f.Name()))
		}
	}

	// Write back to the package directory
	if err := os.WriteFile(checksumFile, []byte(strings.Join(updatedChecksums, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write checksums file: %v", err)
	}

	fmt.Printf("Checksums summary for %s:\n", pkgName)
	for _, s := range summary {
		fmt.Println(" -", s)
	}

	return nil
}

// checksum command
func hokutoChecksum(pkgName string, cfg *Config) error {
	repoPaths := cfg.Values["HOKUTO_PATH"]
	if repoPaths == "" {
		return fmt.Errorf("HOKUTO_PATH is not set")
	}

	paths := strings.Split(repoPaths, ":")
	var pkgDir string
	found := false
	for _, repo := range paths {
		tryPath := filepath.Join(repo, pkgName)
		if info, err := os.Stat(tryPath); err == nil && info.IsDir() {
			pkgDir = tryPath
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("package %s not found in HOKUTO_PATH", pkgName)
	}

	if err := fetchSources(pkgName, pkgDir); err != nil {
		return fmt.Errorf("error fetching sources: %v", err)
	}
	if err := verifyOrCreateChecksums(pkgName, pkgDir); err != nil {
		return fmt.Errorf("error verifying checksums: %v", err)
	}

	return nil
}

// build package
func buildEntry(pkgName string, cfg *Config) error {
	// set tmpdir
	tmpDir := cfg.Values["TMPDIR"]
	pkgTmpDir := filepath.Join(tmpDir, pkgName)
	buildDir := filepath.Join(pkgTmpDir, "build")
	outputDir := filepath.Join(pkgTmpDir, "output")

	// Prepare root dir for installations (used by pkgInstall, depends, etc.)
	rootDir := cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}

	// Create build/output dirs (non-root, inside TMPDIR)
	for _, dir := range []string{buildDir, outputDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

	// Use HOKUTO_PATH from config to find package dir
	repoPaths := cfg.Values["HOKUTO_PATH"]
	if repoPaths == "" {
		return fmt.Errorf("HOKUTO_PATH is not set")
	}

	paths := strings.Split(repoPaths, ":")
	var pkgDir string
	found := false
	for _, repo := range paths {
		tryPath := filepath.Join(repo, pkgName)
		if info, err := os.Stat(tryPath); err == nil && info.IsDir() {
			pkgDir = tryPath
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("package %s not found in HOKUTO_PATH", pkgName)
	}

	// Prepare sources in build directory
	if err := prepareSources(pkgName, pkgDir, buildDir, runAsRoot); err != nil {
		return fmt.Errorf("failed to prepare sources: %v", err)
	}

	// Read version
	versionFile := filepath.Join(pkgDir, "version")
	versionData, err := os.ReadFile(versionFile)
	if err != nil {
		return fmt.Errorf("failed to read version file: %v", err)
	}
	version := strings.Fields(string(versionData))[0]

	// Build script
	buildScript := filepath.Join(pkgDir, "build")
	if _, err := os.Stat(buildScript); err != nil {
		return fmt.Errorf("build script not found: %v", err)
	}

	// Check RUN_BUILD_AS_ROOT
	runBuildAsRoot := false
	asRootFile := filepath.Join(pkgDir, "asroot")
	if _, err := os.Stat(asRootFile); err == nil {
		runBuildAsRoot = true
	}

	// Build environment
	env := os.Environ()
	defaults := map[string]string{
		"AR":          "gcc-ar",
		"CC":          "cc",
		"CXX":         "c++",
		"NM":          "gcc-nm",
		"RANLIB":      "gcc-ranlib",
		"CFLAGS":      "-O2 -march=x86-64 -mtune=generic -pipe -fPIC",
		"CXXFLAGS":    "",
		"LDFLAGS":     "",
		"MAKEFLAGS":   fmt.Sprintf("-j%d", runtime.NumCPU()),
		"RUSTFLAGS":   fmt.Sprintf("--remap-path-prefix=%s=.", buildDir),
		"GOFLAGS":     "-trimpath -modcacherw",
		"GOPATH":      filepath.Join(buildDir, "go"),
		"HOKUTO_ROOT": cfg.Values["HOKUTO_ROOT"],
		"TMPDIR":      tmpDir,
	}

	for k, def := range defaults {
		val := cfg.Values[k]
		if val == "" {
			val = def
		}
		if k == "CXXFLAGS" && val == "" {
			val = cfg.Values["CFLAGS"]
			if val == "" {
				val = defaults["CFLAGS"]
			}
		}
		env = append(env, fmt.Sprintf("%s=%s", k, val))
	}

	// Run build script
	fmt.Printf("Building %s (version %s) in %s, install to %s (root=%v)\n",
		pkgName, version, buildDir, outputDir, runBuildAsRoot)

	cmd := exec.Command(buildScript, outputDir, version)
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	if runBuildAsRoot {
		if err := runAsRoot(cmd); err != nil {
			return fmt.Errorf("build failed: %v", err)
		}
	} else {
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build failed: %v", err)
		}
	}

	// Create /var/db/hokuto/installed/<pkgName> inside the staging outputDir
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	fmt.Printf("Creating metadata directory: %s\n", installedDir)
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := runAsRoot(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installed dir: %v", err)
	}

	// Generate libdeps
	libdepsFile := filepath.Join(installedDir, "libdeps")
	if err := generateLibDeps(outputDir, libdepsFile, runAsRoot); err != nil {
		fmt.Printf("Warning: failed to generate libdeps: %v\n", err)
	} else {
		fmt.Printf("Library dependencies written to %s\n", libdepsFile)
	}

	// Generate depends
	if err := generateDepends(pkgName, pkgDir, outputDir, rootDir, runAsRoot); err != nil {
		return fmt.Errorf("failed to generate depends: %v", err)
	}
	fmt.Printf("Depends written to %s\n", filepath.Join(installedDir, "depends"))

	fmt.Printf("%s built successfully, output in %s\n", pkgName, outputDir)

	// Copy version file from pkgDir
	versionSrc := filepath.Join(pkgDir, "version")
	versionDst := filepath.Join(installedDir, "version")
	cpCmd := exec.Command("cp", "--remove-destination", versionSrc, versionDst)
	if err := runAsRoot(cpCmd); err != nil {
		return fmt.Errorf("failed to copy version file: %v", err)
	}

	// Generate manifest
	if err := generateManifest(outputDir, installedDir, runAsRoot); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}

	// Generate package archive
	if err := createPackageTarball(pkgName, version, outputDir, runAsRoot, runBuildAsRoot); err != nil {
		return fmt.Errorf("failed to package tarball: %v", err)
	}
	return nil
}

// generateLibDeps scans ELF files in outputDir and writes their shared library dependencies to libdepsFile
func generateLibDeps(outputDir, libdepsFile string, runAsRoot func(*exec.Cmd) error) error {
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

	// Collect executable files
	var files []string
	filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// Only consider files with executable permission
		if info.Mode()&0111 != 0 {
			files = append(files, path)
		}
		return nil
	})

	type result struct{ libs []string }
	numWorkers := runtime.NumCPU()
	fileCh := make(chan string, len(files))
	resultCh := make(chan result, len(files))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for file := range fileCh {
			// Check if file is an ELF binary
			cmd := exec.Command("file", "--brief", "--mime-type", file)
			out, err := cmd.Output()
			if err != nil || !(strings.Contains(string(out), "application/x-executable") ||
				strings.Contains(string(out), "application/x-sharedlib")) {
				continue
			}

			lddCmd := exec.Command("ldd", file)
			out, err = lddCmd.Output()
			if err != nil {
				continue
			}

			var libs []string
			scanner := bufio.NewScanner(bytes.NewReader(out))
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

	tmpFile := filepath.Join(os.TempDir(), filepath.Base(libdepsFile)+".tmp")

	// write temp file as user
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	for lib := range seen {
		f.WriteString(lib + "\n")
	}
	f.Close()

	// ensure ownership is root:root
	chownCmd := exec.Command("chown", "0:0", tmpFile)
	if err := runAsRoot(chownCmd); err != nil {
		return fmt.Errorf("failed to chown temp libdeps: %v", err)
	}

	// move into place as root
	mvCmd := exec.Command("mv", "--force", tmpFile, libdepsFile)
	if err := runAsRoot(mvCmd); err != nil {
		return fmt.Errorf("failed to move libdeps into place: %v", err)
	}

	fmt.Printf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(seen))
	return nil
}

func generateDepends(pkgName, pkgDir, outputDir, rootDir string, runAsRoot func(*exec.Cmd) error) error {
	installedDir := filepath.Join(outputDir, "var", "db", "hokuto", "installed", pkgName)
	libdepsFile := filepath.Join(installedDir, "libdeps")
	dependsFile := filepath.Join(installedDir, "depends")

	// Read libdeps
	libdepsData, err := os.ReadFile(libdepsFile)
	if err != nil {
		return fmt.Errorf("failed to read libdeps: %v", err)
	}
	libdeps := strings.Fields(string(libdepsData))
	if len(libdeps) == 0 {
		return nil
	}

	depSet := make(map[string]struct{})

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
				if strings.HasSuffix(line, lib) {
					depSet[otherPkg] = struct{}{}
					break
				}
			}
		}
	}

	// Merge repo depends file if it exists
	repoDepends := filepath.Join(pkgDir, "depends")
	if data, err := os.ReadFile(repoDepends); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				depSet[line] = struct{}{}
			}
		}
	}

	// Prepare depends content
	var deps []string
	for dep := range depSet {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	content := strings.Join(deps, "\n")

	// Write depends file using runAsRoot if necessary
	writeCmd := exec.Command("sh", "-c", fmt.Sprintf("echo %s > %s", shellEscape(content), shellEscape(dependsFile)))
	if err := runAsRoot(writeCmd); err != nil {
		return fmt.Errorf("failed to write depends via runAsRoot: %v", err)
	}

	return nil
}

// shellEscape escapes content for safe use in shell commands
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// listOutputFiles generates a list of all files and directories in outputDir.
func listOutputFiles(outputDir string, runAsRoot func(*exec.Cmd) error) ([]string, error) {
	var entries []string

	// Use find via sudo to safely list all files and directories
	cmd := exec.Command("find", outputDir)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := runAsRoot(cmd); err != nil {
		return nil, fmt.Errorf("failed to list output files via find: %v", err)
	}

	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		path := scanner.Text()

		// Compute path relative to outputDir
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			continue
		}

		if rel == "." {
			continue
		}

		// Filter out libtool .la files and charset.alias
		if strings.HasSuffix(rel, ".la") || strings.HasSuffix(rel, "charset.alias") {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries = append(entries, "/"+rel+"/")
		} else {
			entries = append(entries, "/"+rel)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %v", err)
	}

	sort.Strings(entries)
	return entries, nil
}

// generateManifest scans outputDir and writes a manifest file
// installedDir is the directory where the manifest file will be placed
// outputDir is the dir scanned for files
func generateManifest(outputDir, installedDir string, runAsRoot func(*exec.Cmd) error) error {
	manifestFile := filepath.Join(installedDir, "manifest")
	tmpManifest := filepath.Join(os.TempDir(), filepath.Base(manifestFile)+".tmp")

	// Ensure installedDir exists as root
	mkdirCmd := exec.Command("mkdir", "-p", installedDir)
	if err := runAsRoot(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create installedDir: %v", err)
	}

	// List all output files
	entries, err := listOutputFiles(outputDir, runAsRoot)
	if err != nil {
		return fmt.Errorf("failed to list output files: %v", err)
	}

	// Remove manifest from entries if present
	relManifest, err := filepath.Rel(outputDir, manifestFile)
	if err != nil {
		return fmt.Errorf("failed to compute relative path for manifest: %v", err)
	}

	filtered := []string{}
	for _, e := range entries {
		if e != "/"+relManifest {
			filtered = append(filtered, e)
		}
	}
	filtered = append(filtered, "/"+relManifest)

	// Open temp manifest for writing
	f, err := os.OpenFile(tmpManifest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open temporary manifest file: %v", err)
	}
	defer f.Close()

	for _, entry := range filtered {
		absPath := filepath.Join(outputDir, strings.TrimPrefix(entry, "/"))
		info, err := os.Stat(absPath)
		if err != nil {
			continue
		}

		if info.IsDir() {
			cleaned := "/" + strings.Trim(strings.TrimPrefix(entry, "/"), "/") + "/"
			if _, err := fmt.Fprintf(f, "%s\n", cleaned); err != nil {
				return fmt.Errorf("failed to write manifest entry: %v", err)
			}
			continue
		}

		// Compute checksum with b3sum via runAsRoot
		b3sumCmd := exec.Command("b3sum", absPath)
		var out bytes.Buffer
		b3sumCmd.Stdout = &out
		b3sumCmd.Stderr = os.Stderr // optional: see warnings
		if err := runAsRoot(b3sumCmd); err != nil {
			return fmt.Errorf("b3sum failed for %s: %v", absPath, err)
		}

		fields := strings.Fields(out.String())
		if len(fields) < 1 {
			return fmt.Errorf("unexpected b3sum output for %s: %s", absPath, out.String())
		}
		checksum := fields[0]

		if _, err := fmt.Fprintf(f, "%s  %s\n", entry, checksum); err != nil {
			return fmt.Errorf("failed to write manifest entry: %v", err)
		}
	}

	f.Close() // close before moving

	// Move temp manifest into installedDir as root
	cpCmd := exec.Command("cp", "--remove-destination", tmpManifest, manifestFile)
	if err := runAsRoot(cpCmd); err != nil {
		return fmt.Errorf("failed to copy temporary manifest into place: %v", err)
	}

	// Remove temp manifest
	os.Remove(tmpManifest)

	fmt.Printf("Manifest written to %s (%d entries)\n", manifestFile, len(filtered))
	return nil
}

// prepareSources copies and extracts sources into the build directory
func prepareSources(pkgName, pkgDir, buildDir string, runAsRoot func(*exec.Cmd) error) error {
	srcDir := filepath.Join(CacheDir, "sources", pkgName)
	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return fmt.Errorf("source directory %s does not exist; run hokuto checksum first", srcDir)
	}

	// Clear buildDir via runAsRoot
	rmCmd := exec.Command("rm", "-rf", buildDir)
	if err := runAsRoot(rmCmd); err != nil {
		return fmt.Errorf("failed to clear build dir %s: %v", buildDir, err)
	}

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

		parts := strings.SplitN(line, " ", 2)
		relPath := parts[0]
		targetSubdir := ""
		if len(parts) == 2 {
			targetSubdir = parts[1]
		}

		var srcPath string
		switch {
		case strings.HasPrefix(relPath, "files/"):
			srcPath = filepath.Join(pkgDir, relPath)
		case strings.HasPrefix(relPath, "patches/"):
			srcPath = filepath.Join(pkgDir, relPath)
		default:
			srcPath = filepath.Join(srcDir, relPath)
		}

		info, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("source %s listed but missing: %v", relPath, err)
		}

		targetDir := buildDir
		if targetSubdir != "" {
			targetDir = filepath.Join(buildDir, targetSubdir)
			if err := os.MkdirAll(targetDir, 0o755); err != nil {
				return fmt.Errorf("failed to create target subdir %s: %v", targetDir, err)
			}
		}

		destPath := filepath.Join(targetDir, filepath.Base(relPath))

		if info.IsDir() {
			// Copy directory recursively
			if err := copyDir(srcPath, destPath); err != nil {
				return fmt.Errorf("failed to copy directory %s: %v", relPath, err)
			}
			continue
		}

		// Resolve symlinks
		realPath, err := filepath.EvalSymlinks(srcPath)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink %s: %v", relPath, err)
		}

		// Extract archives or copy file
		switch {
		case strings.HasSuffix(realPath, ".tar.gz"),
			strings.HasSuffix(realPath, ".tar.xz"),
			strings.HasSuffix(realPath, ".tar.bz2"),
			strings.HasSuffix(realPath, ".tar"):
			if err := extractTar(realPath, targetDir); err != nil {
				return fmt.Errorf("failed to extract tar %s: %v", relPath, err)
			}
		case strings.HasSuffix(realPath, ".zip"):
			cmd := exec.Command("unzip", "-q", "-o", realPath, "-d", targetDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to unzip %s: %v", relPath, err)
			}
		default:
			// Copy file
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

// copyFile copies a single file from src to dst
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Copy file mode
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, info.Mode())
}

// copyDir recursively copies a directory from src to dst
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// extractTar extracts a tarball into the destination directory
func extractTar(archive, dest string) error {
	cmd := exec.Command("tar", "xf", archive, "-C", dest, "--strip-components=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract %s: %v", archive, err)
	}
	return nil
}

func createPackageTarball(pkgName, pkgVer, outputDir string, runAsRoot func(*exec.Cmd) error, runBuildAsRoot bool) error {
	// Ensure BinDir exists
	if err := os.MkdirAll(BinDir, 0o755); err != nil {
		return fmt.Errorf("failed to create BinDir: %v", err)
	}

	tarballPath := filepath.Join(BinDir, fmt.Sprintf("%s-%s.tar.zst", pkgName, pkgVer))

	args := []string{"-cf", tarballPath, "-C", outputDir, "."}
	args = append([]string{"--zstd"}, args...) // always compress

	if !runBuildAsRoot {
		// Force numeric root ownership for user builds
		args = append([]string{"--owner=0", "--group=0", "--numeric-owner"}, args...)
	}

	cmd := exec.Command("tar", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("Creating package tarball: %s\n", tarballPath)
	if err := runAsRoot(cmd); err != nil {
		return fmt.Errorf("failed to create tarball: %v", err)
	}

	fmt.Printf("Package tarball created successfully: %s\n", tarballPath)
	return nil
}

func getModifiedFiles(pkgName, rootDir string) ([]string, error) {
	if rootDir == "" {
		rootDir = "/"
	}

	installedDir := filepath.Join(rootDir, "var", "db", "hokuto", "installed", pkgName)
	manifestFile := filepath.Join(installedDir, "manifest")

	// Check if manifest exists
	if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
		return nil, nil // no previously installed files
	}

	// Read manifest entries
	data, err := readFileAsRoot(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %v", err)
	}

	var modified []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		relPath := parts[0]
		relSlash := filepath.ToSlash(relPath)
		// Skip any manifest entry that refers to the package's installed manifest
		// Matches both "var/db/.../installed/<pkg>/manifest" and "/var/db/.../installed/<pkg>/manifest"
		if strings.HasSuffix(relSlash, "/installed/"+pkgName+"/manifest") {
			continue
		}

		absPath := filepath.Join(rootDir, relPath)

		// Compute b3sum of installed file
		sum, err := b3sum(absPath)
		if err != nil {
			continue // skip missing files or checksum failures
		}

		// Compare with recorded hash in manifest (if present)
		if len(parts) > 1 && parts[1] != sum {
			modified = append(modified, relPath)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning manifest: %v", err)
	}

	return modified, nil
}

// Helper to compute b3sum of a file, using system b3sum binary
func b3sum(path string) (string, error) {
	var cmd *exec.Cmd
	if os.Geteuid() != 0 {
		cmd = exec.Command("sudo", "b3sum", path)
	} else {
		cmd = exec.Command("b3sum", path)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("b3sum produced no output for %s", path)
	}
	return fields[0], nil
}

// Helper to read a file as root if needed
func readFileAsRoot(path string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return os.ReadFile(path)
	}

	cmd := exec.Command("sudo", "cat", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// removeObsoleteFiles compares the installed manifest (under Installed/<pkg>/manifest)
// with the manifest present in the staging tree. It returns a slice of absolute
// paths (under rootDir) that should be deleted after the staging has been rsynced.
func removeObsoleteFiles(pkgName, stagingDir, rootDir string, runAsRoot func(*exec.Cmd) error) ([]string, error) {
	installedManifestPath := filepath.Join(rootDir, Installed, pkgName, "manifest")
	stagingManifestPath := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName, "manifest")

	installedData, err := readFileAsRoot(installedManifestPath)
	if err != nil {
		// No installed manifest → nothing to remove
		return nil, nil
	}

	// Read staging manifest if present; treat missing file as empty manifest
	stagingData, _ := os.ReadFile(stagingManifestPath)

	// Build set of paths present in staging manifest
	stagingSet := make(map[string]struct{})
	if len(stagingData) > 0 {
		sc := bufio.NewScanner(strings.NewReader(string(stagingData)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasSuffix(line, "/") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			stagingSet[fields[0]] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("error reading staging manifest: %v", err)
		}
	}

	var filesToDelete []string

	// Scan installed manifest; add files missing from staging manifest
	iscanner := bufio.NewScanner(strings.NewReader(string(installedData)))
	for iscanner.Scan() {
		line := strings.TrimSpace(iscanner.Text())
		if line == "" || strings.HasSuffix(line, "/") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		relPath := fields[0]

		// if present in staging manifest -> skip
		if _, ok := stagingSet[relPath]; ok {
			continue
		}

		installedPath := filepath.Join(rootDir, relPath)

		// if installed file exists on disk, schedule for deletion
		if fi, err := os.Stat(installedPath); err == nil && !fi.IsDir() {
			filesToDelete = append(filesToDelete, installedPath)
		}
		// if file does not exist or is a directory, skip it
	}
	if err := iscanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading installed manifest: %v", err)
	}

	return filesToDelete, nil
}

// rsyncStaging syncs the contents of stagingDir into rootDir.
// Helper to sync staging dir into rootDir, respecting existing symlinks
func rsyncStaging(stagingDir, rootDir string, runAsRoot func(*exec.Cmd) error) error {
	// Ensure trailing slash on stagingDir so rsync copies contents
	stagingPath := filepath.Clean(stagingDir) + string(os.PathSeparator)

	// Ensure rootDir exists
	mkdirCmd := exec.Command("mkdir", "-p", rootDir)
	if err := runAsRoot(mkdirCmd); err != nil {
		return fmt.Errorf("failed to create rootDir %s: %v", rootDir, err)
	}

	// rsync args:
	// -aHAX         : archive mode (permissions, symlinks, hardlinks, xattrs)
	// --numeric-ids : preserve numeric ownership
	// --no-implied-dirs : only create directories that exist in staging
	// --keep-dirlinks : treat symlinked directory on receiver as directory (don't replace the symlink)
	args := []string{
		"-aHAX",
		"--numeric-ids",
		"--no-implied-dirs",
		"--keep-dirlinks",
		stagingPath,
		rootDir,
	}

	cmd := exec.Command("rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := runAsRoot(cmd); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}
	// Clean up staging directory
	rmCmd := exec.Command("rm", "-rf", stagingDir)
	if err := runAsRoot(rmCmd); err != nil {
		return fmt.Errorf("failed to remove staging dir %s: %v", stagingDir, err)
	}

	return nil
}

// runAsRoot executes cmd as root. If already root it runs cmd directly.
// If not root it executes: sudo -E <cmd.Path> <cmd.Args[1:]...>
// It preserves cmd.Dir, cmd.Env and stdio so interactive programs and
// working-directory-dependent scripts behave correctly.
func runAsRoot(cmd *exec.Cmd) error {
	// ensure stdio is set on the original cmd so we can reuse them
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	if os.Geteuid() == 0 {
		// already root: just run it with its env/dir/stdio
		cmd.Env = append(os.Environ(), cmd.Env...) // prefer cmd.Env if set
		return cmd.Run()
	}

	// Not root: construct sudo -E <binary> <args...>
	// cmd.Args[0] is the invoked program (== cmd.Path), cmd.Args[1:] are the args
	args := append([]string{"-E", cmd.Path}, cmd.Args[1:]...)
	sudoCmd := exec.Command("sudo", args...)
	sudoCmd.Stdin = cmd.Stdin
	sudoCmd.Stdout = cmd.Stdout
	sudoCmd.Stderr = cmd.Stderr
	sudoCmd.Dir = cmd.Dir

	// preserve the environment intended for the child
	// if cmd.Env was set use it, otherwise inherit current env
	if len(cmd.Env) > 0 {
		sudoCmd.Env = cmd.Env
	} else {
		sudoCmd.Env = os.Environ()
	}

	return sudoCmd.Run()
}

func pkgInstall(tarballPath, pkgName string, cfg *Config) error {
	tmpDir := cfg.Values["TMPDIR"]
	if tmpDir == "" {
		tmpDir = "/tmp"
	}
	stagingDir := filepath.Join(tmpDir, "staging", pkgName)

	// Clean staging dir
	os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("failed to create staging dir: %v", err)
	}

	// Prepare root dir
	rootDir := cfg.Values["HOKUTO_ROOT"]
	if rootDir == "" {
		rootDir = "/"
	}

	// 1. Unpack tarball into staging
	fmt.Printf("Unpacking %s into %s\n", tarballPath, stagingDir)
	untarCmd := exec.Command("tar", "--zstd", "-xf", tarballPath, "-C", stagingDir)
	if err := runAsRoot(untarCmd); err != nil {
		return fmt.Errorf("failed to unpack tarball: %v", err)
	}

	// 2. Detect user-modified files
	modifiedFiles, err := getModifiedFiles(pkgName, rootDir)
	if err != nil {
		return err
	}

	// 3. Interactive handling of modified files
	for _, file := range modifiedFiles {
		stagingFile := filepath.Join(stagingDir, file)
		currentFile := filepath.Join(rootDir, file) // file under the install root

		if _, err := os.Stat(stagingFile); err == nil {
			// file exists in staging
			cmd := exec.Command("diff", "-u", currentFile, stagingFile)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()

			fmt.Printf("File %s modified, choose action: [k]eep current, [u]se new, [e]dit: ", file)
			var input string
			fmt.Scanln(&input)
			switch input {
			case "k":
				cpCmd := exec.Command("cp", "--remove-destination", currentFile, stagingFile)
				if err := runAsRoot(cpCmd); err != nil {
					return fmt.Errorf("failed to overwrite %s: %v", stagingFile, err)
				}
			case "u":
				// keep staging file as-is
			case "e":
				// read staging content
				stContent, err := os.ReadFile(stagingFile)
				if err != nil {
					return fmt.Errorf("failed to read staging file %s: %v", stagingFile, err)
				}

				// produce unified diff (currentFile vs stagingFile); ignore diff errors (non-zero exit means differences)
				diffCmd := exec.Command("diff", "-u", currentFile, stagingFile)
				diffOut, _ := diffCmd.Output() // we don't fail if diff returns non-zero

				// create temp file prefilled with staging content + marked diff
				tmp, err := os.CreateTemp("", "hokuto-edit-")
				if err != nil {
					return fmt.Errorf("failed to create temp file for editing: %v", err)
				}
				tmpPath := tmp.Name()
				defer func() {
					tmp.Close()
					_ = os.Remove(tmpPath)
				}()

				if _, err := tmp.Write(stContent); err != nil {
					return fmt.Errorf("failed to write staging content to temp file: %v", err)
				}

				// append a separator and diff output for reference
				if len(diffOut) > 0 {
					if _, err := tmp.WriteString("\n\n--- diff (installed -> staging) ---\n"); err != nil {
						return fmt.Errorf("failed to write diff header to temp file: %v", err)
					}
					if _, err := tmp.Write(diffOut); err != nil {
						return fmt.Errorf("failed to write diff to temp file: %v", err)
					}
				}

				// close before launching editor
				if err := tmp.Close(); err != nil {
					return fmt.Errorf("failed to close temp file before editing: %v", err)
				}

				editor := os.Getenv("EDITOR")
				if editor == "" {
					editor = "nano"
				}

				// Launch editor against the temp file as the invoking user so they can edit comfortably.
				editCmd := exec.Command(editor, tmpPath)
				editCmd.Stdin, editCmd.Stdout, editCmd.Stderr = os.Stdin, os.Stdout, os.Stderr
				if err := editCmd.Run(); err != nil {
					return fmt.Errorf("editor failed: %v", err)
				}

				// After editing, copy temp back to staging (use runAsRoot to preserve ownership/permissions)
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", tmpPath, stagingFile)
				if err := runAsRoot(cpCmd); err != nil {
					return fmt.Errorf("failed to copy edited file back to staging %s: %v", stagingFile, err)
				}
			}
		} else {
			// file does NOT exist in staging
			fmt.Printf("User modified %s, but new package has no file. Keep it? [y/N]: ", file)
			var input string
			fmt.Scanln(&input)
			ans := strings.ToLower(strings.TrimSpace(input))
			if ans == "y" {
				// ensure staging directory exists (run as root)
				stagingFileDir := filepath.Dir(stagingFile)
				mkdirCmd := exec.Command("mkdir", "-p", stagingFileDir)
				if err := runAsRoot(mkdirCmd); err != nil {
					return fmt.Errorf("failed to create directory %s: %v", stagingFileDir, err)
				}
				// copy current file into staging preserving attributes
				cpCmd := exec.Command("cp", "--preserve=mode,ownership,timestamps", currentFile, stagingFile)
				if err := runAsRoot(cpCmd); err != nil {
					return fmt.Errorf("failed to copy %s to staging: %v", file, err)
				}
				fmt.Printf("Kept modified file by copying %s into staging\n", file)
			} else {
				// user chose not to keep it -> remove the installed file (run as root)
				rmCmd := exec.Command("rm", "-f", currentFile)
				if err := runAsRoot(rmCmd); err != nil {
					// warn but continue install; do not abort the whole install for a removal failure
					fmt.Printf("warning: failed to remove %s: %v\n", currentFile, err)
				} else {
					fmt.Printf("Removed user-modified file: %s\n", file)
				}
			}
		}
	}
	// Generate updated manifest in staging
	stagingManifest := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	if err := generateManifest(stagingDir, stagingManifest, runAsRoot); err != nil {
		return fmt.Errorf("failed to generate manifest: %v", err)
	}
	// 4. Determine obsolete files (compare manifests)
	filesToDelete, err := removeObsoleteFiles(pkgName, stagingDir, rootDir, runAsRoot)
	if err != nil {
		return err
	}

	// 5. Rsync staging into root
	if err := rsyncStaging(stagingDir, rootDir, runAsRoot); err != nil {
		return fmt.Errorf("failed to sync staging to %s: %v", rootDir, err)
	}

	// 6. Remove files that were scheduled for deletion
	for _, p := range filesToDelete {
		rmCmd := exec.Command("rm", "-f", p)
		if err := runAsRoot(rmCmd); err != nil {
			fmt.Printf("warning: failed to remove obsolete file %s: %v\n", p, err)
		} else {
			fmt.Printf("Removed obsolete file: %s\n", p)
		}
	}

	return nil
}

// Entry point
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: hokuto <command> [args...]")
		return
	}

	cfg, _ := loadConfig(ConfigFile)
	mergeEnvOverrides(cfg)

	switch os.Args[1] {
	case "version":
		fmt.Println("hokuto 0.1")
	case "list":
		pkg := ""
		if len(os.Args) >= 3 {
			pkg = os.Args[2]
		}
		if err := listPackages(pkg); err != nil {
			fmt.Println("Error:", err)
		}
	case "checksum":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto checksum <pkgname>")
			return
		}
		pkg := os.Args[2]
		if err := hokutoChecksum(pkg, cfg); err != nil {
			fmt.Println("Error:", err)
		}
	case "build":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto build <package>")
			os.Exit(1)
		}
		pkgName := os.Args[2]

		// Assume cfg is already loaded from /etc/hokuto.conf
		if err := buildEntry(pkgName, cfg); err != nil {
			fmt.Printf("Error building package %s: %v\n", pkgName, err)
			os.Exit(1)
		}
	case "install":
		if len(os.Args) < 3 {
			fmt.Println("Usage: hokuto install <tarball>")
			os.Exit(1)
		}
		tarballPath := os.Args[2]

		// infer pkgName from tarball name (pkgname-pkgver.tar.zst)
		base := filepath.Base(tarballPath)
		pkgName := strings.SplitN(base, "-", 2)[0]

		if err := pkgInstall(tarballPath, pkgName, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error installing package %s: %v\n", pkgName, err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command:", os.Args[1])
	}
}
