package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func getAntigravityString() (string, error) {
	baseURL := "https://antigravity.google"
	resp, err := http.Get(baseURL + "/download/linux")
	if err != nil {
		return "", fmt.Errorf("failed to fetch download page: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	// Find the main JS file
	// <script src="main-UR65DTH6.js" type="module"></script>
	reScript := regexp.MustCompile(`src="(main-[a-zA-Z0-9]+\.js)"`)
	matchesScript := reScript.FindSubmatch(body)
	if len(matchesScript) < 2 {
		return "", fmt.Errorf("could not find main.js script in download page")
	}
	jsFile := string(matchesScript[1])

	// Fetch main.js
	respJS, err := http.Get(baseURL + "/" + jsFile)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JS file %s: %v", jsFile, err)
	}
	defer respJS.Body.Close()

	jsBody, err := io.ReadAll(respJS.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read JS body: %v", err)
	}

	// Look for the version string in any link (Windows/Mac links are hardcoded in the JS)
	// href:"https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/1.16.5-6703236727046144/windows-x64/Antigravity.exe"
	re := regexp.MustCompile(`/stable/[\d\.]+-(\d+)/`)
	matches := re.FindSubmatch(jsBody)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not find version string in JS file")
	}

	return string(matches[1]), nil
}

func getExtraSubs(pkgName string) (map[string]string, error) {
	if filepath.Base(pkgName) == "antigravity" {
		s, err := getAntigravityString()
		if err != nil {
			return nil, err
		}
		return map[string]string{"${string}": s}, nil
	}
	return nil, nil
}

func applySubstitutions(content, version, pkgName string, extraSubs map[string]string) string {
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

	// Logic for ${version-glued-last}: 1.0.0.a -> 1.0.0a
	versionGluedLast := version
	versionLastOnly := version
	if lastDot := strings.LastIndex(version, "."); lastDot != -1 {
		versionGluedLast = version[:lastDot] + version[lastDot+1:]
		versionLastOnly = version[lastDot+1:]
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

	args := []string{
		"${version}", version,
		"${version-clean}", strings.ReplaceAll(version, "_", "."),
		"${version_}", strings.ReplaceAll(version, ".", "_"),
		"${version-}", strings.ReplaceAll(version, ".", "-"),
		"${version-major}", major,
		"${version-major-minor}", majorMinor,
		"${version-sqlite}", sqliteVer,
		"${version-glued}", strings.ReplaceAll(version, ".", ""),
		"${version-glued-last}", versionGluedLast,
		"${version-last-only}", versionLastOnly,
		"${pkgname}", pkgName,
	}

	for k, v := range extraSubs {
		args = append(args, k, v)
	}

	r := strings.NewReplacer(args...)
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

		extraSubs, err := getExtraSubs(pkgName)
		if err != nil {
			// If we fail to get extra subs (e.g. download failed), warn but proceed?
			// Or fail? For editPackage, maybe just warn?
			fmt.Printf("Warning: failed to get extra substitutions: %v\n", err)
		}

		updatedSources := applySubstitutions(string(dotSourcesData), version, pkgName, extraSubs)
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

// getGitRepoRoot finds the root definition of the git repository containing path.
func getGitRepoRoot(path string) (string, error) {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get git repo root for %s: %v", path, err)
	}
	return strings.TrimSpace(string(output)), nil
}

// pushGitRepo pushes changes to the remote repository.
func pushGitRepo(repoPath string) error {
	colArrow.Print("-> ")
	colSuccess.Printf("Pushing changes for repo: %s\n", repoPath)
	cmd := exec.Command("git", "-C", repoPath, "push")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprint(os.Stderr, string(out))
		return err
	}
	if Verbose {
		fmt.Print(string(out))
	}
	return nil
}

// bumpPackage performs the bump operation on a single package.
// If expectedOldVersion is empty, the version check is skipped.
// Returns the package directory on success.
func bumpPackage(pkgName, expectedOldVersion, newVersion string) (string, error) {
	colArrow.Print("-> ")
	if expectedOldVersion != "" {
		colSuccess.Printf("Bumping %s: %s -> %s\n", pkgName, expectedOldVersion, newVersion)
	} else {
		colSuccess.Printf("Bumping %s: -> %s\n", pkgName, newVersion)
	}

	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return "", fmt.Errorf("%s: package not found", pkgName)
	}

	// 1) Verify .sources exists
	dotSourcesPath := filepath.Join(pkgDir, ".sources")
	if _, err := os.Stat(dotSourcesPath); os.IsNotExist(err) {
		return "", fmt.Errorf("%s: .sources file missing", pkgName)
	}

	// 2) Verify version file matches oldVersion (if checked)
	versionPath := filepath.Join(pkgDir, "version")
	versionData, err := os.ReadFile(versionPath)
	if err != nil {
		return "", fmt.Errorf("%s: could not read version file", pkgName)
	}
	fields := strings.Fields(string(versionData))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s: version file empty", pkgName)
	}
	currentVer := fields[0]
	currentRev := 1
	if len(fields) > 1 {
		if r, err := strconv.Atoi(fields[1]); err == nil {
			currentRev = r
		}
	}

	if expectedOldVersion != "" && currentVer != expectedOldVersion {
		return "", fmt.Errorf("%s: wrong version (found %s, expected %s)", pkgName, currentVer, expectedOldVersion)
	}

	// 3) Amend version to newVersion
	// Logic: If version changed, reset revision to 1
	//        If version same, increment revision
	var newRev int
	if newVersion == currentVer {
		newRev = currentRev + 1
	} else {
		newRev = 1
	}

	newVersionContent := fmt.Sprintf("%s %d\n", newVersion, newRev)
	if err := os.WriteFile(versionPath, []byte(newVersionContent), 0o644); err != nil {
		return "", fmt.Errorf("%s: failed to update version file", pkgName)
	}

	// 4) Execute automatic version substitution
	dotSourcesData, err := os.ReadFile(dotSourcesPath)
	if err != nil {
		return "", fmt.Errorf("%s: failed to read .sources", pkgName)
	}
	extraSubs, err := getExtraSubs(pkgName)
	if err != nil {
		return "", fmt.Errorf("failed to get extra substitutions: %w", err)
	}

	updatedSources := applySubstitutions(string(dotSourcesData), newVersion, pkgName, extraSubs)
	sourcesPath := filepath.Join(pkgDir, "sources")
	if err := os.WriteFile(sourcesPath, []byte(updatedSources), 0o644); err != nil {
		return "", fmt.Errorf("%s: failed to update sources file", pkgName)
	}

	// 5) Update checksums (fetchSources + verifyOrCreateChecksums)
	if err := fetchSources(pkgName, pkgDir, false); err != nil {
		return "", fmt.Errorf("%s: could not download sources: %v", pkgName, err)
	}
	if err := verifyOrCreateChecksums(pkgName, pkgDir, false, nil); err != nil {
		return "", fmt.Errorf("%s: failed to generate checksums: %v", pkgName, err)
	}

	// 6) git add . (within pkgDir)
	gitAdd := exec.Command("git", "-C", pkgDir, "add", ".")
	if err := gitAdd.Run(); err != nil {
		return "", fmt.Errorf("%s: git add failed: %v", pkgName, err)
	}

	// 7) git commit (use hook for message)
	gitCommit := exec.Command("git", "-C", pkgDir, "commit", "--no-edit", ".")
	// Depending on git config, --no-edit might fail if no message logic is hooked?
	// The original code used this, so preserving it.
	if err := gitCommit.Run(); err != nil {
		return "", fmt.Errorf("%s: git commit failed: %v", pkgName, err)
	}

	return pkgDir, nil
}

func handleSingleBumpCommand(pkgName, newVersion string) error {
	pkgDir, err := bumpPackage(pkgName, "", newVersion)
	if err != nil {
		return err
	}

	// Push changes
	repoRoot, err := getGitRepoRoot(pkgDir)
	if err != nil {
		return fmt.Errorf("failed to determine git repo root: %v", err)
	}
	if err := pushGitRepo(repoRoot); err != nil {
		return fmt.Errorf("git push failed: %v", err)
	}

	return nil
}

func handleSetBumpCommand(pkgsetName, oldVersion, newVersion string) error {
	sets, err := loadPkgsets()
	if err != nil {
		return fmt.Errorf("failed to load pkgsets: %v", err)
	}

	pkgs, ok := sets[pkgsetName]
	if !ok {
		return fmt.Errorf("pkgset %s not found in %s", pkgsetName, PkgsetFile)
	}

	var failed []string
	repoRoots := make(map[string]bool)

	for _, pkgName := range pkgs {
		pkgDir, err := bumpPackage(pkgName, oldVersion, newVersion)
		if err != nil {
			failed = append(failed, err.Error())
			continue
		}
		// Collect repo root for later push
		if repoRoot, err := getGitRepoRoot(pkgDir); err == nil {
			repoRoots[repoRoot] = true
		} else {
			fmt.Fprintf(os.Stderr, "Warning: failed to determine git repo root for %s: %v\n", pkgName, err)
		}
	}

	if len(failed) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, f := range failed {
			colArrow.Print("-> ")
			colError.Printf("Failed %s\n", f)
		}
	}

	// Push unique repositories
	for repoRoot := range repoRoots {
		if err := pushGitRepo(repoRoot); err != nil {
			colError.Printf("Failed to push repo %s: %v\n", repoRoot, err)
		}
	}

	return nil
}
