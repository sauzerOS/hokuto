package hokuto

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApplySubstitutionsCUnitVersion(t *testing.T) {
	got := applySubstitutions(
		"https://example.invalid/CUnit/${version-cunit}/CUnit-${version-cunit}.tar.bz2",
		"2.1.3",
		"1",
		"cunit",
		nil,
	)
	want := "https://example.invalid/CUnit/2.1-3/CUnit-2.1-3.tar.bz2"
	if got != want {
		t.Fatalf("unexpected CUnit source substitution: got %q want %q", got, want)
	}
}

func TestFindAntigravityString(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantOK  bool
	}{
		{
			name: "current direct download",
			content: `<a href="https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.8.1-1111111111111111/linux-x64/Antigravity.tar.gz">Antigravity 2.0</a>
<a href="https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.5.5-4923483625488384/linux-x64/Antigravity%20IDE.tar.gz">Antigravity IDE</a>`,
			want:   "4923483625488384",
			wantOK: true,
		},
		{
			name:    "legacy IDE filename",
			content: `href:"https://edgedl.me.gvt1.com/edgedl/release2/j0qc3/antigravity/stable/2.0.3-6242596486512640/linux-x64/Antigravity%20IDE.tar.gz"`,
			want:    "6242596486512640",
			wantOK:  true,
		},
		{
			name:    "unrelated content",
			content: `<script src="main-UR65DTH6.js"></script>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := findAntigravityString([]byte(tt.content))
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("findAntigravityString() = %q, %v; want %q, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestRepologyURLForRepositoryReplacesInRepo(t *testing.T) {
	got, err := repologyURLForRepository(
		"https://repology.example/api/v1/projects/?inrepo=sauzeros&outdated=1",
		"sauzeros-cosmic",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "inrepo=sauzeros-cosmic") {
		t.Fatalf("repository was not replaced in %q", got)
	}
	if !strings.Contains(got, "outdated=1") {
		t.Fatalf("unrelated query parameter was not preserved in %q", got)
	}
}

func TestOptionalAutoBumpRepositoriesPromptAndRunInRequestedOrder(t *testing.T) {
	var prompted []string
	var ran []string
	err := runOptionalAutoBumpRepositories(
		false,
		func(string) bool { return true },
		func(repository autoBumpRepository) bool {
			prompted = append(prompted, repository.DisplayName)
			return repository.DisplayName == "Cosmic"
		},
		func(repository autoBumpRepository) error {
			ran = append(ran, repository.DisplayName)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Cosmic", "KDE"}; !reflect.DeepEqual(prompted, want) {
		t.Fatalf("unexpected prompt order: got %v want %v", prompted, want)
	}
	if want := []string{"Cosmic"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("unexpected processed repositories: got %v want %v", ran, want)
	}
}

func TestOptionalAutoBumpRepositoriesSkipUnavailableAndHonorAssumeYes(t *testing.T) {
	var prompted bool
	var ran []string
	err := runOptionalAutoBumpRepositories(
		true,
		func(path string) bool { return path == "/repo/kde" },
		func(autoBumpRepository) bool {
			prompted = true
			return false
		},
		func(repository autoBumpRepository) error {
			ran = append(ran, repository.DisplayName)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if prompted {
		t.Fatal("--yes should not prompt for optional repositories")
	}
	if want := []string{"KDE"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("unexpected processed repositories: got %v want %v", ran, want)
	}
}

func TestOptionalAutoBumpRepositoryErrorIncludesRepository(t *testing.T) {
	err := runOptionalAutoBumpRepositories(
		true,
		func(path string) bool { return path == "/repo/cosmic" },
		func(autoBumpRepository) bool { return true },
		func(autoBumpRepository) error { return errors.New("feed unavailable") },
	)
	if err == nil || !strings.Contains(err.Error(), "Cosmic repository auto-bump failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrioritizeAutoBumpRepository(t *testing.T) {
	current := strings.Join([]string{"/repo/sauzeros/core", "/repo/cosmic", "/repo/sauzeros/extra"}, string(os.PathListSeparator))
	got := filepath.SplitList(prioritizeAutoBumpRepository("/repo/cosmic", current))
	want := []string{"/repo/cosmic", "/repo/sauzeros/core", "/repo/sauzeros/extra"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected repository order: got %v want %v", got, want)
	}
}

func TestResolveBumpSourcePackageMapsSplitOutputToRecipe(t *testing.T) {
	repository := t.TempDir()
	installed := t.TempDir()
	oldRepoPaths := repoPaths
	oldInstalled := Installed
	repoPaths = repository
	Installed = installed
	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		Installed = oldInstalled
	})

	elfutilsDir := filepath.Join(repository, "elfutils")
	if err := os.MkdirAll(elfutilsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elfutilsDir, ".sources"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elfutilsDir, "depends.libelf"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(installed, "libelf"), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := resolveBumpSourcePackage("libelf"); got != "elfutils" {
		t.Fatalf("split bump target resolved to %q, want %q", got, "elfutils")
	}
}

func TestResolveBumpSourcePackagePrefersDirectRecipe(t *testing.T) {
	repository := t.TempDir()
	oldRepoPaths := repoPaths
	repoPaths = repository
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	directDir := filepath.Join(repository, "libelf")
	if err := os.MkdirAll(directDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directDir, ".sources"), []byte("source"), 0o644); err != nil {
		t.Fatal(err)
	}

	otherDir := filepath.Join(repository, "elfutils")
	if err := os.MkdirAll(otherDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "depends.libelf"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if got := resolveBumpSourcePackage("libelf"); got != "libelf" {
		t.Fatalf("direct bump target resolved to %q, want %q", got, "libelf")
	}
}

func TestAutoBumpLocalVersionReportsMissingOptionalRepositoryPackage(t *testing.T) {
	repository := t.TempDir()
	_, isPkgSet, err := autoBumpLocalVersion("spectacle-kde", nil, repository)
	if err == nil {
		t.Fatal("expected missing optional-repository package to return an error")
	}
	if isPkgSet {
		t.Fatal("ordinary package must not be reported as a pkgset")
	}
	if !strings.Contains(err.Error(), "package spectacle-kde not found in repository "+repository) {
		t.Fatalf("unexpected missing-package error: %v", err)
	}
}

func TestAutoBumpLocalVersionReportsMissingOptionalRepositoryPkgsetMember(t *testing.T) {
	repository := t.TempDir()
	sets := map[string][]string{"plasma-set": {"plasma-workspace"}}
	_, isPkgSet, err := autoBumpLocalVersion("plasma-set", sets, repository)
	if err == nil {
		t.Fatal("expected missing optional-repository pkgset member to return an error")
	}
	if !isPkgSet {
		t.Fatal("pkgset must be identified before checking its first member")
	}
	if !strings.Contains(err.Error(), "package plasma-workspace not found in repository "+repository) {
		t.Fatalf("unexpected missing-pkgset error: %v", err)
	}
}

func TestAutoBumpLocalVersionReadsWebKitSourceRecipe(t *testing.T) {
	repository := t.TempDir()
	oldRepoPaths := repoPaths
	repoPaths = repository
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	pkgDir := filepath.Join(repository, "webkit2gtk")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("2.52.5 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	version, isPkgSet, err := autoBumpLocalVersion("webkit2gtk", nil, repository)
	if err != nil {
		t.Fatal(err)
	}
	if isPkgSet {
		t.Fatal("ordinary package must not be reported as a pkgset")
	}
	if version != "2.52.5" {
		t.Fatalf("unexpected local version: %q", version)
	}
}

func TestParseAutoBumpSelectionSkipsRepository(t *testing.T) {
	for _, input := range []string{"s", "skip", "SKIP", " skip "} {
		selection, err := parseAutoBumpSelection(input, 2)
		if err != nil {
			t.Fatalf("parseAutoBumpSelection(%q) returned an error: %v", input, err)
		}
		if !selection.Skip {
			t.Fatalf("parseAutoBumpSelection(%q) did not request a repository skip", input)
		}
		if len(selection.Selected) != 0 || len(selection.Blacklist) != 0 {
			t.Fatalf("repository skip must not select or blacklist packages: %+v", selection)
		}
	}
}

func TestIsLikelyVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"1.85.0", true},
		{"2.0-rc1", true},
		{"0.1.0_beta", true},
		{"v1.2.3", true},
		{"V2.0", true},
		{"2024.01.01", true},
		{"rebuild for llvm 22.1.8", false},
		{"rebuild", false},
		{"fix build issue", false},
		{"soname bump", false},
		{"", false},
		{"   ", false},
	}

	for _, tt := range tests {
		got := isLikelyVersion(tt.input)
		if got != tt.want {
			t.Errorf("isLikelyVersion(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}

func TestParseSingleBumpArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flagMsg     string
		wantPkg     string
		wantVer     string
		wantMsg     string
		expectError bool
	}{
		{
			name:    "pkg only",
			args:    []string{"rust"},
			wantPkg: "rust",
		},
		{
			name:    "pkg and commit message without new version",
			args:    []string{"rust", "rebuild for llvm 22.1.8"},
			wantPkg: "rust",
			wantVer: "",
			wantMsg: "rebuild for llvm 22.1.8",
		},
		{
			name:    "pkg and new version",
			args:    []string{"rust", "1.85.0"},
			wantPkg: "rust",
			wantVer: "1.85.0",
		},
		{
			name:    "pkg, new version, and commit message",
			args:    []string{"rust", "1.85.0", "upgrade to 1.85.0"},
			wantPkg: "rust",
			wantVer: "1.85.0",
			wantMsg: "upgrade to 1.85.0",
		},
		{
			name:    "pkg with flag commit message",
			args:    []string{"rust"},
			flagMsg: "rebuild for llvm 22.1.8",
			wantPkg: "rust",
			wantVer: "",
			wantMsg: "rebuild for llvm 22.1.8",
		},
		{
			name:    "pkg and new version with flag commit message",
			args:    []string{"rust", "1.85.0"},
			flagMsg: "upgrade to 1.85.0",
			wantPkg: "rust",
			wantVer: "1.85.0",
			wantMsg: "upgrade to 1.85.0",
		},
		{
			name:    "pkg with inline -m flag",
			args:    []string{"rust", "-m", "rebuild for llvm 22.1.8"},
			wantPkg: "rust",
			wantVer: "",
			wantMsg: "rebuild for llvm 22.1.8",
		},
		{
			name:    "pkg, version with inline --message flag",
			args:    []string{"rust", "1.85.0", "--message=upgrade"},
			wantPkg: "rust",
			wantVer: "1.85.0",
			wantMsg: "upgrade",
		},
		{
			name:    "unquoted multi-word commit message",
			args:    []string{"rust", "rebuild", "for", "llvm", "22.1.8"},
			wantPkg: "rust",
			wantVer: "",
			wantMsg: "rebuild for llvm 22.1.8",
		},
		{
			name:        "empty args",
			args:        []string{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, ver, msg, err := parseSingleBumpArgs(tt.args, tt.flagMsg)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pkg != tt.wantPkg || ver != tt.wantVer || msg != tt.wantMsg {
				t.Errorf("parseSingleBumpArgs(%v, %q) = (%q, %q, %q); want (%q, %q, %q)",
					tt.args, tt.flagMsg, pkg, ver, msg, tt.wantPkg, tt.wantVer, tt.wantMsg)
			}
		})
	}
}

func TestParseSetBumpArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flagMsg     string
		wantSet     string
		wantOld     string
		wantNew     string
		wantMsg     string
		expectError bool
	}{
		{
			name:    "basic set bump",
			args:    []string{"kde-set", "6.2.0", "6.3.0"},
			wantSet: "kde-set",
			wantOld: "6.2.0",
			wantNew: "6.3.0",
			wantMsg: "",
		},
		{
			name:    "set bump with positional message",
			args:    []string{"kde-set", "6.2.0", "6.3.0", "upgrade kde"},
			wantSet: "kde-set",
			wantOld: "6.2.0",
			wantNew: "6.3.0",
			wantMsg: "upgrade kde",
		},
		{
			name:    "set bump with flag message",
			args:    []string{"kde-set", "6.2.0", "6.3.0"},
			flagMsg: "upgrade kde",
			wantSet: "kde-set",
			wantOld: "6.2.0",
			wantNew: "6.3.0",
			wantMsg: "upgrade kde",
		},
		{
			name:    "set bump with inline -m flag",
			args:    []string{"-m", "upgrade kde", "kde-set", "6.2.0", "6.3.0"},
			wantSet: "kde-set",
			wantOld: "6.2.0",
			wantNew: "6.3.0",
			wantMsg: "upgrade kde",
		},
		{
			name:        "too few args",
			args:        []string{"kde-set", "6.2.0"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, old, newVer, msg, err := parseSetBumpArgs(tt.args, tt.flagMsg)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if set != tt.wantSet || old != tt.wantOld || newVer != tt.wantNew || msg != tt.wantMsg {
				t.Errorf("parseSetBumpArgs(%v, %q) = (%q, %q, %q, %q); want (%q, %q, %q, %q)",
					tt.args, tt.flagMsg, set, old, newVer, msg, tt.wantSet, tt.wantOld, tt.wantNew, tt.wantMsg)
			}
		})
	}
}

func TestBumpPackageCustomCommitMessage(t *testing.T) {
	repoDir := t.TempDir()
	oldRepoPaths := repoPaths
	oldSourcesDir := SourcesDir
	oldCacheStore := CacheStore
	repoPaths = repoDir
	SourcesDir = filepath.Join(t.TempDir(), "sources")
	CacheStore = filepath.Join(SourcesDir, "_cache")
	t.Cleanup(func() {
		repoPaths = oldRepoPaths
		SourcesDir = oldSourcesDir
		CacheStore = oldCacheStore
	})

	// Initialize git repo in repoDir
	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v: %s", args, err, string(out))
		}
	}
	runGit("init")
	runGit("config", "user.name", "Hokuto Test")
	runGit("config", "user.email", "test@sauzeros.invalid")

	pkgDir := filepath.Join(repoDir, "testpkg")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	filesDir := filepath.Join(pkgDir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(filesDir, "dummy.txt")
	if err := os.WriteFile(srcFile, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(pkgDir, "version"), []byte("1.0.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, ".sources"), []byte("files/dummy.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "sources"), []byte("files/dummy.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runGit("add", ".")
	runGit("commit", "-m", "initial commit")

	// Test revision bump with custom message
	customMsg := "rebuild for llvm 22.1.8"
	returnedPkgDir, err := bumpPackage("testpkg", "", "1.0.0", customMsg)
	if err != nil {
		t.Fatalf("bumpPackage failed: %v", err)
	}
	if returnedPkgDir != pkgDir {
		t.Fatalf("expected %q, got %q", pkgDir, returnedPkgDir)
	}

	// Verify git commit message in git log
	cmd := exec.Command("git", "-C", pkgDir, "log", "-1", "--pretty=%B")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git log failed: %v", err)
	}
	if !strings.Contains(string(out), customMsg) {
		t.Fatalf("git log %q does not contain expected commit message %q", string(out), customMsg)
	}

	// Verify revision bumped to 2
	verData, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(verData), "1.0.0 2") {
		t.Fatalf("expected version file to contain '1.0.0 2', got %q", string(verData))
	}
}
