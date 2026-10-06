package hokuto

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// withKmodFixture creates a repository with a kmod recipe (nvidia-open), a
// plain recipe (zlib) and the two kernel recipes, an empty installed db, and
// fakes the installed kernels.
func withKmodFixture(t *testing.T, kernels ...installedKernel) (repo, installed string) {
	t.Helper()
	tmp := t.TempDir()
	repo = filepath.Join(tmp, "repo")
	installed = filepath.Join(tmp, "installed")
	for name, options := range map[string]string{
		"nvidia-open": "kmod\n", "zlib": "", "linux": "", "linux-cachyos": "",
	} {
		dir := filepath.Join(repo, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, data := range map[string]string{"version": "1.0 1\n", "build": "#!/bin/sh\n", "options": options} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(installed, 0o755); err != nil {
		t.Fatal(err)
	}
	oldRepo, oldInstalled, oldLister := repoPaths, Installed, kernelLister
	repoPaths, Installed = repo, installed
	kernelLister = func() []installedKernel { return kernels }
	t.Cleanup(func() { repoPaths, Installed, kernelLister = oldRepo, oldInstalled, oldLister })
	return repo, installed
}

var (
	kernelLinux   = installedKernel{Package: "linux", Release: "7.2.8-sauzerOS"}
	kernelCachyOS = installedKernel{Package: "linux-cachyos", Release: "7.2.8-sauzerOS_C"}
)

func TestKmodInstanceNames(t *testing.T) {
	repo, _ := withKmodFixture(t)
	if base, kernel, ok := splitKmodInstance("nvidia-open~linux-cachyos"); !ok || base != "nvidia-open" || kernel != "linux-cachyos" {
		t.Errorf("split: %q %q %v", base, kernel, ok)
	}
	for _, name := range []string{"nvidia-open", "~linux", "nvidia-open~", "c++utilities"} {
		if _, _, ok := splitKmodInstance(name); ok {
			t.Errorf("%q must not be an instance", name)
		}
	}
	if dir, err := findPackageDir("nvidia-open~linux-cachyos"); err != nil || dir != filepath.Join(repo, "nvidia-open") {
		t.Errorf("findPackageDir(instance) = %q, %v", dir, err)
	}
	if !isKmodRecipe("nvidia-open") || !isKmodRecipe("nvidia-open~linux") || isKmodRecipe("zlib") {
		t.Error("kmod option detection is wrong")
	}
	if !kmodSiblings("nvidia-open~linux", "nvidia-open~linux-cachyos") || !kmodSiblings("nvidia-open", "nvidia-open~linux") {
		t.Error("instances of one kmod recipe must be siblings")
	}
	if kmodSiblings("nvidia-open~linux", "nvidia-open~linux") || kmodSiblings("zlib", "zlib-ng") {
		t.Error("unrelated or identical names must not be siblings")
	}
}

func TestExpandKmodRequests(t *testing.T) {
	cases := []struct {
		name    string
		kernels []installedKernel
		input   string
		yes     bool
		want    []string
		wantErr bool
	}{
		{name: "single kernel, no prompt", kernels: []installedKernel{kernelCachyOS},
			want: []string{"-y", "nvidia-open~linux-cachyos", "zlib"}},
		{name: "pick one of two", kernels: []installedKernel{kernelLinux, kernelCachyOS}, input: "2\n",
			want: []string{"-y", "nvidia-open~linux-cachyos", "zlib"}},
		{name: "default is all", kernels: []installedKernel{kernelLinux, kernelCachyOS}, input: "\n",
			want: []string{"-y", "nvidia-open~linux", "nvidia-open~linux-cachyos", "zlib"}},
		{name: "non-interactive takes all", kernels: []installedKernel{kernelLinux, kernelCachyOS}, yes: true,
			want: []string{"-y", "nvidia-open~linux", "nvidia-open~linux-cachyos", "zlib"}},
		{name: "invalid selection", kernels: []installedKernel{kernelLinux, kernelCachyOS}, input: "3\n", wantErr: true},
		{name: "no kernel installed", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withKmodFixture(t, tc.kernels...)
			got, legacy, err := expandKmodRequests([]string{"-y", "nvidia-open", "zlib"}, tc.yes, bufio.NewReader(strings.NewReader(tc.input)), io.Discard)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if len(legacy) != 0 {
				t.Errorf("nothing is installed, legacy = %v", legacy)
			}
		})
	}
}

func TestExpandKmodRequestsReportsLegacyInstall(t *testing.T) {
	_, installed := withKmodFixture(t, kernelLinux)
	if err := os.MkdirAll(filepath.Join(installed, "nvidia-open"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, legacy, err := expandKmodRequests([]string{"nvidia-open", "nvidia-open~linux"}, false, bufio.NewReader(strings.NewReader("")), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"nvidia-open~linux", "nvidia-open~linux"}) || !slices.Equal(legacy, []string{"nvidia-open"}) {
		t.Errorf("got %v, legacy %v", got, legacy)
	}
}

func TestKmodBuildTarget(t *testing.T) {
	withKmodFixture(t, kernelLinux, kernelCachyOS)

	target, err := kmodBuildTarget("nvidia-open~linux-cachyos")
	if err != nil {
		t.Fatal(err)
	}
	if target.Release != "7.2.8-sauzerOS_C" || target.BuildDir != "/usr/lib/modules/7.2.8-sauzerOS_C/build" || target.KernelPackage != "linux-cachyos" {
		t.Errorf("unexpected target %+v", target)
	}
	env := target.env()
	if env["HOKUTO_KERNEL_RELEASE"] != "7.2.8-sauzerOS_C" || env["HOKUTO_KERNEL_DIR"] != target.BuildDir {
		t.Errorf("unexpected env %v", env)
	}

	if target, err := kmodBuildTarget("zlib"); target != nil || err != nil {
		t.Errorf("plain packages are not kmod targets: %v %v", target, err)
	}
	for _, name := range []string{"nvidia-open", "nvidia-open~linux-rpi4", "zlib~linux"} {
		if _, err := kmodBuildTarget(name); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestKmodVerifyOutputAndPkgInfo(t *testing.T) {
	target := &kmodTarget{Instance: "nvidia-open~linux", KernelPackage: "linux", Release: "7.2.8-sauzerOS"}
	out := t.TempDir()
	if err := target.verifyOutput(out); err == nil {
		t.Error("an output without modules must be rejected")
	}
	if err := os.MkdirAll(filepath.Join(out, "lib", "modules", "7.2.8-sauzerOS", "kernel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := target.verifyOutput(out); err != nil {
		t.Errorf("matching output rejected: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(out, "usr", "lib", "modules", "7.2.8-sauzerOS_C"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := target.verifyOutput(out); err == nil {
		t.Error("modules for another kernel must be rejected")
	}

	infoDir := filepath.Join(out, "var", "db", "hokuto", "installed", target.Instance)
	if err := os.MkdirAll(infoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(infoDir, "pkginfo"), []byte("name=nvidia-open~linux\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := target.recordInPkgInfo(out, target.Instance, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(infoDir, "pkginfo"))
	info := ParsePkgInfo(data)
	if info["name"] != "nvidia-open~linux" || info[kmodReleaseKey] != "7.2.8-sauzerOS" || info[kmodPackageKey] != "linux" {
		t.Errorf("unexpected pkginfo %v", info)
	}
}

func TestCheckKmodStagedRelease(t *testing.T) {
	withKmodFixture(t, kernelLinux)
	if err := checkKmodStagedRelease("zlib", nil); err != nil {
		t.Errorf("plain packages are not checked: %v", err)
	}
	if err := checkKmodStagedRelease("nvidia-open~linux", map[string]string{kmodReleaseKey: "7.2.8-sauzerOS"}); err != nil {
		t.Errorf("matching release rejected: %v", err)
	}
	if err := checkKmodStagedRelease("nvidia-open~linux", map[string]string{kmodReleaseKey: "7.2.7-sauzerOS"}); err == nil {
		t.Error("modules for an older release must be rejected")
	}
	if err := checkKmodStagedRelease("nvidia-open~linux", map[string]string{}); err == nil {
		t.Error("a package without a recorded release must be rejected")
	}
	if err := checkKmodStagedRelease("nvidia-open~linux-cachyos", map[string]string{kmodReleaseKey: "7.2.8-sauzerOS_C"}); err == nil {
		t.Error("an instance for a kernel that is not installed must be rejected")
	}
}

func TestRebuildTriggerMapsKmodToTriggeringKernel(t *testing.T) {
	_, installed := withKmodFixture(t, kernelLinux, kernelCachyOS)
	for _, pkg := range []string{"nvidia-open~linux", "nvidia-open~linux-cachyos", "zlib"} {
		if err := os.MkdirAll(filepath.Join(installed, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installed, pkg, "version"), []byte("1.0 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "hokuto"), 0o755); err != nil {
		t.Fatal(err)
	}
	rules := "linux nvidia-open zlib\nlinux-cachyos nvidia-open\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "hokuto", "hokuto.rebuild"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := getRebuildTriggers("linux-cachyos", root); !slices.Equal(got, []string{"nvidia-open~linux-cachyos"}) {
		t.Errorf("linux-cachyos triggers %v", got)
	}
	if got := getRebuildTriggers("linux", root); !slices.Equal(got, []string{"nvidia-open~linux", "zlib"}) {
		t.Errorf("linux triggers %v", got)
	}
}

// Two instances of one kmod package ship the same /etc file. Installing the
// second must not prompt and must leave the file owned by both.
func TestCheckStagingConflictsSharesFilesBetweenKmodSiblings(t *testing.T) {
	_, installed := withKmodFixture(t, kernelLinux, kernelCachyOS)
	root := t.TempDir()
	staging := t.TempDir()
	const conf = "/etc/modprobe.d/nvidia.conf"
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(installed, "nvidia-open~linux", "manifest"), conf+"  "+strings.Repeat("0", 64)+"\n")
	write(filepath.Join(root, conf), "options nvidia\n")
	write(filepath.Join(staging, conf), "options nvidia\n")
	manifest := filepath.Join(staging, "var", "db", "hokuto", "installed", "nvidia-open~linux-cachyos", "manifest")
	write(manifest, conf+"  "+strings.Repeat("0", 64)+"\n")

	// A prompt would read this empty pipe and fall back to "use new", which
	// gives the same result, so the test also checks nothing was printed.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = outW
	conflictErr := checkStagingConflicts("nvidia-open~linux-cachyos", staging, root, manifest, &Executor{Context: context.Background()}, false, false, map[string]bool{}, nil)
	os.Stdout = oldStdout
	outW.Close()
	printed, _ := io.ReadAll(outR)
	if conflictErr != nil {
		t.Fatal(conflictErr)
	}
	if strings.Contains(string(printed), "Conflicting") {
		t.Errorf("sibling instances must not prompt, printed:\n%s", printed)
	}
	db, err := loadAlternativesDB(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := db.Files[conf]
	if entry == nil || len(entry.Alternatives) != 1 {
		t.Fatalf("identical content must be one shared alternative, got %#v", entry)
	}
	owners := slices.Clone(entry.Alternatives[0].Owners)
	slices.Sort(owners)
	if !slices.Equal(owners, []string{"nvidia-open~linux", "nvidia-open~linux-cachyos"}) {
		t.Errorf("owners %v", owners)
	}
	if _, err := os.Stat(filepath.Join(staging, conf)); err != nil {
		t.Errorf("the incoming file must stay in staging: %v", err)
	}
}

func TestInstalledKernelsFindsOwningPackages(t *testing.T) {
	repo, installed := withKmodFixture(t)
	kernelLister = installedKernels
	_ = repo
	root := t.TempDir()
	oldRoot := rootDir
	rootDir = root
	t.Cleanup(func() { rootDir = oldRoot })

	for _, rel := range []string{"7.2.8-sauzerOS", "7.2.8-sauzerOS_C", "7.2.7-sauzerOS"} {
		if err := os.MkdirAll(filepath.Join(root, "usr", "lib", "modules", rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sum := strings.Repeat("0", 64)
	manifests := map[string]string{
		"linux":         "/boot/vmlinuz-7.2.8-sauzerOS  " + sum + "\n",
		"linux-cachyos": "/boot/vmlinuz-7.2.8-sauzerOS_C  " + sum + "\n",
		// A module instance ships files below the release, not the kernel.
		"nvidia-open~linux": "/usr/lib/modules/7.2.8-sauzerOS/kernel/drivers/video/nvidia.ko  " + sum + "\n",
	}
	for pkg, manifest := range manifests {
		if err := os.MkdirAll(filepath.Join(installed, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installed, pkg, "manifest"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 7.2.7-sauzerOS is a leftover directory no package owns any more.
	got := installedKernels()
	want := []installedKernel{kernelLinux, kernelCachyOS}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if rel, err := kernelReleaseForPackage("linux-cachyos"); err != nil || rel != "7.2.8-sauzerOS_C" {
		t.Errorf("kernelReleaseForPackage = %q, %v", rel, err)
	}
}

func TestLegacyKmodMigration(t *testing.T) {
	_, installed := withKmodFixture(t, kernelLinux, kernelCachyOS)
	sum := strings.Repeat("0", 64)
	for pkg, manifest := range map[string]string{
		// Built for linux-cachyos, listed under the /lib alias.
		"nvidia-open": "/lib/modules/7.2.8-sauzerOS_C/kernel/drivers/video/nvidia.ko.zst  " + sum + "\n",
		"zlib":        "/usr/lib/libz.so.1  " + sum + "\n",
	} {
		if err := os.MkdirAll(filepath.Join(installed, pkg), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(installed, pkg, "manifest"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if kernel, err := legacyKmodKernel("nvidia-open"); err != nil || kernel != "linux-cachyos" {
		t.Errorf("legacyKmodKernel = %q, %v", kernel, err)
	}

	got, replaced := migrateLegacyKmodTargets([]string{"imagemagick", "nvidia-open", "nvidia-open~linux"})
	if !slices.Equal(got, []string{"imagemagick", "nvidia-open~linux-cachyos", "nvidia-open~linux"}) {
		t.Errorf("targets %v", got)
	}
	if len(replaced) != 1 || replaced["nvidia-open~linux-cachyos"] != "nvidia-open" {
		t.Errorf("replaced %v", replaced)
	}

	// The instance was not installed (its build failed): keep the plain package.
	finishLegacyKmodMigration(replaced, &Config{Values: map[string]string{}})
	if _, err := os.Stat(filepath.Join(installed, "nvidia-open")); err != nil {
		t.Errorf("legacy package must stay when its instance is missing: %v", err)
	}
}

func TestLegacyKmodKernelFallback(t *testing.T) {
	_, installed := withKmodFixture(t, kernelLinux)
	if err := os.MkdirAll(filepath.Join(installed, "vhba-module"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Modules for a kernel that is gone: with one kernel left, use it.
	manifest := "/lib/modules/7.2.7-sauzerOS/extra/vhba.ko  " + strings.Repeat("0", 64) + "\n"
	if err := os.WriteFile(filepath.Join(installed, "vhba-module", "manifest"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if kernel, err := legacyKmodKernel("vhba-module"); err != nil || kernel != "linux" {
		t.Errorf("legacyKmodKernel = %q, %v", kernel, err)
	}
	// With two kernels and no match the choice is ambiguous.
	kernelLister = func() []installedKernel { return []installedKernel{kernelLinux, kernelCachyOS} }
	if _, err := legacyKmodKernel("vhba-module"); err == nil {
		t.Error("ambiguous kernel must be reported")
	}
	got, replaced := migrateLegacyKmodTargets([]string{"vhba-module"})
	if !slices.Equal(got, []string{"vhba-module"}) || len(replaced) != 0 {
		t.Errorf("ambiguous package must be left alone: %v %v", got, replaced)
	}
}

func TestAcquireHeadersSharedAcrossParallelBuilds(t *testing.T) {
	buildDir := filepath.Join(t.TempDir(), "build")
	var mu sync.Mutex
	installs, removals := 0, 0
	oldInstall, oldRemove := kmodInstallHeaders, kmodRemoveHeaders
	kmodInstallHeaders = func(name string, cfg *Config) (bool, error) {
		mu.Lock()
		installs++
		mu.Unlock()
		// Slow on purpose: concurrent installs used to overlap here.
		time.Sleep(20 * time.Millisecond)
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return false, err
		}
		return true, os.WriteFile(filepath.Join(buildDir, "Makefile"), nil, 0o644)
	}
	kmodRemoveHeaders = func(name string, cfg *Config) {
		mu.Lock()
		removals++
		mu.Unlock()
		os.RemoveAll(buildDir)
	}
	t.Cleanup(func() { kmodInstallHeaders, kmodRemoveHeaders = oldInstall, oldRemove })

	targets := []string{"nvidia-open~linux", "vhba-module~linux", "vmware-modules~linux", "xpadneo~linux"}
	releases := make([]func(), len(targets))
	var wg sync.WaitGroup
	errs := make([]error, len(targets))
	for i, name := range targets {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			target := &kmodTarget{Instance: name, KernelPackage: "linux", Release: "7.2.8-sauzerOS", BuildDir: buildDir}
			releases[i], errs[i] = target.acquireHeaders(nil)
		}(i, name)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("%s: %v", targets[i], err)
		}
	}
	if installs != 1 {
		t.Fatalf("headers installed %d times, want once", installs)
	}

	// The first build to finish must not pull the headers from the others.
	for i := 0; i < len(releases)-1; i++ {
		releases[i]()
		releases[i]() // releasing twice is harmless
		if removals != 0 {
			t.Fatalf("headers removed while %d build(s) still use them", len(releases)-1-i)
		}
		if _, err := os.Stat(filepath.Join(buildDir, "Makefile")); err != nil {
			t.Fatalf("build tree gone early: %v", err)
		}
	}
	releases[len(releases)-1]()
	if removals != 1 {
		t.Fatalf("headers removed %d times after the last build, want once", removals)
	}
}

func TestAcquireHeadersKeepsHeadersInstalledByTheUser(t *testing.T) {
	buildDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(buildDir, "Makefile"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	oldInstall, oldRemove := kmodInstallHeaders, kmodRemoveHeaders
	kmodInstallHeaders = func(string, *Config) (bool, error) {
		t.Error("present headers must not be installed again")
		return false, nil
	}
	kmodRemoveHeaders = func(string, *Config) { t.Error("headers the user installed must not be removed") }
	t.Cleanup(func() { kmodInstallHeaders, kmodRemoveHeaders = oldInstall, oldRemove })

	target := &kmodTarget{Instance: "xpadneo~linux", KernelPackage: "linux", Release: "7.2.8-sauzerOS", BuildDir: buildDir}
	release, err := target.acquireHeaders(nil)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// Module builds run under the parallel progress line; header messages must
// pause it (the prompt hooks) instead of being appended to it.
func TestKmodHeaderMessagesPauseTheProgressLine(t *testing.T) {
	buildDir := filepath.Join(t.TempDir(), "build")
	oldInstall, oldRemove := kmodInstallHeaders, kmodRemoveHeaders
	kmodInstallHeaders = func(string, *Config) (bool, error) {
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return false, err
		}
		return true, os.WriteFile(filepath.Join(buildDir, "Makefile"), nil, 0o644)
	}
	kmodRemoveHeaders = func(string, *Config) {}
	t.Cleanup(func() { kmodInstallHeaders, kmodRemoveHeaders = oldInstall, oldRemove })

	paused, resumed := 0, 0
	SetPromptHooks(func() { paused++ }, func() { resumed++ })
	t.Cleanup(func() { SetPromptHooks(nil, nil) })

	target := &kmodTarget{Instance: "xpadneo~linux", KernelPackage: "linux", Release: "7.2.8-sauzerOS", BuildDir: buildDir}
	release, err := target.acquireHeaders(nil)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if paused != 1 || resumed != 1 {
		t.Errorf("installing message: progress line paused %d / resumed %d times, want 1 / 1", paused, resumed)
	}
}

// Module rebuilds triggered by a kernel update run one after another: with
// the headers reserved for all of them, they are installed once and removed
// after the last build, not removed and reinstalled between builds.
func TestReserveKmodHeadersKeepsThemAcrossSequentialBuilds(t *testing.T) {
	withKmodFixture(t, kernelLinux)
	buildDir := filepath.Join(t.TempDir(), "build")
	installs, removals := 0, 0
	oldInstall, oldRemove := kmodInstallHeaders, kmodRemoveHeaders
	kmodInstallHeaders = func(name string, cfg *Config) (bool, error) {
		installs++
		if err := os.MkdirAll(buildDir, 0o755); err != nil {
			return false, err
		}
		return true, os.WriteFile(filepath.Join(buildDir, "Makefile"), nil, 0o644)
	}
	kmodRemoveHeaders = func(name string, cfg *Config) {
		removals++
		os.RemoveAll(buildDir)
	}
	t.Cleanup(func() { kmodInstallHeaders, kmodRemoveHeaders = oldInstall, oldRemove })

	release := reserveKmodHeaders([]string{"nvidia-open~linux", "zlib", "nvidia-open~linux"}, nil)
	for _, name := range []string{"nvidia-open~linux", "vhba-module~linux"} {
		target := &kmodTarget{Instance: name, KernelPackage: "linux", Release: kernelLinux.Release, BuildDir: buildDir}
		done, err := target.acquireHeaders(nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		done()
		if removals != 0 {
			t.Fatalf("headers removed after %s although more module builds are planned", name)
		}
	}
	if installs != 1 {
		t.Fatalf("headers installed %d times, want once", installs)
	}
	release()
	release() // releasing twice is harmless
	if removals != 1 {
		t.Fatalf("headers removed %d times after the reservation ended, want once", removals)
	}

	// Nothing reserved for a list without module builds.
	reserveKmodHeaders([]string{"zlib"}, nil)()
	if removals != 1 {
		t.Fatal("a list without module builds must not touch the headers")
	}
}
