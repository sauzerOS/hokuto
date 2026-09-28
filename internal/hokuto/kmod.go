package hokuto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// Kernel module packages.
//
// A recipe whose options file contains "kmod" builds out-of-tree kernel
// modules. Such modules only load into the exact kernel release they were
// built against, and a system can have several kernels installed (linux,
// linux-cachyos). So a kmod recipe is never built or installed under its own
// name but once per kernel, as an instance named after the kernel package:
//
//	nvidia-open~linux, nvidia-open~linux-cachyos
//
// The instance name stays the same across kernel updates, so the world file
// and hokuto.rebuild keep working. The exact release a build targeted is
// recorded in its pkginfo (kernel_release, kernel_package) and checked when
// the package is installed. "~" appears in no package name, version syntax or
// archive filename field, so nothing else can be mistaken for an instance.

const (
	kmodOption       = "kmod"
	kmodInstanceSep  = "~"
	kmodReleaseKey   = "kernel_release"
	kmodPackageKey   = "kernel_package"
	kmodHeadersSufix = "-headers"
)

// splitKmodInstance splits "nvidia-open~linux" into its recipe and kernel
// package. ok is false for any other name.
func splitKmodInstance(name string) (base, kernelPkg string, ok bool) {
	base, kernelPkg, ok = strings.Cut(name, kmodInstanceSep)
	if !ok || base == "" || kernelPkg == "" {
		return "", "", false
	}
	return base, kernelPkg, true
}

func kmodInstanceName(base, kernelPkg string) string {
	return base + kmodInstanceSep + kernelPkg
}

// kmodBaseName returns the recipe name behind an instance, or name itself.
func kmodBaseName(name string) string {
	if base, _, ok := splitKmodInstance(name); ok {
		return base
	}
	return name
}

// isKmodRecipe reports whether name (a recipe or an instance of one) is a
// kernel module package.
func isKmodRecipe(name string) bool {
	dir, err := findPackageDir(kmodBaseName(name))
	if err != nil {
		return false
	}
	return loadBuildOptions(dir)[kmodOption]
}

// kmodSiblings reports whether a and b are the same kmod recipe for
// different kernels, or an instance and a legacy install under the bare name.
func kmodSiblings(a, b string) bool {
	if a == b {
		return false
	}
	_, _, aInstance := splitKmodInstance(a)
	_, _, bInstance := splitKmodInstance(b)
	if !aInstance && !bInstance {
		return false
	}
	return kmodBaseName(a) == kmodBaseName(b) && isKmodRecipe(a)
}

type installedKernel struct {
	Package string // kernel package owning the release, e.g. linux-cachyos
	Release string // e.g. 7.2.8-sauzerOS_C
}

// installedKernels lists the kernel releases on the system together with the
// package that installed each one (the owner of /boot/vmlinuz-<release>).
// Releases no package owns, such as module directories left over after a
// kernel update, are skipped.
func installedKernels() []installedKernel {
	root := rootDir
	if root == "" {
		root = "/"
	}
	snapshot := getFileOwnershipSnapshot(root)
	var kernels []installedKernel
	for _, release := range installedKernelReleases(root) {
		owner := ""
		for _, marker := range []string{"/boot/vmlinuz-" + release, "/usr/lib/modules/" + release + "/modules.builtin"} {
			for _, pkg := range snapshot.owners[marker] {
				if !isKmodRecipe(pkg) {
					owner = pkg
					break
				}
			}
			if owner != "" {
				break
			}
		}
		if owner != "" {
			kernels = append(kernels, installedKernel{Package: owner, Release: release})
		}
	}
	sort.Slice(kernels, func(i, j int) bool {
		if kernels[i].Package != kernels[j].Package {
			return kernels[i].Package < kernels[j].Package
		}
		return compareVersions(kernels[i].Release, kernels[j].Release) < 0
	})
	return kernels
}

// kernelReleaseForPackage returns the release installed by kernelPkg, the
// newest one if a kernel update left more than one.
func kernelReleaseForPackage(kernelPkg string) (string, error) {
	release := ""
	for _, k := range kernelLister() {
		if k.Package == kernelPkg {
			release = k.Release
		}
	}
	if release == "" {
		return "", fmt.Errorf("kernel package %s is not installed", kernelPkg)
	}
	return release, nil
}

type kmodTarget struct {
	Instance      string
	Base          string
	KernelPackage string
	Release       string
	BuildDir      string
}

// kmodBuildTarget describes the kernel an instance is built for. It returns
// nil for packages that are not kernel module packages.
func kmodBuildTarget(pkgName string) (*kmodTarget, error) {
	base, kernelPkg, isInstance := splitKmodInstance(pkgName)
	if !isKmodRecipe(pkgName) {
		if isInstance {
			return nil, fmt.Errorf("%s: %s is not a kernel module package (no %q option)", pkgName, base, kmodOption)
		}
		return nil, nil
	}
	if !isInstance {
		return nil, fmt.Errorf("%s is a kernel module package; build it for a kernel as %s (installed kernels: %s)",
			pkgName, kmodInstanceName(pkgName, "<kernel>"), describeInstalledKernels())
	}
	release, err := kernelReleaseForPackage(kernelPkg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pkgName, err)
	}
	return &kmodTarget{
		Instance:      pkgName,
		Base:          base,
		KernelPackage: kernelPkg,
		Release:       release,
		BuildDir:      filepath.Join("/usr/lib/modules", release, "build"),
	}, nil
}

func describeInstalledKernels() string {
	var parts []string
	for _, k := range kernelLister() {
		parts = append(parts, fmt.Sprintf("%s (%s)", k.Package, k.Release))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// env is exported to the build script. Recipes use HOKUTO_KERNEL_DIR as the
// kernel build tree and HOKUTO_KERNEL_RELEASE as the module install release.
func (t *kmodTarget) env() map[string]string {
	return map[string]string{
		"HOKUTO_KERNEL_RELEASE": t.Release,
		"HOKUTO_KERNEL_DIR":     t.BuildDir,
		"HOKUTO_KERNEL_PACKAGE": t.KernelPackage,
	}
}

// ensureHeaders makes the target kernel's build tree available, installing
// its headers package (<kernel>-headers) from a binary when needed. It
// returns what it installed so the caller can remove it after the build.
func (t *kmodTarget) ensureHeaders(cfg *Config) ([]string, error) {
	if fi, err := os.Stat(filepath.Join(t.BuildDir, "Makefile")); err == nil && !fi.IsDir() {
		return nil, nil
	}
	headers := t.KernelPackage + kmodHeadersSufix
	colArrow.Print("-> ")
	colSuccess.Printf("Installing %s for %s\n", headers, t.Instance)
	installed, err := installAvailableBuildDependencyBinaryWithOptions(headers, cfg, false, false, true)
	if err != nil {
		return nil, fmt.Errorf("failed to install %s: %w", headers, err)
	}
	if fi, err := os.Stat(filepath.Join(t.BuildDir, "Makefile")); err != nil || fi.IsDir() {
		return nil, fmt.Errorf("%s: no kernel build tree at %s; build and install %s for kernel %s first", t.Instance, t.BuildDir, headers, t.Release)
	}
	if installed {
		return []string{headers}, nil
	}
	return nil, nil
}

// verifyOutput checks that the package only ships modules for the target
// release, catching recipes that picked some other kernel on their own.
func (t *kmodTarget) verifyOutput(outputDir string) error {
	var releases []string
	for _, base := range []string{"lib/modules", "usr/lib/modules"} {
		entries, err := os.ReadDir(filepath.Join(outputDir, base))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				releases = append(releases, e.Name())
			}
		}
	}
	if len(releases) == 0 {
		return fmt.Errorf("%s: package contains no /lib/modules/%s directory", t.Instance, t.Release)
	}
	for _, r := range releases {
		if r != t.Release {
			return fmt.Errorf("%s: built for kernel %s but the target is %s; the recipe must use HOKUTO_KERNEL_DIR and HOKUTO_KERNEL_RELEASE", t.Instance, r, t.Release)
		}
	}
	return nil
}

// recordInPkgInfo appends the target kernel to the package's pkginfo.
func (t *kmodTarget) recordInPkgInfo(outputDir, outputPkgName string, execCtx *Executor) error {
	path := filepath.Join(outputDir, "var", "db", "hokuto", "installed", outputPkgName, "pkginfo")
	lines := fmt.Sprintf("%s=%s\n%s=%s\n", kmodReleaseKey, t.Release, kmodPackageKey, t.KernelPackage)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err == nil {
		_, werr := f.WriteString(lines)
		cerr := f.Close()
		return errors.Join(werr, cerr)
	}
	if execCtx == nil {
		return err
	}
	cmd := exec.Command("tee", "-a", path)
	cmd.Stdin = strings.NewReader(lines)
	cmd.Stdout = nil
	return execCtx.Run(cmd)
}

// checkKmodStagedRelease refuses to install a kmod instance whose modules
// were built for a different release than the one its kernel package has
// installed, e.g. a mirror binary from before the last kernel update.
func checkKmodStagedRelease(pkgName string, pkgInfo map[string]string) error {
	_, kernelPkg, ok := splitKmodInstance(pkgName)
	if !ok {
		return nil
	}
	built := pkgInfo[kmodReleaseKey]
	if built == "" {
		return fmt.Errorf("%s: package does not record the kernel it was built for; rebuild it with hokuto build %s", pkgName, pkgName)
	}
	installed, err := kernelReleaseForPackage(kernelPkg)
	if err != nil {
		return fmt.Errorf("%s: %w", pkgName, err)
	}
	if built != installed {
		return fmt.Errorf("%s was built for kernel %s but %s is %s now; rebuild it with hokuto build %s", pkgName, built, kernelPkg, installed, pkgName)
	}
	return nil
}

// kernelLister is installedKernels, replaceable in tests.
var kernelLister = installedKernels

// expandKmodRequests replaces bare kernel module package names in a list of
// package requests with their per-kernel instances. With one kernel
// installed that kernel is used; with several the user picks one or more,
// and non-interactive runs (assumeYes) take all of them. Flags, paths,
// archives and names that already are instances pass through unchanged.
// legacy lists bare names that are installed from before kernel tracking.
func expandKmodRequests(args []string, assumeYes bool, in *bufio.Reader, out io.Writer) (expanded, legacy []string, err error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") || strings.Contains(arg, "/") || strings.HasSuffix(arg, ".tar.zst") {
			expanded = append(expanded, arg)
			continue
		}
		if _, _, isInstance := splitKmodInstance(arg); isInstance || !isKmodRecipe(arg) {
			expanded = append(expanded, arg)
			continue
		}
		kernels := kernelLister()
		if len(kernels) == 0 {
			return nil, nil, fmt.Errorf("%s is a kernel module package, but no installed kernel was found", arg)
		}
		chosen := kernels
		if len(kernels) > 1 && !assumeYes {
			if chosen, err = promptKernelChoice(arg, kernels, in, out); err != nil {
				return nil, nil, err
			}
		}
		for _, k := range chosen {
			expanded = append(expanded, kmodInstanceName(arg, k.Package))
		}
		if info, statErr := os.Stat(filepath.Join(Installed, arg)); statErr == nil && info.IsDir() {
			legacy = append(legacy, arg)
		}
	}
	return expanded, legacy, nil
}

func promptKernelChoice(pkg string, kernels []installedKernel, in *bufio.Reader, out io.Writer) ([]installedKernel, error) {
	fmt.Fprintf(out, "%s is a kernel module package. Which kernel(s)?\n", pkg)
	for i, k := range kernels {
		fmt.Fprintf(out, "  %d) %s (%s)\n", i+1, k.Package, k.Release)
	}
	fmt.Fprint(out, "Select [a]ll or numbers (e.g. 1 2) [a]: ")
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("no kernel selected for %s", pkg)
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" || line == "a" || line == "all" {
		return kernels, nil
	}
	var chosen []installedKernel
	seen := make(map[int]bool)
	for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == ',' }) {
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > len(kernels) {
			return nil, fmt.Errorf("invalid kernel selection %q for %s", field, pkg)
		}
		if !seen[n] {
			seen[n] = true
			chosen = append(chosen, kernels[n-1])
		}
	}
	return chosen, nil
}

// kmodPromptAssumesYes reports whether the kernel choice must not be asked:
// -y was given or there is no terminal to ask on.
func kmodPromptAssumesYes(yes bool) bool {
	return yes || isExplicitYes() || !term.IsTerminal(int(os.Stdin.Fd()))
}
