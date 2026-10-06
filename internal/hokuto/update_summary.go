package hokuto

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

// locateUpdateBinary finds the binary of the repository's current release
// of pkgName, as the update installs it: the cached archive of the
// preferred variant, else the remote index entry of the preferred or
// generic variant. Nothing is downloaded.
func locateUpdateBinary(pkgName string, cfg *Config, remoteIndex []RepoEntry) (binaryTarball, bool) {
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return binaryTarball{}, false
	}
	archivePkgName := getArchivePackageName(pkgName, cfg)
	arch := GetSystemArchForPackage(cfg, pkgName)
	variant := GetSystemVariantForPackage(cfg, pkgName)
	tarballPath := filepath.Join(BinDir, StandardizeRemoteName(archivePkgName, version, revision, arch, variant))
	if _, err := os.Stat(tarballPath); err == nil {
		return cachedBinaryTarball(archivePkgName, tarballPath), true
	}
	if BinaryMirror == "" || len(remoteIndex) == 0 {
		return binaryTarball{}, false
	}

	fallbackVariant := ""
	if !strings.Contains(variant, "generic") {
		fallbackVariant = "generic"
		if strings.HasPrefix(variant, "multi-") {
			fallbackVariant = "multi-generic"
		}
	}
	var best *RepoEntry
	for i := range remoteIndex {
		entry := &remoteIndex[i]
		if entry.Name != archivePkgName || entry.Version != version || entry.Revision != revision || entry.Arch != arch {
			continue
		}
		if entry.Variant == variant {
			best = entry
			break
		}
		if fallbackVariant != "" && entry.Variant == fallbackVariant {
			best = entry
		}
	}
	if best == nil {
		return binaryTarball{}, false
	}
	return remoteBinaryTarball(archivePkgName, best, cfg), true
}

// splitUpdateBinary is a selected split output updated from its own binary,
// without building its source package.
type splitUpdateBinary struct {
	name    string
	tarball binaryTarball
}

func splitUpdateEntries(splits []splitUpdateBinary) []RepoEntry {
	var entries []RepoEntry
	for _, sb := range splits {
		if sb.tarball.entry != nil {
			entries = append(entries, *sb.tarball.entry)
		}
	}
	return entries
}

// confirmUpdatePlan prints, as pacman does before it asks, what the update
// builds from source and installs from binaries, what it downloads and how
// much the installed size changes, and asks to proceed. It returns true
// without asking with -y, or when the input is not a terminal.
func confirmUpdatePlan(plan *BuildPlan, userRequested, binaryAvailable map[string]bool, updateBinaries map[string]binaryTarball, splits []splitUpdateBinary, cfg *Config, yes bool) bool {
	if (plan == nil || len(plan.Order) == 0) && len(splits) == 0 {
		return true
	}

	builds, binaries, sizes := classifyUpdatePlan(plan, userRequested, binaryAvailable, updateBinaries, splits, cfg)

	if len(builds) > 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("Packages to build (%d): ", len(builds))
		colNote.Println(strings.Join(builds, " "))
		if len(binaries) > 0 {
			colArrow.Print("-> ")
			colSuccess.Printf("Binary packages (%d): ", len(binaries))
			colNote.Println(strings.Join(binaries, " "))
		}
	}
	printRemoteUpdateSizes(sizes)
	if !reportFreeSpace(sizes.download, sizes.net) {
		return false
	}

	if yes || !term.IsTerminal(int(os.Stdin.Fd())) {
		return true
	}
	question := "Proceed with installation?"
	if len(builds) > 0 {
		question = "Proceed with update?"
	}
	colArrow.Print("-> ")
	return askForConfirmation(colSuccess, "%s", question)
}

// classifyUpdatePlan splits plan into what is built from source and what is
// installed from binaries, and adds up the binaries' sizes.
func classifyUpdatePlan(plan *BuildPlan, userRequested, binaryAvailable map[string]bool, updateBinaries map[string]binaryTarball, splits []splitUpdateBinary, cfg *Config) (builds, binaries []string, sizes remoteUpdateSizes) {
	// Split outputs updated from their own binaries go in first.
	for _, sb := range splits {
		binaries = append(binaries, sb.name)
		if isPackageInstalled(sb.name) {
			sizes.addUpgrade(sb.name, sb.tarball.entry, cachedPathOf(sb.tarball))
		} else {
			sizes.addNew(sb.tarball.entry, cachedPathOf(sb.tarball))
		}
	}
	if plan == nil {
		return builds, binaries, sizes
	}
	for _, pkgName := range plan.Order {
		if b, ok := updateBinaries[pkgName]; ok && binaryAvailable[pkgName] {
			binaries = append(binaries, pkgName)
			sizes.addUpgrade(getOutputPackageName(pkgName, cfg), b.entry, cachedPathOf(b))
			continue
		}
		if userRequested[pkgName] || plan.RebuildPackages[pkgName] {
			builds = append(builds, pkgName)
			continue
		}
		if isPackageInstalled(pkgName) {
			continue
		}
		// A dependency the update needs: a binary when there is one (an
		// older one for a build dependency), else it is built too.
		if b, ok, err := locateBuildDependencyBinaryTarball(pkgName, packageBuildConfig(pkgName, cfg), false); err == nil && ok {
			binaries = append(binaries, pkgName)
			sizes.addNew(b.entry, cachedPathOf(b))
			continue
		}
		builds = append(builds, pkgName)
	}
	sizes.built = len(builds)
	return builds, binaries, sizes
}

func cachedPathOf(b binaryTarball) string {
	if b.entry == nil {
		return b.path
	}
	return ""
}
