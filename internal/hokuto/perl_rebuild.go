package hokuto

import (
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// A Perl upgrade that changes the API version (5.42 -> 5.44) breaks every
// compiled extension built against the old one. Instead of rebuilding them on
// each machine when perl is installed, the recipes marked perlxs get a
// revision bump in the repository, so they are rebuilt and published once and
// every machine picks them up as ordinary updates.

// perlXSOption marks a recipe that installs compiled code built against the
// Perl API: XS modules (perl-xml-parser, texinfo's makeinfo) or an embedded
// interpreter (vim). Pure-Perl modules and packages that merely run perl
// scripts survive an API change and don't carry it.
const perlXSOption = "perlxs"

// isPerlXSSymbol matches the interpreter functions an XS object imports. Every
// XS module calls some (Perl_xs_handshake when it loads, since perl 5.22);
// the PL_* globals are optional and the prefix is shared with NSPR's PL_*
// functions (PL_strdup, PL_ArenaAllocate), which made libnss3 look like one.
func isPerlXSSymbol(name string) bool {
	return strings.HasPrefix(name, "Perl_")
}

// findPerlXSObjects returns the shared objects under root, relative to it,
// that import Perl API symbols.
func findPerlXSObjects(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || !strings.Contains(d.Name(), ".so") {
			return nil
		}
		f, err := elf.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		syms, err := f.ImportedSymbols()
		if err != nil {
			return nil
		}
		for _, sym := range syms {
			if isPerlXSSymbol(sym.Name) {
				if rel, err := filepath.Rel(root, path); err == nil {
					found = append(found, "/"+rel)
				}
				break
			}
		}
		return nil
	})
	return found
}

// warnMissingPerlXSOption points at recipes that install XS objects without
// perlxs, since a Perl API bump would otherwise leave them broken.
func warnMissingPerlXSOption(pkgName, outputDir string, options map[string]bool, logger io.Writer) {
	if options[perlXSOption] {
		return
	}
	objects := findPerlXSObjects(outputDir)
	if len(objects) == 0 {
		return
	}
	fmt.Fprintln(logger, colWarn.Sprintf("Warning: %s installs compiled Perl modules (%s) but its options file lacks %q; a Perl API upgrade won't bump it.",
		pkgName, objects[0], perlXSOption))
}

// recipesWithOption returns the recipe directories whose options file has
// option (perlxs, python-rebuild), keyed by package name. When a name exists
// in more than one repository, the first one in HOKUTO_PATH wins, as it does
// for builds.
func recipesWithOption(option string) map[string]string {
	recipes := make(map[string]string)
	seen := make(map[string]bool)
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || seen[name] {
				continue
			}
			pkgDir := filepath.Join(repoPath, name)
			if info, err := os.Stat(filepath.Join(pkgDir, "version")); err != nil || info.IsDir() {
				continue
			}
			seen[name] = true
			if loadBuildOptions(pkgDir)[option] {
				recipes[name] = pkgDir
			}
		}
	}
	return recipes
}

// bumpRecipeRevision rewrites pkgDir/version from "ver N" to "ver N+1" and
// returns the new contents without the trailing newline.
func bumpRecipeRevision(pkgDir string) (string, error) {
	versionPath := filepath.Join(pkgDir, "version")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("version file empty")
	}
	rev := 1
	if len(fields) > 1 {
		if rev, err = strconv.Atoi(fields[1]); err != nil {
			return "", fmt.Errorf("invalid revision %q", fields[1])
		}
	}
	bumped := fmt.Sprintf("%s %d", fields[0], rev+1)
	if err := os.WriteFile(versionPath, []byte(bumped+"\n"), 0o644); err != nil {
		return "", err
	}
	return bumped, nil
}

// perlAPIVersion reduces a perl release to the part its XS ABI follows:
// 5.44.0 -> 5.44. Maintenance releases (5.42.1 -> 5.42.2) keep the ABI.
func perlAPIVersion(version string) string {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1]
}

// currentRecipeVersion returns the first field of a recipe's version file.
func currentRecipeVersion(pkgName string) (string, error) {
	pkgDir, err := findPackageDir(pkgName)
	if err != nil {
		return "", fmt.Errorf("%s: package not found", pkgName)
	}
	data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
	if err != nil {
		return "", fmt.Errorf("%s: could not read version file", pkgName)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s: version file empty", pkgName)
	}
	return fields[0], nil
}

// bumpPerlDependents bumps the revision of every perlxs recipe, then commits
// the version files, one commit per git repository. Nothing is pushed.
func bumpPerlDependents(perlVersion string) error {
	return bumpRecipesWithOption(perlXSOption, fmt.Sprintf("perl %s", perlVersion), fmt.Sprintf("perl %s: bump revision of dependent packages", perlVersion))
}

// bumpRecipesWithOption bumps the revision of every recipe marked option and
// commits the version files with msg, one commit per git repository. Nothing
// is pushed. reason names the upgrade in the progress output.
func bumpRecipesWithOption(option, reason, msg string) error {
	recipes := recipesWithOption(option)
	if len(recipes) == 0 {
		colArrow.Print("-> ")
		colSuccess.Printf("No recipes are marked %s.\n", option)
		return nil
	}
	names := make([]string, 0, len(recipes))
	for name := range recipes {
		names = append(names, name)
	}
	sort.Strings(names)

	colArrow.Print("-> ")
	colSuccess.Printf("Bumping %d recipe(s) for %s\n", len(names), reason)
	byRepo := make(map[string][]string)
	linesByRepo := make(map[string][]string)
	var repoOrder []string
	for _, name := range names {
		pkgDir := recipes[name]
		bumped, err := bumpRecipeRevision(pkgDir)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		colArrow.Print("-> ")
		colSuccess.Printf("%s: %s\n", name, bumped)
		root, err := getGitRepoRoot(pkgDir)
		if err != nil {
			return fmt.Errorf("%s: failed to determine git repo root: %w", name, err)
		}
		if _, ok := byRepo[root]; !ok {
			repoOrder = append(repoOrder, root)
		}
		byRepo[root] = append(byRepo[root], filepath.Join(pkgDir, "version"))
		linesByRepo[root] = append(linesByRepo[root], revisionBumpLine(name, bumped, ""))
	}

	for _, root := range repoOrder {
		if err := commitRevisionBumps(root, msg, linesByRepo[root], byRepo[root]); err != nil {
			return err
		}
	}
	return nil
}

func handlePerlRebuildCommand(cfg *Config) error {
	perlVersion, err := currentRecipeVersion("perl")
	if err != nil {
		return err
	}
	return bumpPerlDependents(perlVersion)
}
