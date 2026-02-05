package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gookit/color"
)

type syncPackage struct {
	Full     string
	Base     string
	Version  string
	Revision string
}

func handleCrossSyncCommand(args []string, cfg *Config) error {
	nativeMode := false
	for _, arg := range args {
		if arg == "-native" {
			nativeMode = true
			break
		}
	}

	// Fetch remote index early
	colArrow.Print("-> ")
	colSuccess.Println("Checking remote repository index")
	remoteIndex, _ := FetchRemoteIndex(cfg)

	var targetPkgs []syncPackage

	if nativeMode {
		colArrow.Print("-> ")
		colSuccess.Println("Scanning repository for existing native aarch64 packages")

		// Pre-filter: only care about packages that already have at least one aarch64 entry on the mirror
		supportedOnMirror := make(map[string]bool)
		for _, entry := range remoteIndex {
			if entry.Arch == "aarch64" {
				supportedOnMirror[entry.Name] = true
			}
		}

		paths := filepath.SplitList(repoPaths)
		seen := make(map[string]bool)

		for _, base := range paths {
			entries, err := os.ReadDir(base)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() || seen[e.Name()] {
					continue
				}
				pkgName := e.Name()

				// User said: only check for packages that already have a native aarch64 on the binary repo
				if !supportedOnMirror[pkgName] {
					continue
				}

				pkgDir := filepath.Join(base, pkgName)

				// Read version
				verPath := filepath.Join(pkgDir, "version")
				verData, err := os.ReadFile(verPath)
				if err != nil {
					continue
				}
				fields := strings.Fields(string(verData))
				if len(fields) == 0 {
					continue
				}
				version := fields[0]
				revision := "1"
				if len(fields) >= 2 {
					revision = fields[1]
				}

				targetPkgs = append(targetPkgs, syncPackage{
					Full:     pkgName,
					Base:     pkgName,
					Version:  version,
					Revision: revision,
				})
				seen[pkgName] = true
			}
		}
	} else {
		colArrow.Print("-> ")
		colSuccess.Println("Scanning for cross-system toolchain packages (aarch64-*)")

		// 1. Get installed packages
		entries, err := os.ReadDir(Installed)
		if err != nil {
			return fmt.Errorf("failed to read installed database: %w", err)
		}

		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, "aarch64-") {
				baseName := strings.TrimPrefix(name, "aarch64-")
				version, revision, err := getInstalledVersionAndRevision(name)
				if err != nil {
					debugf("Warning: failed to get version for %s: %v\n", name, err)
					continue
				}
				targetPkgs = append(targetPkgs, syncPackage{
					Full:     name,
					Base:     baseName,
					Version:  version,
					Revision: revision,
				})
			}
		}
	}

	if len(targetPkgs) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No packages found to sync.")
		return nil
	}

	var missing []syncPackage
	for _, pkg := range targetPkgs {
		found := false

		// 3a. Check Local Binary Cache
		variants := []string{"optimized", "generic"}
		for _, variant := range variants {
			filename := StandardizeRemoteName(pkg.Base, pkg.Version, pkg.Revision, "aarch64", variant)
			localPath := filepath.Join(BinDir, filename)
			if _, err := os.Stat(localPath); err == nil {
				found = true
				break
			}
		}

		if found {
			continue
		}

		// 3b. Check Remote Repository
		for _, entry := range remoteIndex {
			if entry.Name == pkg.Base && entry.Version == pkg.Version && entry.Revision == pkg.Revision && entry.Arch == "aarch64" {
				found = true
				break
			}
		}

		if !found {
			missing = append(missing, pkg)
		}
	}

	if len(missing) == 0 {
		colArrow.Print("-> ")
		if nativeMode {
			colSuccess.Println("All tracked repository packages have corresponding native aarch64 binaries.")
		} else {
			colSuccess.Println("All installed cross-tool packages have corresponding native cross binaries.")
		}
		return nil
	}

	// 4. Print Missing List
	fmt.Println()
	if nativeMode {
		colSuccess.Println("Missing or outdated native aarch64 packages:")
	} else {
		colSuccess.Println("Missing native cross packages:")
	}
	for i, pkg := range missing {
		colArrow.Print("-> ")
		fmt.Printf("%2d) ", i+1)
		color.Bold.Printf("%s", pkg.Base)
		fmt.Printf(" (%s-%s)\n", pkg.Version, pkg.Revision)
	}
	fmt.Println()

	// 5. User Interaction
	promptMsg := "Build (a)ll or pick packages to build (numbers or -numbers):"
	indices, ok := AskForSelection(promptMsg, len(missing))
	if !ok {
		colNote.Println("Operation canceled.")
		return nil
	}

	var toBuild []syncPackage
	for _, idx := range indices {
		toBuild = append(toBuild, missing[idx])
	}

	// 6. Execute Build
	colArrow.Print("-> ")
	colSuccess.Printf("Starting build for %d packages\n", len(toBuild))
	for _, pkg := range toBuild {
		fmt.Println()
		colArrow.Print("-> ")
		if nativeMode {
			color.Bold.Printf("Building native aarch64 package: %s\n", pkg.Base)
		} else {
			color.Bold.Printf("Building native cross package: %s\n", pkg.Base)
		}

		buildArgs := []string{"--cross=arm64", pkg.Base}
		if err := handleBuildCommand(buildArgs, cfg); err != nil {
			colError.Printf("Failed to build %s: %v\n", pkg.Base, err)
			colWarn.Println("Continuing with remaining packages")
		}
	}

	return nil
}

func getInstalledVersionAndRevision(pkgName string) (string, string, error) {
	versionFile := filepath.Join(Installed, pkgName, "version")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return "", "", fmt.Errorf("empty version file")
	}
	version := fields[0]
	revision := "1"
	if len(fields) >= 2 {
		revision = fields[1]
	}
	return version, revision, nil
}
