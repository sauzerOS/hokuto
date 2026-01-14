package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// handlePythonRebuildCommand finds all installed python packages (packages with "python" in the name)
// and rebuilds them. It first ensures build essentials are installed via pip.
func handlePythonRebuildCommand(cfg *Config) error {
	colArrow.Print("-> ")
	colSuccess.Println("Scanning for installed Python packages to rebuild...")

	// 1. Get list of all installed packages
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No packages installed.")
			return nil
		}
		return fmt.Errorf("failed to read installed db: %w", err)
	}

	var pythonPkgs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()

		// Filter for packages with "python" in the name
		// OR explicit packages that depend on python/need rebuild
		extraPkgs := map[string]bool{
			"meson":                 true,
			"protontricks":          true,
			"pyqt-builder":          true,
			"refind-btrfs":          true,
			"streamlink":            true,
			"umu-launcher":          true,
			"btrfs-progs":           true,
			"arandr":                true,
			"gobject-introspection": true,
			"cython":                true,
			"blueman":               true,
			"lutris":                true,
		}

		if strings.Contains(pkgName, "python") || extraPkgs[pkgName] {
			// Exclude the interpreter package itself to avoid chicken-and-egg issues during rebuild?
			// The user requested: "exclude python itself"
			if pkgName == "python" {
				continue
			}
			pythonPkgs = append(pythonPkgs, pkgName)
		}
	}

	if len(pythonPkgs) == 0 {
		colArrow.Print("-> ")
		colSuccess.Println("No Python packages found to rebuild.")
		return nil
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Found %d Python packages: %v\n", len(pythonPkgs), pythonPkgs)

	// 1.5. Force uninstall all identified packages
	colArrow.Print("-> ")
	colSuccess.Println("Force uninstalling all Python packages before rebuild...")

	for _, pkg := range pythonPkgs {
		colArrow.Print("-> ")
		colSuccess.Printf("Uninstalling %s\n", pkg)
		// Force uninstall (force=true, yes=true)
		if err := pkgUninstall(pkg, cfg, RootExec, true, true); err != nil {
			return fmt.Errorf("failed to uninstall package %s: %w", pkg, err)
		}
	}

	// 2. Install build essentials using pip
	colArrow.Print("-> ")
	colSuccess.Println("Installing Python build essentials via pip...")

	// Construct the pip command
	// pip install build flit_core installer packaging pyproject_hooks
	pipCmd := exec.Command("pip", "install", "build", "flit_core", "installer", "packaging", "pyproject_hooks")

	// Set stdout/stderr to inherit so user sees progress
	pipCmd.Stdout = os.Stdout
	pipCmd.Stderr = os.Stderr

	if err := pipCmd.Run(); err != nil {
		return fmt.Errorf("failed to install python build essentials: %w", err)
	}

	// 3. Build python-build-tools first
	colArrow.Print("-> ")
	colSuccess.Println("Building python-build-tools")
	if err := handleBuildCommand([]string{"-a", "python-build-tools"}, cfg); err != nil {
		return fmt.Errorf("failed to build python-build-tools: %w", err)
	}

	// 4. Rebuild the rest of the packages
	colArrow.Print("-> ")
	colSuccess.Println("Starting rebuild of remaining Python packages")

	// Filter out python-build-tools from the main list if present, to avoid redundancy
	var remainingPkgs []string
	for _, pkg := range pythonPkgs {
		if pkg != "python-build-tools" {
			remainingPkgs = append(remainingPkgs, pkg)
		}
	}

	if len(remainingPkgs) > 0 {
		// We pass "-a" to auto-install the packages after build, restoring them to the system.
		buildArgs := append([]string{"-a"}, remainingPkgs...)
		if err := handleBuildCommand(buildArgs, cfg); err != nil {
			return fmt.Errorf("failed to rebuild remaining python packages: %w", err)
		}
	}

	return nil
}
