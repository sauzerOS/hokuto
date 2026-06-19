package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func handleCleanupCommand(args []string, cfg *Config) error {
	cleanupCmd := flag.NewFlagSet("cleanup", flag.ExitOnError)
	cleanSources := cleanupCmd.Bool("sources", false, "Remove all cached source files.")
	cleanBins := cleanupCmd.Bool("bins", false, "Remove all built binary packages.")
	cleanOrphans := cleanupCmd.Bool("orphans", false, "Check and remove orphaned packages.")
	cleanTmp := cleanupCmd.Bool("tmp", false, "Remove temporary build directories.")
	cleanAll := cleanupCmd.Bool("all", false, "sources, binaries, orphans and temporary build dirs.")
	packageNumbers := cleanupCmd.String("number", "", "Pre-select packages by number (e.g. 1,2 or -3)")

	if err := cleanupCmd.Parse(args); err != nil {
		return err // Should not happen with flag.ExitOnError
	}

	// If no flags are provided, show help and exit
	if !*cleanSources && !*cleanBins && !*cleanAll && !*cleanOrphans && !*cleanTmp {
		fmt.Println("Usage: hokuto cleanup [flag]")
		fmt.Println("You must specify what to clean up. Use one of the following flags:")
		cleanupCmd.PrintDefaults()
		return nil
	}

	// If -all is used, it implies both sources, bins, orphans, and tmp
	if *cleanAll {
		*cleanSources = true
		*cleanBins = true
		*cleanOrphans = true
		*cleanTmp = true
	}

	if *cleanSources {
		colArrow.Print("-> ")
		cPrintf(colWarn, "Deleting sources cache at %s.\n", SourcesDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing source cache directory: %s\n", SourcesDir)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(SourcesDir); err != nil {
					return fmt.Errorf("failed to remove source cache natively: %w", err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", SourcesDir)
				if err := RootExec.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove source cache: %w", err)
				}
			}
			colArrow.Print("-> ")
			colSuccess.Println("Source cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of source cache canceled.")
		}
	}

	if *cleanBins {
		cPrintf(colWarn, "This will permanently delete all built binary packages at %s.\n", BinDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing binary cache directory: %s\n", BinDir)
			if os.Geteuid() == 0 {
				if err := os.RemoveAll(BinDir); err != nil {
					return fmt.Errorf("failed to remove binary cache natively: %w", err)
				}
			} else {
				rmCmd := exec.Command("rm", "-rf", BinDir)
				if err := RootExec.Run(rmCmd); err != nil {
					return fmt.Errorf("failed to remove binary cache: %w", err)
				}
			}
			colArrow.Print("-> ")
			colSuccess.Println("Binary cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of binary cache canceled.")
		}
	}

	if *cleanOrphans {
		handleOrphanCleanup(cfg, *packageNumbers)
	}

	if *cleanTmp {
		// Get HOKUTO_ROOT if set
		hokutoRoot := os.Getenv("HOKUTO_ROOT")

		tmpDir1 := cfg.Values["TMPDIR"]
		if tmpDir1 == "" {
			tmpDir1 = "/tmp"
		}
		if hokutoRoot != "" {
			tmpDir1 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir1, "/"))
		}

		tmpDir2 := cfg.Values["TMPDIR2"]
		if tmpDir2 == "" {
			tmpDir2 = "/var/tmpdir"
		}
		if hokutoRoot != "" {
			tmpDir2 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir2, "/"))
		}

		var allPaths []string

		if entries, err := os.ReadDir(tmpDir1); err == nil {
			for _, entry := range entries {
				allPaths = append(allPaths, filepath.Join(tmpDir1, entry.Name()))
			}
		}

		if entries, err := os.ReadDir(tmpDir2); err == nil {
			for _, entry := range entries {
				allPaths = append(allPaths, filepath.Join(tmpDir2, entry.Name()))
			}
		}

		if len(allPaths) == 0 {
			colArrow.Print("-> ")
			colSuccess.Println("No temporary build directories or files found to clean.")
		} else {
			colArrow.Print("-> ")
			cPrintf(colWarn, "Found %d items in temporary build directories to delete:\n", len(allPaths))
			for _, path := range allPaths {
				cPrintf(colInfo, "  - %s\n", path)
			}

			if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
				for _, path := range allPaths {
					debugf("Removing temporary build item: %s\n", path)
					if os.Geteuid() == 0 {
						if err := os.RemoveAll(path); err != nil {
							cPrintf(colWarn, "Warning: failed to remove %s natively: %v\n", path, err)
						}
					} else {
						rmCmd := exec.Command("rm", "-rf", path)
						if err := RootExec.Run(rmCmd); err != nil {
							cPrintf(colWarn, "Warning: failed to remove %s: %v\n", path, err)
						}
					}
				}
				colArrow.Print("-> ")
				colSuccess.Println("Temporary build directories cleaned successfully.")
			} else {
				colArrow.Print("-> ")
				colSuccess.Println("Cleanup of temporary build directories canceled.")
			}
		}
	}

	return nil
}
