package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"flag"
	"fmt"
	"os/exec"
)

func handleCleanupCommand(args []string, cfg *Config) error {
	cleanupCmd := flag.NewFlagSet("cleanup", flag.ExitOnError)
	cleanSources := cleanupCmd.Bool("sources", false, "Remove all cached source files.")
	cleanBins := cleanupCmd.Bool("bins", false, "Remove all built binary packages.")
	cleanOrphans := cleanupCmd.Bool("orphans", false, "Check and remove orphaned packages.")
	cleanAll := cleanupCmd.Bool("all", false, "sources, binaries and orphans.")

	if err := cleanupCmd.Parse(args); err != nil {
		return err // Should not happen with flag.ExitOnError
	}

	// If no flags are provided, show help and exit
	if !*cleanSources && !*cleanBins && !*cleanAll && !*cleanOrphans {
		fmt.Println("Usage: hokuto cleanup [flag]")
		fmt.Println("You must specify what to clean up. Use one of the following flags:")
		cleanupCmd.PrintDefaults()
		return nil
	}

	// If -all is used, it implies both sources and bins
	if *cleanAll {
		*cleanSources = true
		*cleanBins = true
		*cleanOrphans = true
	}

	if *cleanSources {
		colArrow.Print("-> ")
		cPrintf(colWarn, "Deleting sources cache at %s.\n", SourcesDir)
		if askForConfirmation(colArrow, "Are you sure you want to proceed?") {
			debugf("Removing source cache directory: %s\n", SourcesDir)
			rmCmd := exec.Command("rm", "-rf", SourcesDir)
			if err := RootExec.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove source cache: %w", err)
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
			rmCmd := exec.Command("rm", "-rf", BinDir)
			if err := RootExec.Run(rmCmd); err != nil {
				return fmt.Errorf("failed to remove binary cache: %w", err)
			}
			colArrow.Print("-> ")
			colSuccess.Println("Binary cache removed successfully.")
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Cleanup of binary cache canceled.")
		}
	}

	if *cleanOrphans {
		handleOrphanCleanup(cfg)
	}

	return nil
}
