package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// needsRootPrivileges checks if any of the requested operations require root
func needsRootPrivileges(args []string) bool {
	if len(args) < 1 {
		return false
	}

	cmd := args[0]

	// Commands that require root privileges
	rootCommands := map[string]bool{
		"build":     true,
		"b":         true,
		"bootstrap": true,
		"install":   true,
		"i":         true,
		"uninstall": true,
		"remove":    true,
		"r":         true,
		"update":    true,
		"u":         true,
		"chroot":    true,
		"cleanup":   true,
	}

	if rootCommands[cmd] {
		return true
	}

	// Check if build command has auto-install flag
	if cmd == "build" || cmd == "b" {
		for _, arg := range args[1:] {
			if arg == "-a" {
				return true
			}
		}
	}

	return false
}

// authenticateOnce performs a single authentication check at program start
func authenticateOnce() error {
	if os.Geteuid() == 0 {
		return nil // Already root
	}

	// Try run0 first
	/*if _, err := exec.LookPath("run0"); err == nil {
		// run0 uses polkit - test with a simple command
		cmd := exec.Command("run0", "true")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("run0 authentication failed: %w", err)
		}
		cPrintln(colInfo, "Authenticated via run0")
		return nil
	}*/

	// Fallback to sudo
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo authentication failed: %w", err)
	}

	// Start keep-alive goroutine for sudo
	go func() {
		ticker := time.NewTicker(4 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			exec.Command("sudo", "-nv").Run()
		}
	}()

	//cPrintln(colNote, "-> Authenticated via sudo")
	colArrow.Print("-> ")
	colSuccess.Println("Authenticated via sudo")
	return nil
}
