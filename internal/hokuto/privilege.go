package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type privilegeBackend string

const (
	privilegeBackendUnset privilegeBackend = ""
	privilegeBackendSudo  privilegeBackend = "sudo"
	privilegeBackendRun0  privilegeBackend = "run0"
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
		"settings":  true,
		"alt":       true,
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

	// Check if bump command has auto flag
	if cmd == "bump" {
		for _, arg := range args[1:] {
			if arg == "--auto" || arg == "-auto" {
				return true
			}
		}
	}

	return false
}

func authenticateSudo() error {
	if _, err := exec.LookPath("sudo"); err != nil {
		return err
	}
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func authenticateRun0() error {
	if _, err := exec.LookPath("run0"); err != nil {
		return err
	}
	cmd := exec.Command("run0", "true")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startSudoKeepAlive() {
	go func() {
		ticker := time.NewTicker(4 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			exec.Command("sudo", "-nv").Run()
		}
	}()
}

func newPrivilegedCommand(name string, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.Command(name, args...)
	}
	if activePrivilegeBackend == privilegeBackendRun0 {
		run0Args := append([]string{"--pipe", name}, args...)
		return exec.Command("run0", run0Args...)
	}
	sudoArgs := append([]string{"-E", name}, args...)
	return exec.Command("sudo", sudoArgs...)
}

// authenticateOnce performs a single authentication check at program start
func authenticateOnce(quiet bool) error {
	if os.Geteuid() == 0 {
		return nil // Already root
	}

	if err := authenticateSudo(); err == nil {
		activePrivilegeBackend = privilegeBackendSudo
		startSudoKeepAlive()
		if !quiet {
			colArrow.Print("-> ")
			colSuccess.Println("Authenticated via sudo")
		}
		return nil
	} else {
		debugf("sudo authentication unavailable: %v\n", err)
	}

	if err := authenticateRun0(); err == nil {
		activePrivilegeBackend = privilegeBackendRun0
		if !quiet {
			colArrow.Print("-> ")
			colSuccess.Println("Authenticated via run0")
		}
		return nil
	} else {
		debugf("run0 authentication unavailable: %v\n", err)
	}

	var missing []string
	if _, err := exec.LookPath("sudo"); err != nil {
		missing = append(missing, "sudo")
	}
	if _, err := exec.LookPath("run0"); err != nil {
		missing = append(missing, "run0")
	}
	if len(missing) == 2 {
		return fmt.Errorf("no privilege escalation helper found: %s", strings.Join(missing, ", "))
	}
	return fmt.Errorf("privilege authentication failed with sudo and run0")
}
