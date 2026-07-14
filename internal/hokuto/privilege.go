package hokuto

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type privilegeBackend string

const (
	privilegeBackendUnset privilegeBackend = ""
	privilegeBackendSudo  privilegeBackend = "sudo"
	privilegeBackendRun0  privilegeBackend = "run0"
	run0EmpoweredEnv                       = "HOKUTO_RUN0_EMPOWERED"
)

func isRun0Empowered() bool {
	if os.Getenv(run0EmpoweredEnv) != "1" {
		return false
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	capability := uint(unix.CAP_DAC_OVERRIDE)
	return data[capability/32].Effective&(uint32(1)<<(capability%32)) != 0
}

func hasProcessPrivileges() bool {
	return os.Geteuid() == 0 || isRun0Empowered()
}

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
	cmd := exec.Command("run0", "true")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func run0SupportsEmpower() bool {
	output, err := exec.Command("run0", "--help").Output()
	return err == nil && strings.Contains(string(output), "--empower")
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
	if hasProcessPrivileges() {
		return exec.Command(name, args...)
	}
	if activePrivilegeBackend == privilegeBackendRun0 {
		run0Args := append([]string{"--pipe", name}, args...)
		return exec.Command("run0", run0Args...)
	}
	sudoArgs := append([]string{"-E", name}, args...)
	return exec.Command("sudo", sudoArgs...)
}

func run0ReexecEnvironment() []string {
	keys := make(map[string]bool)
	for _, item := range os.Environ() {
		if key, _, ok := strings.Cut(item, "="); ok && validEnvironmentName(key) {
			keys[key] = true
		}
	}
	keys[run0EmpoweredEnv] = true
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func reexecViaRun0() error {
	run0Path, err := exec.LookPath("run0")
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate hokuto executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("failed to resolve hokuto executable: %w", err)
	}

	args := []string{"run0", "--empower"}
	if cwd, cwdErr := os.Getwd(); cwdErr == nil {
		args = append(args, "--chdir="+cwd)
	}
	for _, item := range run0ReexecEnvironment() {
		args = append(args, "--setenv="+item)
	}
	args = append(args, executable)
	args = append(args, os.Args[1:]...)
	run0Env := append(os.Environ(), run0EmpoweredEnv+"=1")
	if err := syscall.Exec(run0Path, args, run0Env); err != nil {
		return fmt.Errorf("failed to re-execute hokuto through run0: %w", err)
	}
	return nil
}

// authenticateOnce performs a single authentication check at program start
func authenticateOnce(quiet bool) error {
	if os.Geteuid() == 0 {
		return nil // Already root
	}
	if isRun0Empowered() {
		activePrivilegeBackend = privilegeBackendRun0
		if !quiet {
			colArrow.Print("-> ")
			colSuccess.Println("Authenticated via run0")
		}
		return nil
	}
	if activePrivilegeBackend != privilegeBackendUnset {
		return nil
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

	if _, err := exec.LookPath("run0"); err == nil {
		if run0SupportsEmpower() {
			return reexecViaRun0()
		}
		// systemd before v259 has no operation-wide empowered session. Keep
		// the legacy backend functional, even though polkit may authenticate
		// individual transient units on these older releases.
		if err := authenticateRun0(); err == nil {
			activePrivilegeBackend = privilegeBackendRun0
			if !quiet {
				colArrow.Print("-> ")
				colSuccess.Println("Authenticated via run0")
			}
			return nil
		}
		return fmt.Errorf("run0 authentication failed")
	} else {
		debugf("run0 unavailable: %v\n", err)
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
