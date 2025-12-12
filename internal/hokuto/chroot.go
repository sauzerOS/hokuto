package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (e *Executor) ExecuteChroot(targetDir string, cmdArgs []string) (int, error) {
	// First check if systemd-run is available
	_, err := exec.LookPath("systemd-run")
	if err == nil {
		// Build systemd-run invocation that sets RootDirectory and runs the command directly.
		suffix := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
		unitName := "hokuto-chroot-" + filepath.Base(targetDir) + "-" + suffix
		sdArgs := []string{
			"systemd-run", "--pty",
			"--setenv=TERM=xterm",
			"--unit=" + unitName,
			"--description=hokuto chroot " + targetDir,
			"--property=RootDirectory=" + targetDir,
			"--",
		}
		sdArgs = append(sdArgs, cmdArgs...)

		cmd := exec.CommandContext(e.Context, sdArgs[0], sdArgs[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := e.Run(cmd); err != nil {
			return 1, fmt.Errorf("error running chroot via systemd-run: %w", err)
		}
		return 0, nil
	}

	// Fallback: use traditional chroot if systemd-run is not found
	chrootArgs := append([]string{targetDir}, cmdArgs...)
	cmd := exec.CommandContext(e.Context, "chroot", chrootArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := e.Run(cmd); err != nil {
		return 1, fmt.Errorf("error running chroot fallback: %w", err)
	}
	return 0, nil
}

// runChrootCommand encapsulates the chroot logic and GUARANTEES cleanup via defer.

func runChrootCommand(args []string, execCtx *Executor) (exitCode int) {
	// Set default exitCode to 1 (failure) in case we encounter errors before the chrooted command runs.
	exitCode = 1

	if len(args) < 1 {
		fmt.Println("Usage: hokuto chroot <targetdir> [command...]")
		return // Returns exitCode 1
	}

	targetDir := args[0]
	var chrootCmd []string
	if len(args) > 1 {
		chrootCmd = args[1:]
	} else {
		// FIX: Add the interactive flag to prevent hangs on startup
		chrootCmd = []string{"/bin/bash", "-i", "-l"}
	}
	// --- A. DEFERRED CLEANUP (CRITICAL STEP) ---
	pathsToUnmount := []string{
		// Reverse order of mounting, most nested first.
		filepath.Join(targetDir, "tmp"),
		filepath.Join(targetDir, "run"),
		filepath.Join(targetDir, "dev/shm"),
		filepath.Join(targetDir, "dev/pts"),
		// Specific device files must be unmounted BEFORE /dev
		filepath.Join(targetDir, "dev/tty"),
		filepath.Join(targetDir, "dev/console"),
		filepath.Join(targetDir, "dev/null"),
		filepath.Join(targetDir, "dev"),
		//filepath.Join(targetDir, "sys/firmware/efi/efivars"),
		filepath.Join(targetDir, "sys"),
		filepath.Join(targetDir, "proc"),
	}

	// Filter out paths that don't exist before deferring cleanup
	existingPaths := []string{}
	for _, p := range pathsToUnmount {
		if _, err := os.Stat(p); err == nil {
			existingPaths = append(existingPaths, p)
		}
	}

	defer func() {
		colArrow.Print("-> ")
		colSuccess.Println("Starting chroot cleanup")
		// Use the list of paths confirmed to exist
		err := execCtx.UnmountFilesystems(existingPaths)
		if err != nil {
			// ... (error handling for cleanup) ...
		} else {
			colArrow.Print("-> ")
			colSuccess.Println("Successfully unmounted all chroot filesystems.")
		}
	}()

	// --- B. PREPARATION ---
	isCriticalAtomic.Store(1)
	defer isCriticalAtomic.Store(0)

	debugf("[INFO] Setting up specialized mounts in %s \n", targetDir)

	// Helper to reduce verbosity. m now sends the full destination path.
	m := func(source, target string, fsType, options string, isBind bool) error {
		// Construct the full destination path here once: /var/tmp/lfs + /proc = /var/tmp/lfs/proc
		destPath := filepath.Join(targetDir, target)
		return execCtx.executeMountCommand(source, destPath, fsType, options, isBind)
	}
	// NOTE: If any mount fails, the function returns, and the defer block executes.

	// 1. /proc (proc)
	if err := m("proc", "proc", "proc", "nosuid,noexec,nodev", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /proc: %v\n", err)
		return
	}

	// 2. /sys (sysfs)
	if err := m("sys", "sys", "sysfs", "nosuid,noexec,nodev,ro", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /sys: %v\n", err)
		return
	}

	// 3. /sys/firmware/efi/efivars (Conditional mount)
	efiVarsPath := filepath.Join(targetDir, "sys/firmware/efi/efivars")
	if _, err := os.Stat(efiVarsPath); err == nil {
		// ignore_error here, so we don't return on failure.
		m("efivarfs", "sys/firmware/efi/efivars", "efivarfs", "nosuid,noexec,nodev", false)
	}

	// 4. /dev (devtmpfs) - CRITICAL for TTY/ioctl fix
	if err := m("udev", "dev", "devtmpfs", "mode=0755,nosuid", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev: %v\n", err)
		return
	}

	// 5. /dev/pts (devpts)
	if err := m("devpts", "dev/pts", "devpts", "mode=0620,gid=5,nosuid,noexec", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev/pts: %v\n", err)
		return
	}

	// 6. Bind mount essential TTY/device nodes (The ioctl fix)
	if err := m("/dev/ptmx", "dev/ptmx", "", "", true); err != nil { // <-- This now correctly creates a file placeholder
		fmt.Printf("[FATAL] Failed to bind /dev/ptmx: %v\n", err)
		return
	}
	if err := m("/dev/tty", "dev/tty", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/tty: %v\n", err)
		return
	}
	if err := m("/dev/console", "dev/console", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/console: %v\n", err)
		return
	}
	if err := m("/dev/null", "dev/null", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /dev/null: %v\n", err)
		return
	}

	// 7. /dev/shm (tmpfs)
	if err := m("shm", "dev/shm", "tmpfs", "mode=1777,nosuid,nodev", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /dev/shm: %v\n", err)
		return
	}

	// 8. /run (Bind mount with private propagation)
	if err := m("/run", "run", "", "", true); err != nil {
		fmt.Printf("[FATAL] Failed to bind /run: %v\n", err)
		return
	}
	// Execute the propagation step separately
	execCtx.executeMountCommand("", filepath.Join(targetDir, "run"), "", "--make-private", true)

	// 9. /tmp (tmpfs)
	if err := m("tmp", "tmp", "tmpfs", "mode=1777,strictatime,nodev,nosuid", false); err != nil {
		fmt.Printf("[FATAL] Failed to mount /tmp: %v\n", err)
		return
	}

	// --- C. CHROOT EXECUTION ---
	colArrow.Print("-> ")
	colSuccess.Printf("Executing command %v in chroot %s\n", chrootCmd, targetDir)

	finalCode, err := execCtx.ExecuteChroot(targetDir, chrootCmd)

	// Check for errors during execution (not just non-zero exit code)
	if err != nil {
		// Handle the "No such file or directory" error specifically
		if strings.Contains(err.Error(), "No such file or directory") {
			fmt.Printf("[ERROR] Chroot command failure: The target executable '%s' was not found inside %s.\n", chrootCmd[0], targetDir)
			// Set exitCode to 127 (standard for 'command not found')
			exitCode = 127
		} else {
			fmt.Printf("[ERROR] Command failed inside chroot: %v\n", err)
			exitCode = 1
		}
		return // Returns the updated exitCode. The defer will execute now.
	}

	// Success: return the exit code from the chrooted command.
	exitCode = finalCode
	return
}

// getPackageDependenciesToUninstall returns a list of package names to uninstall
// before installing the given package. For Python/Cython packages, it returns the
// package name itself. For specific packages, it returns their associated dependencies.
// Returns an empty slice if no uninstallation is needed.
// This fixes issues with broken pip versions during upgrades and removes bootstrap packages when required.
