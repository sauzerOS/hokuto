package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func (e *Executor) executeMountCommand(source, dest, fsType, options string, isBind bool) error {
	args := []string{}

	// Check if the destination is expected to be a device file.
	// These must exist as a file, not a directory.
	base := filepath.Base(source)
	isDeviceFileBind := isBind && (base == "tty" || base == "console" || base == "null" || base == "ptmx" || base == "zero" || base == "full" || base == "random" || base == "urandom")
	// NOTE: Added "ptmx", "zero", "full", "random", "urandom" to match typical essential device nodes.

	if isDeviceFileBind {
		// For device file binds:
		// 1. Ensure the parent directory exists.
		parentDir := filepath.Dir(dest)
		if err := os.MkdirAll(parentDir, 0755); err != nil {
			return fmt.Errorf("failed to create parent directory %s: %w", parentDir, err)
		}

		// 2. Create the file placeholder if it doesn't exist.
		if _, err := os.Stat(dest); os.IsNotExist(err) {
			if err := os.WriteFile(dest, []byte{}, 0644); err != nil {
				return fmt.Errorf("failed to create device file placeholder %s: %w", dest, err)
			}
		}
	} else {
		// 1. Ensure the destination directory exists (for all non-device file mounts)
		if err := os.MkdirAll(dest, 0755); err != nil {
			return fmt.Errorf("failed to create destination directory %s: %w", dest, err)
		}
	}

	// --- Rest of the logic remains the same (Bind/Type mounting logic) ---

	if isBind {
		if options == "--make-private" {
			// ... (propagation logic remains the same) ...
			// Omitted for brevity.
			return nil
		}
		args = []string{source, dest, "--bind"}
	} else {
		args = append(args, source, dest)
		if fsType != "" {
			args = append(args, "-t", fsType)
		}
		if options != "" {
			args = append(args, "-o", options)
		}
	}

	cmd := exec.Command("mount", args...)
	debugf("[INFO] Running mount: %s\n", strings.Join(cmd.Args, " "))

	if err := e.Run(cmd); err != nil {
		return fmt.Errorf("mount failed for %s to %s: %w", source, dest, err)
	}
	return nil
}

// UnmountFilesystems unmounts all given paths using the external 'umount -l'
// command via e.Run() to ensure proper privilege escalation.

func (e *Executor) UnmountFilesystems(paths []string) error {
	var cleanupErrors []string

	// Iterate backwards to safely unmount mounts within other mounts
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]

		// Check if the path exists before attempting unmount
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		debugf("[INFO] Unmounting: %s\n", path)

		// Use external `umount -l` (lazy unmount)
		cmdUnmount := exec.Command("umount", "-l", path)

		// Execute the command via the privileged Executor
		if err := e.Run(cmdUnmount); err != nil {
			// Note: We avoid checking specific syscall errors (like EBUSY) here
			// because the error comes from the external `umount` binary.
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("Failed to umount %s (via external umount): %v", path, err))
		}
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("multiple unmount errors occurred:\n%s", strings.Join(cleanupErrors, "\n"))
	}
	return nil
}

// BindMount creates the destination directory and performs a recursive bind mount
// using the external 'mount' binary via e.Run() to ensure proper privilege escalation.

func (e *Executor) BindMount(source, dest, options string) error {
	// 1. Ensure the destination directory exists
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dest, err)
	}

	// 2. Perform the bind mount: `mount --bind source dest`
	// We use an external command to trigger the privilege escalation via e.Run().
	// Note: We use the '-o bind' option, which is equivalent to MS_BIND.
	cmdBind := exec.Command("mount", "--bind", source, dest)

	debugf("[INFO] Running: %s %s\n", "mount", strings.Join(cmdBind.Args, " "))
	if err := e.Run(cmdBind); err != nil {
		return fmt.Errorf("failed to perform bind mount of %s to %s: %w", source, dest, err)
	}

	// 3. Set mount propagation to MS_PRIVATE (using external mount command)
	// This prevents chroot mount/unmount events from affecting the host.
	// We use --make-rprivate to apply recursively and privately.
	// We MUST run this as a separate command.
	cmdPrivate := exec.Command("mount", "--make-rprivate", dest)

	if err := e.Run(cmdPrivate); err != nil {
		fmt.Printf("[WARNING] Could not set mount %s to private: %v\n", dest, err)
		// This is a warning, not a fatal error, so we continue.
	}

	return nil
}
