package hokuto

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Executor provides a consistent interface for executing commands,
// abstracting away the privilege escalation (sudo) logic.
type Executor struct {
	Context           context.Context // The context to use for cancellation
	ShouldRunAsRoot   bool            // ShouldRunAsRoot specifies whether the command MUST be executed with root privileges.
	ApplyIdlePriority bool            // Apply nice -n 19 to this specific command
	Interactive       bool            // Interactive indicates whether the command may prompt the user
}

// Update the constructor/factory function for Executor
func NewExecutor(ctx context.Context /* other params */) *Executor {
	// ... initialize other fields if necessary
	return &Executor{Context: ctx}
}

// runInteractiveCommand executes a command, ensuring it's attached to the TTY for interactive prompts.
// It does not use process group isolation, making it suitable for commands like `sudo -v`.
func runInteractiveCommand(ctx context.Context, name string, arg ...string) error {
	cmd := exec.CommandContext(ctx, name, arg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ensureSudo checks if the sudo ticket is still valid and re-prompts if necessary.
// It handles interactive re-authentication by running `sudo -v` with a proper TTY
// if the non-interactive check `sudo -nv` fails.
// No action needed if we are already root or the command doesn't require root.
func (e *Executor) ensureSudo() error {
	if os.Geteuid() == 0 || !e.ShouldRunAsRoot {
		return nil
	}
	// 1. First, perform a non-interactive check (`sudo -nv`) to see if the ticket is still valid.
	// This is fast and avoids any user interaction if the ticket is fresh.
	checkCmd := exec.CommandContext(e.Context, "sudo", "-nv")
	checkCmd.Stdout = io.Discard
	checkCmd.Stderr = io.Discard

	if err := checkCmd.Run(); err == nil {
		// Success (exit code 0): The sudo ticket is valid. Nothing more to do.
		return nil
	}

	// Non-interactive check failed — the ticket has likely expired.
	// We must now re-authenticate interactively using `sudo -v`.
	colArrow.Print("-> ")
	colSuccess.Println("Sudo ticket has expired. Re-authenticating")

	// Use a dedicated interactive runner that does NOT set a new process group.
	// This ensures `sudo` can correctly access the TTY for password input.
	if err := runInteractiveCommand(e.Context, "sudo", "-v"); err != nil {
		return fmt.Errorf("sudo re-authentication failed: %w", err)
	}
	colArrow.Print("-> ")
	colSuccess.Println("Re-authenticated via sudo successfully.")
	return nil
}

// Run executes the given command, elevating via sudo -E only when needed.
// It wires up stdio, isolates the child in its own process group for cleanup,
// and calls ensureSudo() to avoid unnecessary password prompts.
func (e *Executor) Run(cmd *exec.Cmd) error {
	// --- Phase 0: wire up stdio ---
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}

	// --- Phase 1: maybe check privilege ---
	if err := e.ensureSudo(); err != nil {
		return err
	}

	// --- Phase 2: build the final command ---
	var finalCmd *exec.Cmd

	basePath := cmd.Path
	baseArgs := cmd.Args[1:]

	// 2b. Apply IDLE/NICENESS wrapper if requested
	if e.ApplyIdlePriority {
		baseArgs = append([]string{"-n", "19", basePath}, baseArgs...)
		basePath = "nice"
	}

	// 2c. Apply privilege wrapper if needed
	if e.ShouldRunAsRoot && os.Geteuid() != 0 {
		// Try run0 first (preferred)
		/*if _, err := exec.LookPath("run0"); err == nil {
			args := []string{}

			// Set working directory if specified
			if cmd.Dir != "" {
				args = append(args, "--working-directory="+cmd.Dir)
			}

			args = append(args, basePath)
			args = append(args, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "run0", args...)

			// Don't set Dir since we used --working-directory
			finalCmd.Dir = ""
		} else {*/
		// Fallback to sudo -E
		{
			args := append([]string{"-E", basePath}, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "sudo", args...)
			finalCmd.Dir = cmd.Dir
		}
	} else {
		finalCmd = exec.CommandContext(e.Context, basePath, baseArgs...)
		finalCmd.Dir = cmd.Dir
	}

	// preserve or inherit the environment
	if len(cmd.Env) > 0 {
		finalCmd.Env = cmd.Env
	} else {
		finalCmd.Env = os.Environ()
	}

	// carry over stdio
	finalCmd.Stdin = cmd.Stdin
	finalCmd.Stdout = cmd.Stdout
	finalCmd.Stderr = cmd.Stderr

	// --- Phase 3: isolate process group for context-based cleanup ---
	if !e.Interactive {
		finalCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	// --- Phase 4: start and watch for cancel ---
	if err := finalCmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	// Conditionally manage cancellation. If interactive, let CommandContext handle it.
	// Otherwise, manage the entire process group.
	if !e.Interactive {
		pgid := finalCmd.Process.Pid

		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-e.Context.Done():
				syscall.Kill(-pgid, syscall.SIGKILL)
			case <-done:
			}
		}()
	}

	// --- Phase 5: wait and return ---
	if waitErr := finalCmd.Wait(); waitErr != nil {
		if e.Context.Err() != nil {
			time.Sleep(100 * time.Millisecond)
			return fmt.Errorf("command aborted: %v", e.Context.Err())
		}
		return waitErr
	}
	return nil
}
