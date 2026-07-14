package hokuto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"
)

var (
	ErrPrivilegeAuthentication = errors.New("privilege re-authentication failed")
	sudoAuthenticationMu       sync.Mutex
)

// Executor provides a consistent interface for executing commands,
// abstracting away the privilege escalation (sudo) logic.
type Executor struct {
	Context           context.Context // The context to use for cancellation
	ShouldRunAsRoot   bool            // ShouldRunAsRoot specifies whether the command MUST be executed with root privileges.
	ApplyIdlePriority bool            // Apply nice -n 19 to this specific command
	Interactive       bool            // Interactive indicates whether the command may prompt the user
	Stdout            io.Writer       // Optional redirect for Stdout
	Stderr            io.Writer       // Optional redirect for Stderr
	LogPath           string          // Optional path to write output logs to
	Reauthenticate    func() error    // Optional frontend-specific authentication prompt
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

// ensurePrivilege checks if the selected privilege backend is still usable and
// re-prompts if necessary. sudo supports ticket refresh; modern run0 executes
// Hokuto inside one empowered session, while older run0 releases retain the
// per-command compatibility path.
func (e *Executor) ensurePrivilege() error {
	if hasProcessPrivileges() || !e.ShouldRunAsRoot {
		return nil
	}
	if activePrivilegeBackend == privilegeBackendUnset {
		if err := authenticateOnce(true); err != nil {
			return err
		}
	}
	if activePrivilegeBackend == privilegeBackendRun0 {
		if _, err := exec.LookPath("run0"); err != nil {
			return fmt.Errorf("run0 privilege backend is selected but run0 is unavailable: %w", err)
		}
		return nil
	}
	return e.ensureSudo()
}

// ensureSudo checks if the sudo ticket is still valid and re-prompts if necessary.
// It handles interactive re-authentication by running `sudo -v` with a proper TTY
// if the non-interactive check `sudo -nv` fails.
// No action needed if we are already root or the command doesn't require root.
func (e *Executor) ensureSudo() error {
	if hasProcessPrivileges() || !e.ShouldRunAsRoot {
		return nil
	}
	// Keep the normal valid-ticket path lock-free. The mutex below only
	// serializes callers after authentication has actually expired.
	checkCmd := exec.CommandContext(e.Context, "sudo", "-nv")
	checkCmd.Stdout = io.Discard
	checkCmd.Stderr = io.Discard
	if err := checkCmd.Run(); err == nil {
		return nil
	}

	sudoAuthenticationMu.Lock()
	defer sudoAuthenticationMu.Unlock()

	for {
		if e.Context.Err() != nil {
			return e.Context.Err()
		}
		if e.Reauthenticate != nil {
			if err := e.Reauthenticate(); err != nil {
				return fmt.Errorf("%w: %v", ErrPrivilegeAuthentication, err)
			}
			continue
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

		if e.Context.Err() != nil {
			return e.Context.Err()
		}

		// Non-interactive check failed — the ticket has likely expired.
		// We must now re-authenticate interactively using `sudo -v`.
		colArrow.Print("-> ")
		colSuccess.Println("Sudo ticket has expired. Re-authenticating")

		startTime := time.Now()
		// Use a dedicated interactive runner that does NOT set a new process group.
		// This ensures `sudo` can correctly access the TTY for password input.
		err := runInteractiveCommand(e.Context, "sudo", "-v")
		if err == nil {
			colArrow.Print("-> ")
			colSuccess.Println("Re-authenticated via sudo successfully.")
			return nil
		}

		if e.Context.Err() != nil {
			return e.Context.Err()
		}

		// If it's not a terminal or it failed extremely fast (e.g. non-interactive failure or sudo not configured),
		// we should not retry to avoid a tight infinite loop.
		isStdinTerminal := term.IsTerminal(int(os.Stdin.Fd()))
		if !isStdinTerminal || time.Since(startTime) < 2*time.Second {
			return fmt.Errorf("%w: %v", ErrPrivilegeAuthentication, err)
		}

		colArrow.Print("-> ")
		colWarn.Println("Sudo authentication failed or timed out. Retrying...")
		time.Sleep(1 * time.Second)
	}
}

func run0SetenvArgs(env []string) []string {
	args := make([]string, 0, len(env))
	for _, item := range env {
		if item == "" || !strings.Contains(item, "=") {
			continue
		}
		args = append(args, "--setenv="+item)
	}
	return args
}

// Run executes the given command, elevating via the selected backend only when needed.
// It wires up stdio, isolates the child in its own process group for cleanup,
// and calls ensurePrivilege() to avoid unnecessary password prompts.
func (e *Executor) Run(cmd *exec.Cmd) error {
	// --- Phase 0: wire up stdio ---
	// --- Phase 0: wire up stdio ---
	if cmd.Stdin == nil && e.Interactive {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		if e.Stdout != nil {
			cmd.Stdout = e.Stdout
		} else {
			cmd.Stdout = os.Stdout
		}
	}
	if cmd.Stderr == nil {
		if e.Stderr != nil {
			cmd.Stderr = e.Stderr
		} else {
			cmd.Stderr = os.Stderr
		}
	}

	// --- Phase 1: maybe check privilege ---
	if err := e.ensurePrivilege(); err != nil {
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

	// run0 --empower grants the Hokuto session capabilities and the polkit
	// empower group. Commands intentionally assigned to UserExec must lose both
	// before exec, especially package build scripts.
	if !e.ShouldRunAsRoot && isRun0Empowered() {
		if _, err := exec.LookPath("setpriv"); err != nil {
			return fmt.Errorf("cannot drop run0 session privileges for %s: setpriv is unavailable: %w", basePath, err)
		}
		dropArgs := []string{
			"--reuid=" + strconv.Itoa(os.Getuid()),
			"--regid=" + strconv.Itoa(os.Getgid()),
			"--init-groups",
			"--inh-caps=-all",
			"--ambient-caps=-all",
			"--bounding-set=-all",
			"--no-new-privs",
			basePath,
		}
		baseArgs = append(dropArgs, baseArgs...)
		basePath = "setpriv"
	}

	// 2c. Apply privilege wrapper if needed
	if e.ShouldRunAsRoot && !hasProcessPrivileges() {
		switch activePrivilegeBackend {
		case privilegeBackendRun0:
			args := []string{"--pipe"}
			if cmd.Dir != "" {
				args = append(args, "--chdir="+cmd.Dir)
			}
			childEnv := cmd.Env
			if len(childEnv) == 0 {
				childEnv = os.Environ()
			}
			args = append(args, run0SetenvArgs(childEnv)...)
			args = append(args, basePath)
			args = append(args, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "run0", args...)
			finalCmd.Dir = ""
		default:
			args := append([]string{"-E", basePath}, baseArgs...)
			finalCmd = exec.CommandContext(e.Context, "sudo", args...)
			finalCmd.Dir = cmd.Dir
		}
	} else {
		finalCmd = exec.CommandContext(e.Context, basePath, baseArgs...)
		finalCmd.Dir = cmd.Dir
	}

	// preserve or inherit the environment
	if e.ShouldRunAsRoot && !hasProcessPrivileges() && activePrivilegeBackend == privilegeBackendRun0 {
		finalCmd.Env = os.Environ()
	} else if len(cmd.Env) > 0 {
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
