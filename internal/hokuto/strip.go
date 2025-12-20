package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

func stripPackage(outputDir string, buildExec *Executor) error {
	colArrow.Print("-> ")
	colSuccess.Println("Stripping executables in parallel")

	var wg sync.WaitGroup

	maxConcurrency := runtime.GOMAXPROCS(0) * 4
	if maxConcurrency < 8 {
		maxConcurrency = 8
	}
	concurrencyLimit := make(chan struct{}, maxConcurrency)

	// --- PHASE 1: Execute 'find' command via the Executor to get the file list ---
	shellCommand := fmt.Sprintf(
		"find %s -type f \\( -perm /u+x -o -perm /g+x -o -perm /o+x \\) -exec sh -c 'file -0 {} 2>/dev/null | grep -q ELF && printf \"%%s\\n\" {}' \\;",
		outputDir,
	)

	var findOutput bytes.Buffer
	findCmd := exec.Command("sh", "-c", shellCommand)
	findCmd.Stdout = &findOutput
	if !Verbose && !Debug {
		findCmd.Stderr = io.Discard
	} else {
		findCmd.Stderr = os.Stderr
	}

	debugf("  -> Discovering stripable ELF files")
	if err := buildExec.Run(findCmd); err != nil {
		return fmt.Errorf("failed to execute file discovery command (find/file filter): %w", err)
	}

	// --- PHASE 2: Process the collected output ---
	pathsRaw := strings.TrimSpace(findOutput.String())
	if pathsRaw == "" {
		debugf("-> No stripable ELF files found.")
		return nil
	}
	paths := strings.Split(pathsRaw, "\n")

	var failedMu sync.Mutex
	var failedFiles []string

	for _, path := range paths {
		if path == "" {
			continue
		}

		wg.Add(1)
		concurrencyLimit <- struct{}{}
		p := path

		go func(p string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			// --- MODIFICATION START ---
			// Define the stderr writer once based on global flags.
			var stderrWriter io.Writer = os.Stderr
			if !Debug && !Verbose {
				stderrWriter = io.Discard
			}
			// --- MODIFICATION END ---

			// Save original permissions
			statCmd := exec.Command("sh", "-c", fmt.Sprintf("stat -c %%a %q", p))
			var permOut bytes.Buffer
			statCmd.Stdout = &permOut
			statCmd.Stderr = stderrWriter // Use the conditional writer

			if err := buildExec.Run(statCmd); err != nil {
				debugf("Warning: failed to stat permissions for %s: %v. Skipping this file.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}
			originalPerms := strings.TrimSpace(permOut.String())
			if originalPerms == "" {
				debugf("Warning: empty perms from stat for %s. Skipping this file.\n", p)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}

			// Ensure we restore perms no matter what
			defer func() {
				restoreCmd := exec.Command("chmod", originalPerms, p)
				restoreCmd.Stderr = stderrWriter // Use the conditional writer
				if err := buildExec.Run(restoreCmd); err != nil {
					debugf("Warning: failed to restore permissions on %s to %s: %v\n", p, originalPerms, err)
				}
			}()

			// Try to grant write permission
			chmodWriteCmd := exec.Command("chmod", "u+w", p)
			chmodWriteCmd.Stderr = stderrWriter // Use the conditional writer
			if err := buildExec.Run(chmodWriteCmd); err != nil {
				debugf("Warning: failed to chmod +w %s: %v. Skipping strip for this file.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}

			debugf("  -> Stripping %s\n", p)
			stripCmd := exec.Command("strip", p)
			stripCmd.Stderr = stderrWriter // Use the conditional writer
			if err := buildExec.Run(stripCmd); err != nil {
				// Log as warning only. Do not mark the whole package as failed.
				debugf("Warning: failed to strip %s: %v. Continuing with other files.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}
		}(p)
	}

	wg.Wait()

	if len(failedFiles) > 0 {
		// Provide an informational summary but do not fail the whole build.
		debugf("Warning: some files failed to be stripped (%d). See above for details. Continuing.\n", len(failedFiles))
	}

	return nil
}
