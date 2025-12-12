package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

func PostInstallTasks(e *Executor) error {
	colArrow.Print("-> ")
	colSuccess.Println("Executing post-install tasks")
	tasks := []struct {
		name string
		args []string
	}{
		// These are ordered roughly from fastest to slowest
		// to get quick wins out of the way first.
		{"systemctl", []string{"daemon-reload"}},
		{"systemd-sysusers", nil},
		{"systemd-tmpfiles", []string{"--create"}},
		{"ldconfig", nil},
		{"glib-compile-schemas", []string{"/usr/share/glib-2.0/schemas"}},
		{"gdk-pixbuf-query-loaders", []string{"--update-cache"}},
		//{"update-mime-database", []string{"/usr/share/mime"}},
		{"update-desktop-database", []string{"/usr/share/applications"}},
		{"fc-cache", nil},
		{"gtk-update-icon-cache", []string{"-q", "-t", "-f", "/usr/share/icons/hicolor"}},
	}

	// --- Worker Pool Implementation ---

	// Use a number of workers based on CPU count, but cap it to prevent thrashing.
	// 4 is a sensible maximum for this kind of I/O-bound work.
	numWorkers := runtime.NumCPU()
	if numWorkers > 4 {
		numWorkers = 4
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	jobs := make(chan struct {
		name string
		args []string
	}, len(tasks))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	// Start the worker goroutines.
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each worker pulls jobs from the channel until it's closed and empty.
			for job := range jobs {
				if _, err := exec.LookPath(job.name); err != nil {
					debugf("Skipping post-install task: command '%s' not found.\n", job.name)
					continue
				}

				cmd := exec.CommandContext(e.Context, job.name, job.args...)
				cmd.Stdout = io.Discard
				cmd.Stderr = io.Discard
				cmd.Stdin = nil

				if err := e.Run(cmd); err != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s failed: %w", job.name, err))
					mu.Unlock()
				}

				// --- ADD THIS LINE FOR DEBUGGING ---
				// This will print a message every time a task finishes.
				debugf("Completed post-install task: %s\n", job.name)
			}
		}()
	}

	// Feed all the jobs into the channel.
	for _, task := range tasks {
		jobs <- task
	}
	// Close the channel to signal to the workers that no more jobs are coming.
	close(jobs)

	// Wait for all worker goroutines to finish.
	wg.Wait()
	debugf("post-install tasks done")

	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
		return nil // Still treat as non-fatal
	}

	return nil
}

// build package
