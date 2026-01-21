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

// PostInstallTasks runs common system cache updates after package installs.
// It uses a worker pool to execute tasks with limited concurrency,
// preventing I/O contention and providing a significant speedup.

func PostInstallTasks(e *Executor) error {
	colArrow.Print("-> ")
	colSuccess.Println("Executing post-install tasks")

	var mu sync.Mutex
	var errs []error
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

	// Run systemctl, systemd-sysusers, and systemd-tmpfiles sequentially first.
	// These tools have inter-dependencies and should not be run in parallel.
	sequentialTasks := []struct {
		name string
		args []string
	}{
		{"systemctl", []string{"daemon-reload"}},
		{"systemd-sysusers", nil},
		{"systemd-tmpfiles", []string{"--create"}},
	}

	for _, task := range sequentialTasks {
		if _, err := exec.LookPath(task.name); err == nil {
			cmd := exec.Command(task.name, task.args...)
			cmd.Stdout = io.Discard
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			cmd.Stdin = nil
			if err := e.Run(cmd); err != nil {
				debugf("%s failed: %v\n", task.name, err)
				mu.Lock()
				errMsg := fmt.Errorf("%s failed: %w", task.name, err)
				if stderr.Len() > 0 {
					errMsg = fmt.Errorf("%s failed: %w\n  %s", task.name, err, strings.TrimSpace(stderr.String()))
				}
				errs = append(errs, errMsg)
				mu.Unlock()
			}
		}
	}

	// --- Worker Pool Implementation ---

	// Use a number of workers based on CPU count, but cap it to prevent thrashing.
	// 4 is a sensible maximum for this kind of I/O-bound work.
	numWorkers := max(min(runtime.NumCPU(), 4), 1)

	// Filter out the sequential tasks from the parallel pool
	parallelTasks := make([]struct {
		name string
		args []string
	}, 0, len(tasks)-len(sequentialTasks))
	for _, task := range tasks {
		isSequential := false
		for _, seqTask := range sequentialTasks {
			if task.name == seqTask.name {
				isSequential = true
				break
			}
		}
		if !isSequential {
			parallelTasks = append(parallelTasks, task)
		}
	}

	jobs := make(chan struct {
		name string
		args []string
	}, len(parallelTasks))
	var wg sync.WaitGroup

	// Start the worker goroutines.
	for range numWorkers {
		wg.Go(func() {
			// Each worker pulls jobs from the channel until it's closed and empty.
			for job := range jobs {
				if _, err := exec.LookPath(job.name); err != nil {
					debugf("Skipping post-install task: command '%s' not found.\n", job.name)
					continue
				}

				// Create command without context first - e.Run will create the final command with context
				cmd := exec.Command(job.name, job.args...)
				cmd.Stdout = io.Discard
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				cmd.Stdin = nil

				if err := e.Run(cmd); err != nil {
					mu.Lock()
					errMsg := fmt.Errorf("%s failed: %w", job.name, err)
					if stderr.Len() > 0 {
						errMsg = fmt.Errorf("%s failed: %w\n  %s", job.name, err, strings.TrimSpace(stderr.String()))
					}
					errs = append(errs, errMsg)
					mu.Unlock()
				}

				// --- ADD THIS LINE FOR DEBUGGING ---
				// This will print a message every time a task finishes.
				debugf("Completed post-install task: %s\n", job.name)
			}
		})
	}

	// Feed all the jobs into the channel.
	for _, task := range parallelTasks {
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
