package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// systemdBooted reports whether systemd is the running init, the same test
// sd_booted(3) makes.
func systemdBooted() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// PostInstallTasks runs global post-install hooks like ldconfig, icon cache updates, etc.
func PostInstallTasks(execCtx *Executor, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	fmt.Fprint(logger, colArrow.Sprint("-> "))
	fmt.Fprintln(logger, colSuccess.Sprint("Executing post-install tasks"))

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
		{"/usr/bin/gio-querymodules", []string{"/usr/lib/gio/modules"}},
		{"/usr/bin/gio-querymodules-32", []string{"/usr/lib32/gio/modules"}},
		{"gdk-pixbuf-query-loaders", []string{"--update-cache"}},
		// VLC's plugins come in many split packages; its cache has to follow
		// whichever of them were installed, updated or removed.
		{"/usr/libexec/vlc/vlc-cache-gen", []string{"/usr/lib/vlc/plugins"}},
		//{"update-mime-database", []string{"/usr/share/mime"}},
		{"update-desktop-database", []string{"/usr/share/applications"}},
		{"fc-cache", nil},
	}
	for _, themeDir := range staleIconThemeCaches(iconThemesDir) {
		tasks = append(tasks, struct {
			name string
			args []string
		}{"gtk-update-icon-cache", []string{"-q", "-t", "-f", themeDir}})
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
		// A container that was not booted (hokuto-builder's nspawn, a
		// chroot) has no systemd manager to reload.
		if task.name == "systemctl" && !systemdBooted() {
			debugf("Skipping systemctl daemon-reload: the system was not booted with systemd\n")
			continue
		}
		if _, err := exec.LookPath(task.name); err == nil {
			cmd := exec.Command(task.name, task.args...)
			cmd.Stdout = io.Discard
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			cmd.Stdin = nil
			if err := execCtx.Run(cmd); err != nil {
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

				if err := execCtx.Run(cmd); err != nil {
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

// iconThemesDir holds the icon themes whose caches PostInstallTasks keeps
// current.
var iconThemesDir = "/usr/share/icons"

// staleIconThemeCaches returns the icon themes under iconsDir whose
// icon-theme.cache is missing or older than one of the theme's directories,
// which is how GTK itself decides to ignore a cache. A theme directory left
// with nothing but its cache, by uninstalling the theme, loses the cache and
// the directory.
func staleIconThemeCaches(iconsDir string) []string {
	entries, err := os.ReadDir(iconsDir)
	if err != nil {
		return nil
	}
	var stale []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		themeDir := filepath.Join(iconsDir, entry.Name())
		cachePath := filepath.Join(themeDir, "icon-theme.cache")
		if _, err := os.Stat(filepath.Join(themeDir, "index.theme")); err != nil {
			// gtk-update-icon-cache refuses a directory without an index.
			if contents, err := os.ReadDir(themeDir); err == nil &&
				len(contents) == 1 && contents[0].Name() == "icon-theme.cache" {
				if err := os.Remove(cachePath); err == nil {
					_ = os.Remove(themeDir)
				}
			}
			continue
		}
		cacheInfo, err := os.Stat(cachePath)
		if err != nil {
			stale = append(stale, themeDir)
			continue
		}
		cacheTime := cacheInfo.ModTime()
		newer := errors.New("directory newer than the icon cache")
		walkErr := filepath.WalkDir(themeDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil && info.ModTime().After(cacheTime) {
				return newer
			}
			return nil
		})
		if walkErr == newer {
			stale = append(stale, themeDir)
		}
	}
	return stale
}
