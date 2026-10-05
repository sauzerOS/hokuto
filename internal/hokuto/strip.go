package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// stripBinary returns the strip executable a package's output should be run
// through.
//
// A cross build emits target binaries and the host strip cannot read them, so
// the cross toolchain's strip is used. The exceptions mirror the toolchain
// selection in pkgBuild's environment setup: cross-simple mode, and
// "host-tool" packages under cross-system, both produce build-machine binaries
// and want the plain host strip.
func stripBinary(cfg *Config, options map[string]bool) string {
	const hostStrip = "strip"
	if cfg == nil {
		return hostStrip
	}
	crossArch := cfg.Values["HOKUTO_CROSS_ARCH"]
	if crossArch == "" || cfg.Values["HOKUTO_CROSS_SIMPLE"] == "1" {
		return hostStrip
	}
	if options["host-tool"] && cfg.Values["HOKUTO_CROSS_SYSTEM"] == "1" {
		return hostStrip
	}
	if crossArch == "arm64" {
		crossArch = "aarch64"
	}
	return crossArch + "-linux-gnu-strip"
}

func stripPackage(outputDir string, stripStaticArchives bool, stripBin string, buildExec *Executor, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	if stripBin == "" {
		stripBin = "strip"
	}
	fmt.Fprint(logger, colArrow.Sprint("-> "))
	if stripStaticArchives {
		fmt.Fprintln(logger, colSuccess.Sprint("Stripping executables and static archives in parallel"))
	} else {
		fmt.Fprintln(logger, colSuccess.Sprint("Stripping executables in parallel"))
	}

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
	var paths []string
	if pathsRaw := strings.TrimSpace(findOutput.String()); pathsRaw != "" {
		paths = strings.Split(pathsRaw, "\n")
	}

	if stripStaticArchives {
		err := filepath.WalkDir(outputDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".a") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to discover static archives: %w", err)
		}
	}

	if len(paths) == 0 {
		debugf("-> No stripable files found.")
		return nil
	}

	// One name per file: strip keeps a file's hard links by writing the
	// result back into it through a temporary stXXXXXX file, so stripping
	// two names of one file at once raced, and the loser left its temporary
	// file behind (binutils: /usr/bin/aarch64-linux-gnu-ld and
	// /usr/aarch64-linux-gnu/bin/ld). Stripped once, every name has it.
	paths = uniqueFilesByInode(paths)
	leftoverWatch := snapshotStripTempNames(paths)
	defer removeStripLeftovers(leftoverWatch, buildExec)

	var failedMu sync.Mutex
	var failedFiles []string

	for _, path := range paths {
		if path == "" {
			continue
		}

		wg.Add(1)
		concurrencyLimit <- struct{}{}
		p := path
		isStaticArchive := stripStaticArchives && strings.HasSuffix(path, ".a")

		go func(p string, isStaticArchive bool) {
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
			statCmd := exec.Command("stat", "-c", "%a", p)
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

			stripArgs := []string{p}
			if isStaticArchive {
				// Preserve the symbols and object code needed by the linker while
				// removing DWARF data from archive members.
				stripArgs = []string{"--strip-debug", p}
			}
			debugf("  -> Stripping %s\n", p)
			stripCmd := exec.Command(stripBin, stripArgs...)
			stripCmd.Stderr = stderrWriter // Use the conditional writer
			if err := buildExec.Run(stripCmd); err != nil {
				// Log as warning only. Do not mark the whole package as failed.
				debugf("Warning: failed to strip %s: %v. Continuing with other files.\n", p, err)
				failedMu.Lock()
				failedFiles = append(failedFiles, p)
				failedMu.Unlock()
				return
			}
		}(p, isStaticArchive)
	}

	wg.Wait()

	if len(failedFiles) > 0 {
		// Provide an informational summary but do not fail the whole build.
		debugf("Warning: some files failed to be stripped (%d). See above for details. Continuing.\n", len(failedFiles))
	}

	return nil
}

// uniqueFilesByInode keeps the first name of each file among paths; a name
// that cannot be stat-ed is kept.
func uniqueFilesByInode(paths []string) []string {
	seen := make(map[[2]uint64]bool, len(paths))
	unique := paths[:0:0]
	for _, p := range paths {
		if p == "" {
			continue
		}
		if info, err := os.Lstat(p); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				key := [2]uint64{uint64(st.Dev), st.Ino}
				if seen[key] {
					debugf("  -> Not stripping %s: a hard link of a file already stripped\n", p)
					continue
				}
				seen[key] = true
			}
		}
		unique = append(unique, p)
	}
	return unique
}

// stripTempName matches strip's temporary files: "st" and six characters.
var stripTempName = regexp.MustCompile(`^st[A-Za-z0-9]{6}$`)

// snapshotStripTempNames records, for each directory strip works in, the
// names there that already look like strip's temporary files, so only ones
// strip leaves behind are removed afterwards.
func snapshotStripTempNames(paths []string) map[string]map[string]bool {
	dirs := make(map[string]map[string]bool)
	for _, p := range paths {
		dir := filepath.Dir(p)
		if _, done := dirs[dir]; done {
			continue
		}
		existing := make(map[string]bool)
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				if stripTempName.MatchString(e.Name()) {
					existing[e.Name()] = true
				}
			}
		}
		dirs[dir] = existing
	}
	return dirs
}

// removeStripLeftovers removes the temporary files a failed strip left in
// the directories it worked in.
func removeStripLeftovers(dirs map[string]map[string]bool, buildExec *Executor) {
	for dir, existing := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !stripTempName.MatchString(e.Name()) || existing[e.Name()] {
				continue
			}
			path := filepath.Join(dir, e.Name())
			debugf("Removing strip leftover %s\n", path)
			if err := os.Remove(path); err != nil {
				_ = buildExec.Run(exec.Command("rm", "-f", "--", path))
			}
		}
	}
}
