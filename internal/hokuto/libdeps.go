package hokuto

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// generateLibDeps records the shared libraries the package's executables and
// libraries link against directly: the DT_NEEDED entries of each ELF file,
// the same list `readelf -d` prints. Nothing is resolved further, so the
// libraries those libraries need (what ldd would show) never end up here.
//
// ELF files are read in-process. Only when the output tree cannot be read
// natively, or a file cannot be parsed, does it fall back to running file(1)
// and readelf(1) through execCtx as before.
func generateLibDeps(outputDir, libdepsFile string, execCtx *Executor) error {
	libs, err := collectLibDepsNative(outputDir, execCtx)
	if err != nil {
		debugf("Native libdeps scan of %s failed (%v); falling back to file/readelf\n", outputDir, err)
		libs, err = collectLibDepsExec(outputDir, execCtx)
		if err != nil {
			return err
		}
	}
	if err := writeLibDeps(libdepsFile, libs, execCtx); err != nil {
		return err
	}
	debugf("Library dependencies written to %s (%d deps)\n", libdepsFile, len(libs))

	// Written even when empty: an empty file says "uses no private API",
	// where a missing one only says "not recorded".
	private, err := collectPrivateAPILibs(outputDir)
	if err != nil {
		debugf("Private API scan of %s failed: %v\n", outputDir, err)
		return nil
	}
	privateFile := filepath.Join(filepath.Dir(libdepsFile), "privatedeps")
	if err := writeLibDeps(privateFile, private, execCtx); err != nil {
		return err
	}
	return nil
}

// collectPrivateAPILibs lists the shared libraries (by soname) that the ELF
// files in outputDir import private-API symbols from: symbols whose version
// ends in _PRIVATE_API, such as Qt's Qt_6_PRIVATE_API. Such a library keeps
// no compatibility for those symbols between its minor releases, so its
// users need a rebuild then, even though its soname stays the same (KWin
// against Qt 6.11 cannot start with Qt 6.12). Libraries the package ships
// itself are left out.
func collectPrivateAPILibs(outputDir string) ([]string, error) {
	provided := make(map[string]bool)
	var files []string
	err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			provided[filepath.Base(path)] = true
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		provided[filepath.Base(path)] = true
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o111 != 0 {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, file := range files {
		for _, lib := range elfPrivateAPILibraries(file) {
			if !provided[lib] {
				seen[lib] = true
			}
		}
	}
	libs := make([]string, 0, len(seen))
	for lib := range seen {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	return libs, nil
}

// elfPrivateAPILibraries returns the libraries path imports _PRIVATE_API
// versioned symbols from; nothing for a file that is not a readable ELF.
func elfPrivateAPILibraries(path string) []string {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	symbols, err := f.ImportedSymbols()
	if err != nil {
		return nil
	}
	var libs []string
	seen := make(map[string]bool)
	for _, sym := range symbols {
		if sym.Library == "" || !strings.HasSuffix(sym.Version, "_PRIVATE_API") || seen[sym.Library] {
			continue
		}
		seen[sym.Library] = true
		libs = append(libs, sym.Library)
	}
	return libs
}

// providedLibDepKey is how a file the package itself ships is matched against
// a DT_NEEDED entry, so a package never depends on its own libraries.
func providedLibDepKey(path string) string {
	if pathIs32BitLibrary(path) {
		return "elf32:" + filepath.Base(path)
	}
	return "elf64:" + filepath.Base(path)
}

// symlinkResolvesInsideTree reports whether the symlink at path leads,
// possibly through further links, to a regular file inside root. Absolute
// targets are taken relative to root, since that is where they point once the
// package is installed. A link that leaves the tree names a library some
// other package provides, so it must not count as provided here.
func symlinkResolvesInsideTree(root, path string) bool {
	root = filepath.Clean(root)
	for hops := 0; hops < 40; hops++ {
		target, err := os.Readlink(path)
		if err != nil {
			return false
		}
		if filepath.IsAbs(target) {
			path = filepath.Join(root, target)
		} else {
			path = filepath.Join(filepath.Dir(path), target)
		}
		if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return false
		}
		info, err := os.Lstat(path)
		if err != nil {
			return false
		}
		switch {
		case info.Mode().IsRegular():
			return true
		case info.Mode()&os.ModeSymlink == 0:
			return false
		}
	}
	return false
}

// libDepsFromNeeded turns one file's DT_NEEDED list into libdeps entries,
// dropping the libraries the package provides itself.
func libDepsFromNeeded(abi string, needed []string, provided map[string]struct{}) []string {
	var libs []string
	for _, lib := range needed {
		if _, ok := provided[abi+":"+lib]; ok {
			continue
		}
		if abi != "" {
			libs = append(libs, abi+":"+lib)
		} else {
			libs = append(libs, lib)
		}
	}
	return libs
}

func sortedLibDeps(seen map[string]struct{}) []string {
	libs := make([]string, 0, len(seen))
	for lib := range seen {
		libs = append(libs, lib)
	}
	sort.Strings(libs)
	return libs
}

// errELFNeedsTools marks a file the native reader cannot handle; it is then
// inspected with file/readelf instead.
var errELFNeedsTools = errors.New("ELF file needs file/readelf")

// elfNeededNative returns the ELF class ("elf32"/"elf64") and DT_NEEDED
// entries of path. isELF is false for anything that is not an ELF file.
func elfNeededNative(path string) (abi string, needed []string, isELF bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false, errELFNeedsTools
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != elf.ELFMAG {
		return "", nil, false, nil
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return "", nil, true, errELFNeedsTools
	}
	defer ef.Close()

	switch ef.Class {
	case elf.ELFCLASS32:
		abi = "elf32"
	case elf.ELFCLASS64:
		abi = "elf64"
	}

	if ef.SectionByType(elf.SHT_DYNAMIC) == nil {
		// Without section headers the dynamic segment is only reachable
		// through the program headers, which readelf also understands.
		for _, prog := range ef.Progs {
			if prog.Type == elf.PT_DYNAMIC {
				return abi, nil, true, errELFNeedsTools
			}
		}
		return abi, nil, true, nil
	}
	needed, err = ef.ImportedLibraries()
	if err != nil {
		return abi, nil, true, errELFNeedsTools
	}
	return abi, needed, true, nil
}

// collectLibDepsNative walks outputDir like `find -type f` and reads the
// DT_NEEDED entries of every file with an executable bit, like
// `find -type f -perm /111` did.
func collectLibDepsNative(outputDir string, execCtx *Executor) ([]string, error) {
	provided := make(map[string]struct{})
	var files []string
	err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Sonames are usually symlinks (libfoo.so.1 -> libfoo.so.1.2.3),
			// and DT_NEEDED names the soname.
			if symlinkResolvesInsideTree(outputDir, path) {
				provided[providedLibDepKey(path)] = struct{}{}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		provided[providedLibDepKey(path)] = struct{}{}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o111 != 0 {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	debugf("Found %d executable files to check for dependencies.\n", len(files))

	seen := make(map[string]struct{})
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				abi, needed, isELF, err := elfNeededNative(file)
				if errors.Is(err, errELFNeedsTools) {
					abi, needed, isELF = elfNeededExec(file, execCtx)
				}
				if !isELF {
					continue
				}
				libs := libDepsFromNeeded(abi, needed, provided)
				mu.Lock()
				for _, lib := range libs {
					seen[lib] = struct{}{}
				}
				mu.Unlock()
			}
		}()
	}
	for _, file := range files {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	return sortedLibDeps(seen), nil
}

// elfNeededExec is the file/readelf implementation for a single file, run
// through execCtx so root-owned files can be read.
func elfNeededExec(file string, execCtx *Executor) (abi string, needed []string, isELF bool) {
	var fileOut, readelfOut bytes.Buffer

	cmdFile := exec.Command("file", "--brief", file)
	cmdFile.Stdout = &fileOut
	cmdFile.Stderr = io.Discard
	if err := execCtx.Run(cmdFile); err != nil {
		return "", nil, false
	}
	fileDesc := fileOut.String()
	if !strings.Contains(fileDesc, "ELF") {
		return "", nil, false
	}
	switch {
	case strings.Contains(fileDesc, "ELF 32-bit"):
		abi = "elf32"
	case strings.Contains(fileDesc, "ELF 64-bit"):
		abi = "elf64"
	}

	readelfCmd := exec.Command("readelf", "-d", file)
	readelfCmd.Stdout = &readelfOut
	readelfCmd.Stderr = io.Discard
	if err := execCtx.Run(readelfCmd); err != nil {
		// Matches the old behaviour: an unreadable dynamic section adds nothing.
		return abi, nil, false
	}

	scanner := bufio.NewScanner(bytes.NewReader(readelfOut.Bytes()))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "(NEEDED)") {
			continue
		}
		// Format: 0x0000000000000001 (NEEDED)             Shared library: [libassuan.so.9]
		idxStart := strings.Index(line, "[")
		idxEnd := strings.Index(line, "]")
		if idxStart != -1 && idxEnd != -1 && idxEnd > idxStart {
			needed = append(needed, line[idxStart+1:idxEnd])
		}
	}
	return abi, needed, true
}

// collectLibDepsExec lists files with find(1) through execCtx and inspects
// each one with file/readelf. It is the fallback for output trees the
// current user cannot walk.
func collectLibDepsExec(outputDir string, execCtx *Executor) ([]string, error) {
	var findOutput bytes.Buffer
	findCmd := exec.Command("find", outputDir, "-type", "f", "-perm", "/111")
	findCmd.Stdout = &findOutput
	findCmd.Stderr = io.Discard
	if err := execCtx.Run(findCmd); err != nil {
		return nil, fmt.Errorf("failed to execute find command to locate executables: %w", err)
	}
	var files []string
	for _, line := range strings.Split(findOutput.String(), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	if len(files) == 0 {
		debugf("No executable files found in %s\n", outputDir)
		return nil, nil
	}

	provided := make(map[string]struct{})
	var findFilesOutput bytes.Buffer
	findFilesCmd := exec.Command("find", outputDir, "(", "-type", "f", "-o", "-type", "l", ")", "-printf", "%y %p\\n")
	findFilesCmd.Stdout = &findFilesOutput
	findFilesCmd.Stderr = io.Discard
	if err := execCtx.Run(findFilesCmd); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(findFilesOutput.Bytes()))
		for scanner.Scan() {
			kind, path, ok := strings.Cut(scanner.Text(), " ")
			if !ok || (kind == "l" && !symlinkResolvesInsideTree(outputDir, path)) {
				continue
			}
			provided[providedLibDepKey(path)] = struct{}{}
		}
	}

	debugf("Found %d executable files to check for dependencies.\n", len(files))

	seen := make(map[string]struct{})
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				abi, needed, isELF := elfNeededExec(file, execCtx)
				if !isELF {
					continue
				}
				libs := libDepsFromNeeded(abi, needed, provided)
				mu.Lock()
				for _, lib := range libs {
					seen[lib] = struct{}{}
				}
				mu.Unlock()
			}
		}()
	}
	for _, file := range files {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	return sortedLibDeps(seen), nil
}

// writeLibDeps writes one library per line, or an empty file when there are
// none, natively as root and through execCtx otherwise.
func writeLibDeps(libdepsFile string, libs []string, execCtx *Executor) error {
	content := ""
	if len(libs) > 0 {
		content = strings.Join(libs, "\n") + "\n"
	}
	if os.Geteuid() == 0 {
		if err := os.WriteFile(libdepsFile, []byte(content), 0o644); err != nil {
			return fmt.Errorf("failed to write libdeps file natively: %w", err)
		}
		return nil
	}
	if content == "" {
		if err := execCtx.Run(exec.Command("touch", libdepsFile)); err != nil {
			return fmt.Errorf("failed to create empty libdeps file: %w", err)
		}
		return nil
	}
	cmd := exec.Command("tee", libdepsFile)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = io.Discard
	if err := execCtx.Run(cmd); err != nil {
		return fmt.Errorf("failed to write libdeps file via tee: %w", err)
	}
	return nil
}

// libDepMachineUse records whether a libdeps entry is needed by ELF files
// built for the cross target, by files built for any other machine (the build
// host), or both.
type libDepMachineUse struct {
	target bool
	host   bool
}

// elfMachineForArchPrefix maps a cross-system package prefix to the ELF
// machine of the target files such a package ships.
func elfMachineForArchPrefix(prefix string) (elf.Machine, bool) {
	switch prefix {
	case "aarch64-":
		return elf.EM_AARCH64, true
	case "x86_64-":
		return elf.EM_X86_64, true
	}
	return elf.EM_NONE, false
}

// libDepsByMachine classifies the DT_NEEDED entries of the executable ELF
// files in outputDir by the machine they were built for, keyed like libdeps
// entries ("elf64:libfoo.so.1"). A cross-system package (aarch64-foo) holds
// target libraries, whose dependencies live in the sysroot, and may also hold
// host tools (aarch64-gcc's compiler), whose dependencies live on the host;
// the libdeps file alone cannot tell the two apart. Files the native reader
// cannot parse are skipped, leaving their libraries to the host-only default.
var libDepsByMachine = func(outputDir string, target elf.Machine) (map[string]libDepMachineUse, error) {
	uses := make(map[string]libDepMachineUse)
	err := filepath.WalkDir(outputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An asroot build's output holds directories only root may
			// enter (cups: etc/cups/ssl); they hold no ELF files to
			// classify, and stopping there lost every library.
			if errors.Is(err, fs.ErrPermission) {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Mode().Perm()&0o111 == 0 {
			return err
		}
		f, err := elf.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		abi := "elf64"
		if f.Class == elf.ELFCLASS32 {
			abi = "elf32"
		}
		needed, err := f.ImportedLibraries()
		if err != nil {
			return nil
		}
		for _, lib := range needed {
			key := abi + ":" + lib
			use := uses[key]
			if f.Machine == target {
				use.target = true
			} else {
				use.host = true
			}
			uses[key] = use
		}
		return nil
	})
	return uses, err
}
