package hokuto

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// AlternativeRequest represents a request to register an alternative (used for batch processing)
type AlternativeRequest struct {
	FilePath     string
	IncomingPkg  string
	CurrentPkg   string
	IncomingFile string
	KeepOriginal bool
}

type alternativeFileInfo struct {
	Sum        string
	Mode       string
	UID        int
	GID        int
	Type       AlternativeFileType
	LinkTarget string
}

type alternativeBatchContext struct {
	incomingFiles map[string]alternativeFileInfo
	ownerByPath   map[string]string
}

var alternativeStoreLocks sync.Map

// GlobalAlternativesDBPath is the path to the global alternatives database
const GlobalAlternativesDBPath = "var/db/hokuto/alternatives/db.json"

// GlobalAlternativesStoreDir is the directory where stashed alternative files are stored (by hash)
const GlobalAlternativesStoreDir = "var/db/hokuto/alternatives/store"

// AlternativeState represents the state of an alternative (Active or Stashed)
type AlternativeState string

type AlternativeFileType string

const (
	StateActive  AlternativeState = "active"
	StateStashed AlternativeState = "stashed"

	AlternativeRegular AlternativeFileType = "regular"
	AlternativeSymlink AlternativeFileType = "symlink"
)

// Alternative represents a specific content version of a file
type Alternative struct {
	B3Sum  string              `json:"b3sum"`
	Owners []string            `json:"owners"` // List of packages that provide this exact content
	State  AlternativeState    `json:"state"`
	Mode   string              `json:"mode"`
	UID    int                 `json:"uid"`
	GID    int                 `json:"gid"`
	Type   AlternativeFileType `json:"type,omitempty"`
	Target string              `json:"target,omitempty"`
}

// FileEntry represents a file path that has alternatives
type FileEntry struct {
	Path         string         `json:"path"`
	Alternatives []*Alternative `json:"alternatives"`
}

// GlobalAlternativesDB represents the entire alternatives database
type GlobalAlternativesDB struct {
	Files map[string]*FileEntry `json:"files"`
}

// loadAlternativesDB loads the global alternatives database
func loadAlternativesDB(hRoot string) (*GlobalAlternativesDB, error) {
	dbPath := filepath.Join(hRoot, GlobalAlternativesDBPath)
	db := &GlobalAlternativesDB{
		Files: make(map[string]*FileEntry),
	}

	data, err := readFileAsRoot(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, fmt.Errorf("failed to read alternatives DB: %w", err)
	}

	if len(data) == 0 {
		return db, nil
	}

	if err := json.Unmarshal(data, db); err != nil {
		return nil, fmt.Errorf("failed to unmarshal alternatives DB: %w", err)
	}
	if err := validateAlternativesDB(db); err != nil {
		return nil, fmt.Errorf("invalid alternatives DB: %w", err)
	}

	return db, nil
}

func validAlternativeDigest(sum string) bool {
	if len(sum) != 64 {
		return false
	}
	for _, c := range sum {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func validateAlternativePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("unsafe alternative path %q", path)
	}
	return nil
}

func validateAlternativesDB(db *GlobalAlternativesDB) error {
	if db.Files == nil {
		db.Files = make(map[string]*FileEntry)
		return nil
	}
	for path, entry := range db.Files {
		if err := validateAlternativePath(path); err != nil {
			return err
		}
		if entry == nil {
			return fmt.Errorf("nil entry for %s", path)
		}
		if entry.Path != "" && entry.Path != path {
			return fmt.Errorf("entry path %q does not match key %q", entry.Path, path)
		}
		activeCount := 0
		for _, alt := range entry.Alternatives {
			if alt == nil {
				return fmt.Errorf("nil alternative for %s", path)
			}
			if !validAlternativeDigest(alt.B3Sum) {
				return fmt.Errorf("invalid digest for %s", path)
			}
			switch normalizedAlternativeType(alt.Type) {
			case AlternativeRegular:
			case AlternativeSymlink:
				if alt.Target == "" || hashString("symlink\x00"+alt.Target) != alt.B3Sum {
					return fmt.Errorf("invalid symlink target metadata for %s", path)
				}
			default:
				return fmt.Errorf("invalid file type %q for %s", alt.Type, path)
			}
			mode, err := strconv.ParseUint(alt.Mode, 8, 32)
			if err != nil || mode > 0o7777 {
				return fmt.Errorf("invalid mode %q for %s", alt.Mode, path)
			}
			if alt.UID < 0 || alt.GID < 0 {
				return fmt.Errorf("invalid ownership for %s", path)
			}
			switch alt.State {
			case StateActive:
				activeCount++
			case StateStashed:
			default:
				return fmt.Errorf("invalid state %q for %s", alt.State, path)
			}
		}
		if len(entry.Alternatives) > 0 && activeCount != 1 {
			return fmt.Errorf("expected exactly one active alternative for %s, found %d", path, activeCount)
		}
	}
	return nil
}

// saveAlternativesDB saves the global alternatives database
func saveAlternativesDB(hRoot string, db *GlobalAlternativesDB, execCtx *Executor) error {
	if err := validateAlternativesDB(db); err != nil {
		return fmt.Errorf("refusing to save invalid alternatives DB: %w", err)
	}
	dbPath := filepath.Join(hRoot, GlobalAlternativesDBPath)
	dbDir := filepath.Dir(dbPath)

	// Ensure directory exists
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return fmt.Errorf("failed to create DB directory: %w", err)
		}
	} else {
		cmd := exec.Command("mkdir", "-p", dbDir)
		if err := execCtx.Run(cmd); err != nil {
			return fmt.Errorf("failed to create DB directory with exec: %w", err)
		}
	}

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal alternatives DB: %w", err)
	}

	tempPath := fmt.Sprintf("%s.tmp-%d", dbPath, os.Getpid())
	if err := removeAlternativeDestination(tempPath, execCtx); err != nil {
		return fmt.Errorf("failed to prepare alternatives DB temporary file: %w", err)
	}
	defer func() { _ = removeAlternativeDestination(tempPath, execCtx) }()
	if err := writeFileAsRoot(tempPath, data, 0o644, execCtx); err != nil {
		return err
	}
	if err := renameAlternativeAsRoot(tempPath, dbPath, execCtx); err != nil {
		return fmt.Errorf("failed to atomically replace alternatives DB: %w", err)
	}
	return nil
}

// getStashedFilePath returns the path to a stashed file in the store
func getStashedFilePath(hRoot, b3sum string) string {
	return filepath.Join(hRoot, GlobalAlternativesStoreDir, b3sum)
}

// ensureStoreDir creates the store directory if it doesn't exist
func ensureStoreDir(hRoot string, execCtx *Executor) error {
	storeDir := filepath.Join(hRoot, GlobalAlternativesStoreDir)
	if info, err := os.Stat(storeDir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("alternatives store path is not a directory: %s", storeDir)
		}
		return nil
	} else if !os.IsNotExist(err) && !os.IsPermission(err) {
		return err
	}
	if os.Geteuid() == 0 {
		return os.MkdirAll(storeDir, 0755)
	}
	cmd := exec.Command("mkdir", "-p", storeDir)
	return execCtx.Run(cmd)
}

func alternativeModeValue(mode os.FileMode) uint64 {
	value := uint64(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		value |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		value |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		value |= 0o1000
	}
	return value
}

func osFileModeFromAlternative(value uint64) os.FileMode {
	mode := os.FileMode(value & 0o777)
	if value&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if value&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if value&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

func alternativeFileMetadata(path string, execCtx *Executor) (alternativeFileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return alternativeFileInfo{}, err
	}

	meta := alternativeFileInfo{
		Mode: fmt.Sprintf("%04o", alternativeModeValue(info.Mode())),
		Type: AlternativeRegular,
	}
	if sysStat, ok := info.Sys().(*syscall.Stat_t); ok {
		meta.UID = int(sysStat.Uid)
		meta.GID = int(sysStat.Gid)
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return alternativeFileInfo{}, fmt.Errorf("failed to read symlink %s: %w", path, err)
		}
		meta.Type = AlternativeSymlink
		meta.LinkTarget = target
		meta.Sum = hashString("symlink\x00" + target)
	case info.Mode().IsRegular():
		sum, err := ComputeChecksum(path, execCtx)
		if err != nil {
			return alternativeFileInfo{}, err
		}
		meta.Sum = sum
	default:
		return alternativeFileInfo{}, fmt.Errorf("unsupported alternative file type for %s (%s)", path, info.Mode().Type())
	}

	return meta, nil
}

func inspectAlternativeFiles(paths []string, execCtx *Executor) (map[string]alternativeFileInfo, error) {
	results := make(map[string]alternativeFileInfo, len(paths))
	if len(paths) == 0 {
		return results, nil
	}

	workerCount := runtime.NumCPU() * 2
	if workerCount > len(paths) {
		workerCount = len(paths)
	}
	jobs := make(chan string, len(paths))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				info, err := alternativeFileMetadata(path, execCtx)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("failed to inspect alternative file %s: %w", path, err)
					}
				} else {
					results[path] = info
				}
				mu.Unlock()
			}
		}()
	}
	for _, path := range paths {
		jobs <- path
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func normalizedAlternativeType(fileType AlternativeFileType) AlternativeFileType {
	if fileType == "" {
		return AlternativeRegular
	}
	return fileType
}

func alternativeMatchesInfo(alt *Alternative, info alternativeFileInfo) bool {
	return alt != nil && alt.B3Sum == info.Sum && normalizedAlternativeType(alt.Type) == info.Type
}

func alternativeFromInfo(info alternativeFileInfo) *Alternative {
	return &Alternative{
		B3Sum:  info.Sum,
		State:  StateStashed,
		Mode:   info.Mode,
		UID:    info.UID,
		GID:    info.GID,
		Type:   info.Type,
		Target: info.LinkTarget,
	}
}

func getOrCreateAlternative(entry *FileEntry, info alternativeFileInfo) *Alternative {
	for _, alt := range entry.Alternatives {
		if alternativeMatchesInfo(alt, info) {
			return alt
		}
	}
	alt := alternativeFromInfo(info)
	entry.Alternatives = append(entry.Alternatives, alt)
	return alt
}

func addAlternativeOwner(alt *Alternative, owner string) {
	if owner == "" {
		return
	}
	for _, existing := range alt.Owners {
		if existing == owner {
			return
		}
	}
	alt.Owners = append(alt.Owners, owner)
}

func setActiveAlternative(entry *FileEntry, active *Alternative) {
	for _, alt := range entry.Alternatives {
		if alt == active {
			alt.State = StateActive
		} else {
			alt.State = StateStashed
		}
	}
}

func copyAlternativeRegularFile(source, destination string, execCtx *Executor) error {
	cmd := exec.Command("cp", "-a", "--reflink=auto", "--", source, destination)
	if execCtx != nil {
		return execCtx.Run(cmd)
	}
	return cmd.Run()
}

func ensureAlternativeStored(hRoot, source string, info alternativeFileInfo, execCtx *Executor) error {
	lockValue, _ := alternativeStoreLocks.LoadOrStore(info.Sum, &sync.Mutex{})
	storeLock := lockValue.(*sync.Mutex)
	storeLock.Lock()
	defer storeLock.Unlock()

	if err := ensureStoreDir(hRoot, execCtx); err != nil {
		return err
	}
	storePath := getStashedFilePath(hRoot, info.Sum)
	if storedInfo, err := os.Lstat(storePath); err == nil {
		if !storedInfo.Mode().IsRegular() {
			return fmt.Errorf("alternative store path is not a regular file: %s", storePath)
		}
		if info.Type == AlternativeSymlink {
			data, err := readFileAsRoot(storePath)
			if err != nil {
				return fmt.Errorf("failed to verify stored symlink target: %w", err)
			}
			if string(data) != info.LinkTarget {
				return fmt.Errorf("alternative store collision for symlink %s", storePath)
			}
			return nil
		}
		sum, err := ComputeChecksum(storePath, execCtx)
		if err != nil {
			return fmt.Errorf("failed to verify stored alternative: %w", err)
		}
		if sum != info.Sum {
			return fmt.Errorf("alternative store corruption at %s", storePath)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if info.Type == AlternativeSymlink {
		if err := writeFileAsRoot(storePath, []byte(info.LinkTarget), 0o600, execCtx); err != nil {
			return fmt.Errorf("failed to store symlink target: %w", err)
		}
		return nil
	}
	if err := copyAlternativeRegularFile(source, storePath, execCtx); err != nil {
		return fmt.Errorf("failed to copy alternative to store: %w", err)
	}
	return nil
}

func removeAlternativeDestination(path string, execCtx *Executor) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace directory %s with an alternative", path)
	}
	return removeFileAsRoot(path, execCtx)
}

func createSymlinkAsRoot(target, path string, execCtx *Executor) error {
	if err := os.Symlink(target, path); err == nil {
		return nil
	} else if os.Geteuid() == 0 {
		return err
	}
	return execCtx.Run(exec.Command("ln", "-s", "--", target, path))
}

func renameAlternativeAsRoot(oldPath, newPath string, execCtx *Executor) error {
	if err := os.Rename(oldPath, newPath); err == nil {
		return nil
	} else if os.Geteuid() == 0 {
		return err
	}
	return execCtx.Run(exec.Command("mv", "-f", "--", oldPath, newPath))
}

func alternativeTempPatterns(targetPath string) (goPattern, mktempTemplate string) {
	prefix := "." + filepath.Base(targetPath) + ".hokuto-alt-"
	// os.MkdirTemp uses a single '*' placeholder, while GNU mktemp requires
	// its template to end in at least three consecutive 'X' characters.
	return prefix + "*", prefix + "XXXXXX"
}

func createAlternativeTempDir(targetPath string, execCtx *Executor) (string, error) {
	parent := filepath.Dir(targetPath)
	goPattern, mktempTemplate := alternativeTempPatterns(targetPath)
	if dir, err := os.MkdirTemp(parent, goPattern); err == nil {
		return dir, nil
	} else if os.Geteuid() == 0 {
		return "", err
	}

	var output bytes.Buffer
	cmd := exec.Command("mktemp", "-d", filepath.Join(parent, mktempTemplate))
	cmd.Stdout = &output
	if err := execCtx.Run(cmd); err != nil {
		return "", err
	}
	dir := strings.TrimSpace(output.String())
	if dir == "" {
		return "", fmt.Errorf("mktemp returned an empty directory path")
	}
	// Privileged mktemp creates a root-owned 0700 directory. Hokuto still
	// needs to lstat the staged entry before delegating mutations back to the
	// privileged executor. Allow traversal without making the directory
	// listable or writable by the invoking user.
	if err := execCtx.Run(exec.Command("chmod", "0711", "--", dir)); err != nil {
		_ = execCtx.Run(exec.Command("rmdir", "--", dir))
		return "", fmt.Errorf("failed to prepare alternative temporary directory: %w", err)
	}
	return dir, nil
}

func removeAlternativeTempDir(path string, execCtx *Executor) {
	if err := os.Remove(path); err == nil || os.IsNotExist(err) {
		return
	}
	if os.Geteuid() != 0 {
		_ = execCtx.Run(exec.Command("rmdir", "--", path))
	}
}

func restoreAlternativeMetadata(path string, alt *Alternative, execCtx *Executor) error {
	isSymlink := normalizedAlternativeType(alt.Type) == AlternativeSymlink
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	uid, gid := -1, -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(stat.Uid), int(stat.Gid)
	}
	ownershipChanged := uid != alt.UID || gid != alt.GID
	if ownershipChanged {
		if isSymlink {
			err = os.Lchown(path, alt.UID, alt.GID)
		} else {
			err = os.Chown(path, alt.UID, alt.GID)
		}
		if err != nil {
			if os.Geteuid() == 0 {
				return err
			}
			args := []string{fmt.Sprintf("%d:%d", alt.UID, alt.GID), path}
			if isSymlink {
				args = append([]string{"-h"}, args...)
			}
			if err := execCtx.Run(exec.Command("chown", args...)); err != nil {
				return err
			}
		}
	}

	// chown may clear setuid/setgid bits, so restore the recorded mode last.
	if !isSymlink && alt.Mode != "" {
		mode, err := strconv.ParseUint(alt.Mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid stored mode %q: %w", alt.Mode, err)
		}
		desiredMode := osFileModeFromAlternative(mode)
		if !ownershipChanged && alternativeModeValue(info.Mode()) == mode {
			return nil
		}
		if err := os.Chmod(path, desiredMode); err != nil {
			if os.Geteuid() == 0 {
				return err
			}
			if err := execCtx.Run(exec.Command("chmod", alt.Mode, path)); err != nil {
				return err
			}
		}
	}
	return nil
}

func restoreAlternativeContent(hRoot, path string, alt *Alternative, execCtx *Executor) error {
	storePath := getStashedFilePath(hRoot, alt.B3Sum)
	storeInfo, err := os.Lstat(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("alternative content missing from store: %s", alt.B3Sum)
		}
		return err
	}
	if !storeInfo.Mode().IsRegular() {
		return fmt.Errorf("invalid alternative store entry: %s", storePath)
	}
	if normalizedAlternativeType(alt.Type) == AlternativeRegular {
		sum, err := ComputeChecksum(storePath, execCtx)
		if err != nil {
			return fmt.Errorf("failed to verify stored alternative: %w", err)
		}
		if sum != alt.B3Sum {
			return fmt.Errorf("stored alternative checksum mismatch for %s", path)
		}
	}

	targetPath := filepath.Join(hRoot, path)
	if info, err := os.Lstat(targetPath); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to replace directory %s with an alternative", targetPath)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	tempDir, err := createAlternativeTempDir(targetPath, execCtx)
	if err != nil {
		return fmt.Errorf("failed to create alternative temporary directory: %w", err)
	}
	tempPath := filepath.Join(tempDir, "entry")
	defer func() {
		_ = removeAlternativeDestination(tempPath, execCtx)
		removeAlternativeTempDir(tempDir, execCtx)
	}()

	if normalizedAlternativeType(alt.Type) == AlternativeSymlink {
		data, err := readFileAsRoot(storePath)
		if err != nil {
			return fmt.Errorf("failed to read stored symlink target: %w", err)
		}
		target := string(data)
		if alt.Target != "" && target != alt.Target {
			return fmt.Errorf("stored symlink target does not match alternatives DB for %s", path)
		}
		if hashString("symlink\x00"+target) != alt.B3Sum {
			return fmt.Errorf("stored symlink target checksum mismatch for %s", path)
		}
		if err := createSymlinkAsRoot(target, tempPath, execCtx); err != nil {
			return fmt.Errorf("failed to restore symlink: %w", err)
		}
	} else {
		if err := copyAlternativeRegularFile(storePath, tempPath, execCtx); err != nil {
			return fmt.Errorf("failed to restore regular file: %w", err)
		}
	}
	if err := restoreAlternativeMetadata(tempPath, alt, execCtx); err != nil {
		return fmt.Errorf("failed to restore alternative metadata: %w", err)
	}
	if err := renameAlternativeAsRoot(tempPath, targetPath, execCtx); err != nil {
		return fmt.Errorf("failed to activate restored alternative: %w", err)
	}
	return nil
}

type alternativeRestoreJob struct {
	Path        string
	Entry       *FileEntry
	Alternative *Alternative
}

const maxAlternativeWorkers = 8

// restoreAlternativeContentsBatch restores independent paths concurrently.
// Each individual restore still uses restoreAlternativeContent's atomic
// sibling-temp-and-rename operation.
func restoreAlternativeContentsBatch(hRoot string, jobs []alternativeRestoreJob, execCtx *Executor) error {
	if len(jobs) == 0 {
		return nil
	}

	workerLimit := maxAlternativeWorkers
	if workerLimit > len(jobs) {
		workerLimit = len(jobs)
	}
	sem := make(chan struct{}, workerLimit)
	errs := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			job := jobs[index]
			if err := restoreAlternativeContent(hRoot, job.Path, job.Alternative, execCtx); err != nil {
				errs[index] = fmt.Errorf("%s: %w", job.Path, err)
			}
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func parseManifestFilePath(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	lastSpace := strings.LastIndexAny(line, " \t")
	if lastSpace == -1 {
		return line
	}
	return strings.TrimSpace(line[:lastSpace])
}

func buildAlternativeOwnerCache(hRoot string) map[string]string {
	ownerByPath := make(map[string]string)
	installedRoot := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(installedRoot)
	if err != nil {
		return ownerByPath
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(installedRoot, pkgName, "manifest")
		f, err := os.Open(manifestPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			manifestPath := parseManifestFilePath(scanner.Text())
			if manifestPath == "" || strings.HasSuffix(manifestPath, "/") {
				continue
			}
			canonicalPath := canonicalizePath(hRoot, manifestPath)
			canonicalNoSlash := strings.TrimPrefix(canonicalPath, "/")
			if _, exists := ownerByPath[canonicalPath]; !exists {
				ownerByPath[canonicalPath] = pkgName
			}
			if _, exists := ownerByPath[canonicalNoSlash]; !exists {
				ownerByPath[canonicalNoSlash] = pkgName
			}
		}
		_ = f.Close()
	}
	return ownerByPath
}

func alternativeOwnerFromCache(ctx *alternativeBatchContext, hRoot, targetAbsPath string) string {
	if ctx == nil || len(ctx.ownerByPath) == 0 {
		return findPackageOwningFile(hRoot, targetAbsPath)
	}
	canonicalTarget := canonicalizePath(hRoot, targetAbsPath)
	if owner := ctx.ownerByPath[canonicalTarget]; owner != "" {
		return owner
	}
	return ctx.ownerByPath[strings.TrimPrefix(canonicalTarget, "/")]
}

// registerAlternative registers regular files and symlinks without ever
// following symlinks or admitting directories into the alternatives store.
func registerAlternative(hRoot, filePath string, req AlternativeRequest, execCtx *Executor, db *GlobalAlternativesDB, dbMu *sync.Mutex, batchCtx *alternativeBatchContext) error {
	var incomingInfo alternativeFileInfo
	var ok bool
	if batchCtx != nil {
		incomingInfo, ok = batchCtx.incomingFiles[req.IncomingFile]
	}
	if !ok {
		var err error
		incomingInfo, err = alternativeFileMetadata(req.IncomingFile, execCtx)
		if err != nil {
			return fmt.Errorf("failed to inspect incoming alternative: %w", err)
		}
	}

	dbMu.Lock()
	defer dbMu.Unlock()
	if db.Files == nil {
		db.Files = make(map[string]*FileEntry)
	}
	entry := db.Files[filePath]
	if entry == nil {
		entry = &FileEntry{Path: filePath}
		db.Files[filePath] = entry
	}

	var activeAlt *Alternative
	for _, alt := range entry.Alternatives {
		if alt.State != StateActive {
			continue
		}
		if activeAlt != nil {
			return fmt.Errorf("alternatives database has multiple active entries for %s", filePath)
		}
		activeAlt = alt
	}

	targetAbsPath := filepath.Join(hRoot, filePath)
	currentInfo, err := alternativeFileMetadata(targetAbsPath, execCtx)
	if err != nil {
		return fmt.Errorf("failed to inspect existing alternative: %w", err)
	}
	if activeAlt != nil && !alternativeMatchesInfo(activeAlt, currentInfo) {
		return fmt.Errorf("active alternative for %s does not match the file on disk", filePath)
	}

	currentAlt := getOrCreateAlternative(entry, currentInfo)
	currentOwner := req.CurrentPkg
	if currentOwner == "" {
		currentOwner = alternativeOwnerFromCache(batchCtx, hRoot, targetAbsPath)
		if currentOwner == "" {
			currentOwner = "unmanaged"
		}
	}
	addAlternativeOwner(currentAlt, currentOwner)

	incomingAlt := getOrCreateAlternative(entry, incomingInfo)
	addAlternativeOwner(incomingAlt, req.IncomingPkg)

	if req.KeepOriginal {
		if incomingAlt != currentAlt {
			if err := ensureAlternativeStored(hRoot, req.IncomingFile, incomingInfo, execCtx); err != nil {
				return err
			}
		}
		setActiveAlternative(entry, currentAlt)
	} else {
		if incomingAlt != currentAlt {
			if err := ensureAlternativeStored(hRoot, targetAbsPath, currentInfo, execCtx); err != nil {
				return err
			}
		}
		setActiveAlternative(entry, incomingAlt)
	}
	return nil
}

// BatchRegisterAlternatives processes a list of alternative requests concurrently.
func BatchRegisterAlternatives(hRoot string, requests []AlternativeRequest, execCtx *Executor) error {
	if len(requests) == 0 {
		return nil
	}
	normalizedRequests := make([]AlternativeRequest, len(requests))
	for i, req := range requests {
		if err := validateAlternativePath(req.FilePath); err != nil {
			return err
		}
		// Conflict detection can encounter the same installed file through
		// usr-merge aliases such as /bin/X and /usr/bin/X. Always key the
		// alternatives database by the canonical parent path so subsequent
		// installs update one conflict set instead of creating parallel sets.
		req.FilePath = canonicalizePath(hRoot, req.FilePath)
		if err := validateAlternativePath(req.FilePath); err != nil {
			return err
		}
		if req.IncomingFile == "" {
			return fmt.Errorf("missing incoming file for alternative %s", req.FilePath)
		}
		if req.IncomingPkg == "" {
			return fmt.Errorf("missing incoming package for alternative %s", req.FilePath)
		}
		normalizedRequests[i] = req
	}
	requests = normalizedRequests

	db, err := loadAlternativesDB(hRoot)
	if err != nil {
		return err
	}
	if db.Files == nil {
		db.Files = make(map[string]*FileEntry)
	}

	// Ensure store directory exists once
	if err := ensureStoreDir(hRoot, execCtx); err != nil {
		return err
	}

	incomingPaths := make([]string, 0, len(requests))
	seenIncoming := make(map[string]bool, len(requests))
	for _, req := range requests {
		if req.IncomingFile == "" || seenIncoming[req.IncomingFile] {
			continue
		}
		seenIncoming[req.IncomingFile] = true
		incomingPaths = append(incomingPaths, req.IncomingFile)
	}

	incomingInfo, err := inspectAlternativeFiles(incomingPaths, execCtx)
	if err != nil {
		return err
	}

	batchCtx := &alternativeBatchContext{
		incomingFiles: incomingInfo,
		ownerByPath:   buildAlternativeOwnerCache(hRoot),
	}

	var dbMu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, len(requests))

	// Limit concurrency to avoid too many open files/processes
	// (e.g. 8 workers or based on CPU). For now, we rely on Go scheduler but maybe semaphore?
	// Let's use a semaphore for safety.
	sem := make(chan struct{}, 8) // Max 8 concurrent operations

	for _, req := range requests {
		wg.Add(1)
		go func(r AlternativeRequest) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			if err := registerAlternative(hRoot, r.FilePath, r, execCtx, db, &dbMu, batchCtx); err != nil {
				errCh <- fmt.Errorf("failed to register alternative for %s: %w", r.FilePath, err)
			}
		}(req)
	}

	wg.Wait()
	close(errCh)

	// Return the first error if any
	for err := range errCh {
		if err != nil {
			return err
		}
	}

	// Save DB once
	return saveAlternativesDB(hRoot, db, execCtx)
}

// findPackageOwningFile searches installed packages to find which one owns the given file path.
// It returns the package name, or empty string if not found.
func findPackageOwningFile(hRoot, targetAbsPath string) string {
	// The targetAbsPath is absolute (e.g. /usr/bin/foo).
	// Manifests store paths relative to root or absolute (handled in uninstall.go).
	// We need to iterate all installed packages: var/db/hokuto/installed/*/manifest

	installedRoot := filepath.Join(hRoot, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(installedRoot)
	if err != nil {
		return ""
	}

	canonicalTarget := canonicalizePath(hRoot, targetAbsPath)
	canonicalTargetNoSlash := strings.TrimPrefix(canonicalTarget, "/")

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkgName := e.Name()
		manifestPath := filepath.Join(installedRoot, pkgName, "manifest")

		// We'll use a simple scanner - optimized for speed?
		// Since this only runs on conflict, it's acceptable.
		f, err := os.Open(manifestPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		found := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Line format: path [checksum]
			// or: path
			// We need to match the path.

			// Extract path part
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}

			lastSpace := strings.LastIndexAny(line, " \t")
			var mPath string
			if lastSpace == -1 {
				mPath = line
			} else {
				mPath = strings.TrimSpace(line[:lastSpace])
			}

			// Normalize manifest path using canonicalizePath
			canonicalMPath := canonicalizePath(hRoot, mPath)
			canonicalMPathNoSlash := strings.TrimPrefix(canonicalMPath, "/")
			if canonicalMPathNoSlash == canonicalTargetNoSlash {
				found = true
				break
			}
		}
		f.Close()

		if found {
			return pkgName
		}
	}

	return ""
}

func restoreAlternativesOnUninstall(pkgName, hRoot string, execCtx *Executor) (map[string]bool, error) {
	return restoreAlternativesOnUninstallSet(pkgName, hRoot, execCtx, map[string]bool{pkgName: true})
}

// restoreAlternativesOnUninstallSet checks if an uninstall removes the owner of
// the active file. If so, it restores an alternative that is not also being
// removed in the same operation.
func restoreAlternativesOnUninstallSet(pkgName, hRoot string, execCtx *Executor, removing map[string]bool) (map[string]bool, error) {
	db, err := loadAlternativesDB(hRoot)
	if err != nil {
		return nil, err
	}
	if removing == nil {
		removing = make(map[string]bool)
	}
	removing[pkgName] = true

	restoredFiles := make(map[string]bool)
	modified := false
	var restoreJobs []alternativeRestoreJob

	for path, entry := range db.Files {
		var activeAlt *Alternative
		// var pkgAlt *Alternative // removed unused var

		// Find active alt and the alt owned by this package
		for _, alt := range entry.Alternatives {
			if alt.State == StateActive {
				activeAlt = alt
			}

			// Check if this package is an owner
			isOwner := false
			newOwners := []string{}
			for _, o := range alt.Owners {
				if removing[o] {
					isOwner = true
				} else {
					newOwners = append(newOwners, o)
				}
			}

			if isOwner {
				// Remove package from owners
				alt.Owners = newOwners
				modified = true

				// Identify if this alt (content) depends on this package
				if len(alt.Owners) == 0 {
					// No more owners!
					// If it's active, we have a problem (need to restore something else).
					// If it's stashed, we can delete the stashed file.
				}
				// pkgAlt = alt // removed unused assignment
			}
		}

		// Logic for restoration:
		// If the Active alternative was owned ONLY by the uninstalled package (now has 0 owners),
		// we MUST switch to another alternative.
		// If the Active alternative STILL has owners, we must preserve it (prevent uninstall deletion).

		if activeAlt != nil {
			if len(activeAlt.Owners) == 0 {
				// Active file is now orphaned.
				// Try to find another candidate.
				var candidate *Alternative

				// Simple policy: Find first stashed alternative with owners.
				// TODO: Prompt user if multiple choices? For now, automatic picking.
				for _, alt := range entry.Alternatives {
					if alt != activeAlt && alt.State == StateStashed && len(alt.Owners) > 0 {
						candidate = alt
						break
					}
				}

				if candidate != nil {
					restoreJobs = append(restoreJobs, alternativeRestoreJob{
						Path:        path,
						Entry:       entry,
						Alternative: candidate,
					})
				} else {
					// No candidates. File is orphaned.
					// Uninstall process will naturally remove it since it's in the manifest of Pkg A.
					// We interpret "0 owners" = remove from DB.
				}
			} else {
				// Active alternative still has owners. It is shared.
				// We MUST mark it as restored so uninstall.go doesn't delete it.
				restoredFiles[path] = true
				if Debug {
					fmt.Printf("-> Retaining shared alternative for %s (owners: %v)\n", path, activeAlt.Owners)
				}
			}
		}

	}

	if err := restoreAlternativeContentsBatch(hRoot, restoreJobs, execCtx); err != nil {
		return nil, fmt.Errorf("failed to restore alternative: %w", err)
	}
	for _, job := range restoreJobs {
		setActiveAlternative(job.Entry, job.Alternative)
		restoredFiles[job.Path] = true
		fmt.Printf("-> Restored alternative for %s from %v\n", job.Path, job.Alternative.Owners)
	}

	// Drop alternatives whose final owner is being removed. Do this only after
	// every replacement succeeds so a failed batch is never committed.
	for _, entry := range db.Files {
		cleanAlts := entry.Alternatives[:0]
		for _, alt := range entry.Alternatives {
			if len(alt.Owners) > 0 {
				cleanAlts = append(cleanAlts, alt)
			}
		}
		entry.Alternatives = cleanAlts
	}

	// Remove file entries with no alternatives
	for p, e := range db.Files {
		if len(e.Alternatives) == 0 {
			delete(db.Files, p)
			modified = true
		}
	}

	if modified {
		if err := saveAlternativesDB(hRoot, db, execCtx); err != nil {
			return nil, err
		}
	}

	return restoredFiles, nil
}

// getSortedOwners returns a sorted list of unique owners for a file entry
func getSortedOwners(entry *FileEntry) []string {
	uniqueOwners := make(map[string]bool)
	for _, alt := range entry.Alternatives {
		for _, o := range alt.Owners {
			uniqueOwners[o] = true
		}
	}
	owners := make([]string, 0, len(uniqueOwners))
	for o := range uniqueOwners {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	return owners
}

// getActiveOwner returns the owner(s) of the currently active alternative
func getActiveOwner(entry *FileEntry) string {
	for _, alt := range entry.Alternatives {
		if alt.State == StateActive {
			if len(alt.Owners) > 0 {
				return strings.Join(alt.Owners, ",")
			}
			return "unmanaged"
		}
	}
	return "none"
}

// handleAlternativesCommand handles the 'hokuto alt' command
func handleAlternativesCommand(args []string) error {
	hRoot := os.Getenv("HOKUTO_ROOT")
	if hRoot == "" {
		hRoot = "/"
	}

	db, err := loadAlternativesDB(hRoot)
	if err != nil {
		return err
	}

	if len(db.Files) == 0 {
		colInfo.Println("No alternatives recorded.")
		return nil
	}

	if len(args) == 0 {
		return listAlternativesGrouped(db)
	}

	// Check for subcommands
	if len(args) > 0 {
		switch args[0] {
		case "discard-unmanaged":
			return discardUnmanagedAlternatives(hRoot, db)
		case "--help", "-h":
			printAlternativesHelp()
			return nil
		case "-ls", "--list":
			if len(args) < 2 {
				return fmt.Errorf("usage: hokuto alt -ls <provider>")
			}
			return listAlternativesForProvider(db, args[1])
		}
	}

	// Interactive switch
	targetPkg := args[0]
	return handleAlternativeSwitch(hRoot, db, targetPkg)
}

func printAlternativesHelp() {
	fmt.Println("Usage: hokuto alt [subcommand] [arguments]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  (no args)             List all alternatives grouped by conflict set")
	fmt.Println("  <package>             Interactively switch alternatives for a package")
	fmt.Println("  discard-unmanaged     Cleanup unmanaged alternatives (requires root)")
	fmt.Println("  -ls, --list <owner>   List files provided by a specific owner (e.g. 'unmanaged')")
	fmt.Println()
}

func listAlternativesForProvider(db *GlobalAlternativesDB, provider string) error {
	colInfo.Printf("Listing files provided by '%s':\n", provider)
	count := 0

	// Sort by path for consistent output
	var paths []string
	for p := range db.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		entry := db.Files[path]
		for _, alt := range entry.Alternatives {
			isOwner := false
			for _, o := range alt.Owners {
				if o == provider {
					isOwner = true
					break
				}
			}

			if isOwner {
				stateMarker := ""
				if alt.State == StateActive {
					stateMarker = " (active)"
				}
				fmt.Printf(" - %s%s\n", path, stateMarker)
				count++
				// Don't break, a provider might theoretically have multiple alts for same file?
				// Unlikely in current model but safe to show all.
			}
		}
	}

	if count == 0 {
		fmt.Printf("No files found for provider '%s'.\n", provider)
	} else {
		fmt.Printf("\nTotal: %d files.\n", count)
	}

	return nil
}

// discardUnmanagedAlternatives removes "unmanaged" ownership from all files.
// If an alternative becomes orphaned (no owners), it is removed.
// If the active alternative becomes orphaned, we try to switch to another valid one.
func discardUnmanagedAlternatives(hRoot string, db *GlobalAlternativesDB) error {
	execCtx := RootExec // Use the global root executor

	modified := false
	removedCount := 0
	switchedCount := 0

	colInfo.Println("Scanning for unmanaged alternatives")

	// Iterate over all files
	// Note: We need to be careful modifying the map while iterating if we delete keys?
	// Go maps allow deletion during iteration, but values are pointers so we modify contents safely.

	for path, entry := range db.Files {
		entryModified := false

		var newAlts []*Alternative

		// 1. First pass: Remove "unmanaged" from owners
		for _, alt := range entry.Alternatives {
			newOwners := []string{}
			hasUnmanaged := false
			for _, o := range alt.Owners {
				if o == "unmanaged" {
					hasUnmanaged = true
				} else {
					newOwners = append(newOwners, o)
				}
			}

			if hasUnmanaged {
				alt.Owners = newOwners
				entryModified = true
				modified = true
			}
		}

		if !entryModified {
			continue
		}

		// 2. Second pass: Handle orphaned alternatives
		// We rebuild the alternatives list, dropping orphans unless they need special handling (Active)

		for _, alt := range entry.Alternatives {
			if len(alt.Owners) > 0 {
				newAlts = append(newAlts, alt)
				continue
			}

			// This alternative is now orphaned (0 owners)
			if alt.State == StateStashed {
				removedCount++
				continue // Do not add to newAlts
			}

			if alt.State == StateActive {
				// Active alternative is orphaned!
				// We must try to switch to another candidate.

				var candidate *Alternative
				for _, other := range entry.Alternatives {
					if other != alt && other.State == StateStashed && len(other.Owners) > 0 {
						candidate = other
						break
					}
				}

				if candidate != nil {
					// Switch to candidate
					colArrow.Printf("Switching %s to managed alternative (owners: %v)\n", path, candidate.Owners)

					if err := restoreAlternativeContent(hRoot, path, candidate, execCtx); err != nil {
						colError.Printf("Error restoring alternative for %s: %v\n", path, err)
						newAlts = append(newAlts, alt) // Keep broken/orphaned active
						continue
					}

					setActiveAlternative(entry, candidate)
					// Old active (alt) is dropped (not added to newAlts)
					// Verify we shouldn't stash it? It's unmanaged and orphaned, so we discard it.
					switchedCount++
					removedCount++
					// candidate is already in list or will be handled if we iterate differently?
					// Wait, we are iterating `entry.Alternatives`. `candidate` comes from that list.
					// If `candidate` was already processed, it's in `newAlts`.
					// If `candidate` is yet to be processed, it will be added.
					// We just need to ensure `candidate.State` update sticks.
					// Since `candidate` is a pointer to an element in `entry.Alternatives`, it checks out.

					// CRITICAL: If candidate is 'orphaned' this same loop, it won't be a candidate.
					// We checked `len(other.Owners) > 0`.
				} else {
					// No candidates available.
					// The file is orphaned and unmanaged.
					// We should probably stop tracking it in alternatives DB.
					// It remains on disk as a regular file (now truly unmanaged by hokuto).
					colWarn.Printf("Dropping unmanaged file from alternatives system: %s\n", path)
					removedCount++
					// Do not add to newAlts
				}
			}
		}

		entry.Alternatives = newAlts
	}

	// 3. Cleanup empty file entries OR entries with only one managed owner (no conflict)
	prunedCount := 0
	for path, entry := range db.Files {
		if len(entry.Alternatives) == 0 {
			delete(db.Files, path)
			modified = true
		} else {
			// If only one owner remains, it's no longer an "alternative" conflict.
			owners := getSortedOwners(entry)
			if len(owners) <= 1 {
				delete(db.Files, path)
				modified = true
				prunedCount++
			}
		}
	}

	if modified {
		if err := saveAlternativesDB(hRoot, db, execCtx); err != nil {
			return fmt.Errorf("failed to save DB: %w", err)
		}
		colSuccess.Printf("Cleanup complete. Removed %d unmanaged records, pruned %d redundant entries, switched %d active files.\n", removedCount, prunedCount, switchedCount)
	} else {
		colInfo.Println("No unmanaged alternatives found.")
	}

	return nil
}

func listAlternativesGrouped(db *GlobalAlternativesDB) error {
	// Group files by their set of owners (Conflict Set)
	type GroupStats struct {
		Files       []string
		OwnerCounts map[string]int
	}
	groups := make(map[string]*GroupStats)

	for path, entry := range db.Files {
		owners := getSortedOwners(entry)
		if len(owners) == 0 {
			continue // Should not happen for valid entries
		}
		groupKey := strings.Join(owners, ", ")

		stats, exists := groups[groupKey]
		if !exists {
			stats = &GroupStats{
				Files:       []string{},
				OwnerCounts: make(map[string]int),
			}
			groups[groupKey] = stats
		}
		stats.Files = append(stats.Files, path)

		active := getActiveOwner(entry)
		// Active might be comma-separated if shared, or "unmanaged"
		// We'll count distinct active packages logic?
		// Simpler: Just count how many files have this exact active string first.
		stats.OwnerCounts[active]++
	}

	// Sort keys for deterministic output
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		stats := groups[key]
		colArrow.Print("-> ")

		// Format: "pkgA, pkgB have 5 alternatives. Active: pkgA (3), pkgB (2)"
		var activeSummary []string
		for owner, count := range stats.OwnerCounts {
			activeSummary = append(activeSummary, fmt.Sprintf("%s (%d)", owner, count))
		}
		sort.Strings(activeSummary) // Sort for consistency

		colInfo.Printf("%s\n", key)
		// Check indentation/formatting
		fmt.Printf("   %d files. Active dist: %s\n", len(stats.Files), strings.Join(activeSummary, ", "))
	}
	return nil
}

func handleAlternativeSwitch(hRoot string, db *GlobalAlternativesDB, targetPkg string) error {
	return runAlternativesTUI(hRoot, db, targetPkg)
}

// activateAlternativeForOwner makes the alternative owned by pkgName active.
// Returns true if a change was made.
func activateAlternativeForOwner(hRoot, path string, entry *FileEntry, pkgName string, execCtx *Executor) (bool, error) {
	// Find the alternative owned by pkgName
	var targetAlt *Alternative
	var activeAlt *Alternative

	for _, alt := range entry.Alternatives {
		if alt.State == StateActive {
			if activeAlt != nil {
				return false, fmt.Errorf("multiple active alternatives recorded for %s", path)
			}
			activeAlt = alt
		}
		for _, o := range alt.Owners {
			if o == pkgName {
				targetAlt = alt
			}
		}
	}

	if targetAlt == nil {
		return false, fmt.Errorf("package '%s' does not provide an alternative for this file", pkgName)
	}

	if targetAlt == activeAlt {
		// Already active
		return false, nil
	}

	targetAbsPath := filepath.Join(hRoot, path)
	if activeAlt != nil {
		currentInfo, err := alternativeFileMetadata(targetAbsPath, execCtx)
		if err != nil {
			return false, fmt.Errorf("failed to inspect active alternative: %w", err)
		}
		if !alternativeMatchesInfo(activeAlt, currentInfo) {
			return false, fmt.Errorf("active alternative has been modified on disk")
		}
		if err := ensureAlternativeStored(hRoot, targetAbsPath, currentInfo, execCtx); err != nil {
			return false, fmt.Errorf("failed to stash current alternative: %w", err)
		}
	}

	if err := restoreAlternativeContent(hRoot, path, targetAlt, execCtx); err != nil {
		return false, err
	}
	setActiveAlternative(entry, targetAlt)
	return true, nil
}

// activateAlternativesForOwnerBatch switches distinct conflict paths in
// parallel and leaves persistence to the caller, allowing one DB commit for a
// multi-selection operation.
func activateAlternativesForOwnerBatch(hRoot string, db *GlobalAlternativesDB, paths []string, pkgName string, execCtx *Executor) (int, error) {
	seen := make(map[string]bool, len(paths))
	type activationJob struct {
		path  string
		entry *FileEntry
	}
	jobs := make([]activationJob, 0, len(paths))
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		entry := db.Files[path]
		if entry == nil {
			return 0, fmt.Errorf("no alternatives recorded for %s", path)
		}
		jobs = append(jobs, activationJob{path: path, entry: entry})
	}
	if len(jobs) == 0 {
		return 0, nil
	}

	workerLimit := maxAlternativeWorkers
	if workerLimit > len(jobs) {
		workerLimit = len(jobs)
	}
	sem := make(chan struct{}, workerLimit)
	changed := make([]bool, len(jobs))
	errs := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			job := jobs[index]
			changed[index], errs[index] = activateAlternativeForOwner(hRoot, job.path, job.entry, pkgName, execCtx)
			if errs[index] != nil {
				errs[index] = fmt.Errorf("%s: %w", job.path, errs[index])
			}
		}(i)
	}
	wg.Wait()

	changedCount := 0
	var firstErr error
	for i := range jobs {
		if changed[i] {
			changedCount++
		}
		if firstErr == nil && errs[i] != nil {
			firstErr = errs[i]
		}
	}
	return changedCount, firstErr
}
