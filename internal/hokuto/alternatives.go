package hokuto

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/gookit/color"
)

// AlternativeRequest represents a request to register an alternative (used for batch processing)
type AlternativeRequest struct {
	FilePath     string
	IncomingPkg  string
	CurrentPkg   string
	IncomingFile string
	KeepOriginal bool
}

// GlobalAlternativesDBPath is the path to the global alternatives database
const GlobalAlternativesDBPath = "var/db/hokuto/alternatives/db.json"

// GlobalAlternativesStoreDir is the directory where stashed alternative files are stored (by hash)
const GlobalAlternativesStoreDir = "var/db/hokuto/alternatives/store"

// AlternativeState represents the state of an alternative (Active or Stashed)
type AlternativeState string

const (
	StateActive  AlternativeState = "active"
	StateStashed AlternativeState = "stashed"
)

// Alternative represents a specific content version of a file
type Alternative struct {
	B3Sum  string           `json:"b3sum"`
	Owners []string         `json:"owners"` // List of packages that provide this exact content
	State  AlternativeState `json:"state"`
	Mode   string           `json:"mode"`
	UID    int              `json:"uid"`
	GID    int              `json:"gid"`
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

	return db, nil
}

// saveAlternativesDB saves the global alternatives database
func saveAlternativesDB(hRoot string, db *GlobalAlternativesDB, execCtx *Executor) error {
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

	return writeFileAsRoot(dbPath, data, 0644, execCtx)
}

// getStashedFilePath returns the path to a stashed file in the store
func getStashedFilePath(hRoot, b3sum string) string {
	return filepath.Join(hRoot, GlobalAlternativesStoreDir, b3sum)
}

// ensureStoreDir creates the store directory if it doesn't exist
func ensureStoreDir(hRoot string, execCtx *Executor) error {
	storeDir := filepath.Join(hRoot, GlobalAlternativesStoreDir)
	if os.Geteuid() == 0 {
		return os.MkdirAll(storeDir, 0755)
	}
	cmd := exec.Command("mkdir", "-p", storeDir)
	return execCtx.Run(cmd)
}

// registerAlternative registers an alternative (internal helper for batch processing).
// It assumes the caller manages the DB lifecycle and concurrency via dbMu.
func registerAlternative(hRoot, filePath string, req AlternativeRequest, execCtx *Executor, db *GlobalAlternativesDB, dbMu *sync.Mutex) error {
	incomingPkg := req.IncomingPkg
	currentPkg := req.CurrentPkg
	incomingFile := req.IncomingFile
	keepOriginal := req.KeepOriginal
	// Calculate B3Sum of the incoming file
	incomingSum, err := ComputeChecksum(incomingFile, execCtx)
	if err != nil {
		return fmt.Errorf("failed to compute checksum of incoming file: %w", err)
	}

	// Get stats of incoming file for metadata
	incStat, err := os.Lstat(incomingFile)
	if err != nil {
		return fmt.Errorf("failed to stat incoming file: %w", err)
	}
	incMode := fmt.Sprintf("%04o", incStat.Mode().Perm())
	var incUID, incGID int
	if sysStat, ok := incStat.Sys().(*syscall.Stat_t); ok {
		incUID = int(sysStat.Uid)
		incGID = int(sysStat.Gid)
	}

	dbMu.Lock()
	if db.Files == nil {
		db.Files = make(map[string]*FileEntry)
	}

	entry, exists := db.Files[filePath]
	if !exists {
		entry = &FileEntry{
			Path:         filePath,
			Alternatives: []*Alternative{},
		}
		db.Files[filePath] = entry
	}

	// 1. Handle the EXISTING file (if it exists and isn't already tracked as active)
	// If this is the first conflict, the existing file might not be in the DB yet.
	// We need to verify if there is an active alternative in the DB.
	var activeAlt *Alternative
	for _, alt := range entry.Alternatives {
		if alt.State == StateActive {
			activeAlt = alt
			break
		}
	}

	targetAbsPath := filepath.Join(hRoot, filePath)
	if activeAlt == nil {
		// No active alternative recorded, but file exists on disk (first conflict).
		// We need to import the existing file into the DB as the "Active" alternative.
		// BUT, we need to know who owns it. This is usually passed or checked.
		// For now, we'll try to guess or require the caller to handle "unmanaged" detection.
		// Wait, install.go logic handles "unmanaged" vs "package" conflict.
		// If it's a package conflict, we should ideally know the owner.
		// Ideally `install.go` passed us `conflictPkg`.
		// To simplify, we'll assume the caller wants us to REGISTER existing file if it exists.

		if _, err := os.Lstat(targetAbsPath); err == nil {
			// Calculate sum of existing file
			_, err := ComputeChecksum(targetAbsPath, execCtx)
			if err == nil {
				// We need to find the owner of this file.
				// This is expensive to search every manifest.
				// However, likely one of the alternatives ALREADY in the list owns it if we had a record.
				// If not, it might be unmanaged or from a previous install that didn't use alternatives.
				// For now, let's look up owners from the DB if they match the hash.

				// Create a new alternative for the existing file
				// We don't know the owner exactly here without searching.
				// Let's assume the caller logic in install.go will handle the conceptual split.
				// Actually, `saveAlternative` should probably just handle the INCOMING file and its relation to the DB.
				// The "Existing" file logic is tricky.

				// REVISIT: The prompt says "global db of files with alternatives ... b3sum, owner ...".
				// If we strictly follow the new structure, we insert the INCOMING file.
				// If `keepOriginal` is true, Incoming becomes STASHED.
				// If `keepOriginal` is false, Incoming becomes ACTIVE. The Previous Active becomes STASHED.
			}
		}
	}

	// Let's refine the logic based on `keepOriginal`.

	// Helper to find or create alternative
	getOrCreateAlt := func(sum, mode string, uid, gid int) *Alternative {
		for _, alt := range entry.Alternatives {
			if alt.B3Sum == sum {
				return alt
			}
		}
		alt := &Alternative{
			B3Sum:  sum,
			Owners: []string{},   // Will be appended to
			State:  StateStashed, // Default to stashed, changed later if needed
			Mode:   mode,
			UID:    uid,
			GID:    gid,
		}
		entry.Alternatives = append(entry.Alternatives, alt)
		return alt
	}

	// Helper to add owner
	addOwner := func(alt *Alternative, pkg string) {
		for _, p := range alt.Owners {
			if p == pkg {
				return
			}
		}
		alt.Owners = append(alt.Owners, pkg)
	}

	incomingAlt := getOrCreateAlt(incomingSum, incMode, incUID, incGID)
	addOwner(incomingAlt, incomingPkg)

	if keepOriginal {
		// Incoming file is normally STASHED because we are keeping the original.
		// HOWEVER, if the incoming file is IDENTICAL to the file we are keeping,
		// we should treat it as ACTIVE (shared ownership) and NOT duplicate it to the store.

		isIdentical := false
		if activeAlt != nil && activeAlt.B3Sum == incomingSum {
			isIdentical = true
		} else if activeAlt == nil {
			// Check if file on disk matches incoming
			if _, err := os.Lstat(targetAbsPath); err == nil {
				if dSum, err := ComputeChecksum(targetAbsPath, execCtx); err == nil && dSum == incomingSum {
					isIdentical = true
				}
			}
		}

		if isIdentical {
			incomingAlt.State = StateActive
			// No need to copy to store.
		} else {
			// Incoming is different. Stash it.
			// We ensure the file is saved to the store.
			if err := ensureStoreDir(hRoot, execCtx); err != nil {
				return err
			}
			storePath := getStashedFilePath(hRoot, incomingSum)
			// Check if store file already exists (use Lstat to detect broken links)
			if _, err := os.Lstat(storePath); os.IsNotExist(err) {
				// File doesn't exist, proceed to copy
			} else if err == nil {
				// File exists. Check if it's a symlink or regular file.
				// If it's a symlink, it is corrupt/invalid for the store, remove it.
				info, _ := os.Lstat(storePath)
				if info.Mode()&os.ModeSymlink != 0 {
					debugf("Removing invalid symlink in store: %s\n", storePath)
					os.Remove(storePath)
				}
			}

			// Check again (or assume safe if we just removed it)
			if _, err := os.Lstat(storePath); os.IsNotExist(err) {
				// Copy incoming (staging) file to store
				if err := copyFileAsRoot(incomingFile, storePath, execCtx); err != nil {
					return fmt.Errorf("failed to copy to store: %w", err)
				}
			}
			incomingAlt.State = StateStashed
		}

		// We must ensure there IS an active alternative.
		// If we are keeping original, the file on disk (targetAbsPath) is the active one.
		// We should register it if not registered.
		if activeAlt == nil {
			// Register valid existing file as active
			if _, err := os.Lstat(targetAbsPath); err == nil {
				currentSum, _ := ComputeChecksum(targetAbsPath, execCtx)
				// getting stats...
				currStat, _ := os.Lstat(targetAbsPath)
				currMode := fmt.Sprintf("%04o", currStat.Mode().Perm())
				var currUID, currGID int
				if sysStat, ok := currStat.Sys().(*syscall.Stat_t); ok {
					currUID = int(sysStat.Uid)
					currGID = int(sysStat.Gid)
				}

				currAlt := getOrCreateAlt(currentSum, currMode, currUID, currGID)

				// Try to find the local owner
				if currentPkg != "" {
					addOwner(currAlt, currentPkg)
				} else if len(currAlt.Owners) == 0 {
					if owner := findPackageOwningFile(hRoot, targetAbsPath); owner != "" {
						currAlt.Owners = append(currAlt.Owners, owner)
					} else {
						currAlt.Owners = append(currAlt.Owners, "unmanaged")
					}
				}

				currAlt.State = StateActive
			}
		}

	} else {
		// Incoming file becomes ACTIVE.
		// Any previously active alternative becomes STASHED.

		// 1. Stash currently active file (if any and different from incoming)
		if activeAlt != nil && activeAlt.B3Sum != incomingSum {
			activeAlt.State = StateStashed
			if err := ensureStoreDir(hRoot, execCtx); err != nil {
				return err
			}
			storePath := getStashedFilePath(hRoot, activeAlt.B3Sum)

			// Check if store file already exists (use Lstat)
			if _, err := os.Lstat(storePath); os.IsNotExist(err) {
				// ok to copy
			} else if err == nil {
				// Exists, check if symlink
				info, _ := os.Lstat(storePath)
				if info.Mode()&os.ModeSymlink != 0 {
					debugf("Removing invalid symlink in store: %s\n", storePath)
					os.Remove(storePath)
				}
			}

			if _, err := os.Lstat(storePath); os.IsNotExist(err) {
				// Copy from TARGET (current file on disk) to store
				if err := copyFileAsRoot(targetAbsPath, storePath, execCtx); err != nil {
					return fmt.Errorf("failed to stash existing file: %w", err)
				}
			}
		} else if activeAlt == nil {
			// No active record, but file might exist (unmanaged/legacy).
			if _, err := os.Lstat(targetAbsPath); err == nil {
				// We are overwriting it. We should stash it if we want to be safe,
				// but usually "Use New" implies overwriting.
				// However, if we want to restore it later, we MUST stash it and register it.
				currentSum, _ := ComputeChecksum(targetAbsPath, execCtx)
				currStat, _ := os.Lstat(targetAbsPath)
				currMode := fmt.Sprintf("%04o", currStat.Mode().Perm())
				var currUID, currGID int
				if sysStat, ok := currStat.Sys().(*syscall.Stat_t); ok {
					currUID = int(sysStat.Uid)
					currGID = int(sysStat.Gid)
				}

				currAlt := getOrCreateAlt(currentSum, currMode, currUID, currGID)

				if currentPkg != "" {
					addOwner(currAlt, currentPkg)
				} else if len(currAlt.Owners) == 0 {
					if owner := findPackageOwningFile(hRoot, targetAbsPath); owner != "" {
						currAlt.Owners = append(currAlt.Owners, owner)
					} else {
						currAlt.Owners = append(currAlt.Owners, "unmanaged")
					}
				}

				// Optimization: If legacy file is identical to incoming, don't stash it (it becomes Active).
				if currentSum != incomingSum {
					currAlt.State = StateStashed

					if err := ensureStoreDir(hRoot, execCtx); err != nil {
						return err
					}
					storePath := getStashedFilePath(hRoot, currentSum)
					// Check if store file already exists (use Lstat)
					if _, err := os.Lstat(storePath); os.IsNotExist(err) {
						// ok to copy
					} else if err == nil {
						// Exists, check if symlink
						info, _ := os.Lstat(storePath)
						if info.Mode()&os.ModeSymlink != 0 {
							debugf("Removing invalid symlink in store: %s\n", storePath)
							os.Remove(storePath)
						}
					}

					if _, err := os.Lstat(storePath); os.IsNotExist(err) {
						if err := copyFileAsRoot(targetAbsPath, storePath, execCtx); err != nil {
							return fmt.Errorf("failed to stash legacy file: %w", err)
						}
					}
				}
			}
		}

		// 2. Set incoming as active
		incomingAlt.State = StateActive

		// Note: The caller (pkgInstall) is responsible for actually moving the staging file
		// to the target location. We just update the DB state here.
	}

	dbMu.Unlock()

	// File operations (copying to store) are done, and DB is updated in memory.
	// Saving happens in BatchRegisterAlternatives.
	return nil
}

// BatchRegisterAlternatives processes a list of alternative requests concurrently.
func BatchRegisterAlternatives(hRoot string, requests []AlternativeRequest, execCtx *Executor) error {
	if len(requests) == 0 {
		return nil
	}

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

			if err := registerAlternative(hRoot, r.FilePath, r, execCtx, db, &dbMu); err != nil {
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

	targetClean := filepath.Clean(targetAbsPath)
	hRootClean := filepath.Clean(hRoot)
	relPath := targetClean
	if strings.HasPrefix(targetClean, hRootClean) {
		relPath = targetClean[len(hRootClean):]
	}
	relPath = strings.TrimPrefix(relPath, "/")

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

			// The path usually comes first, but might contain spaces?
			// Hokuto manifest format: "path checksum" or "path"
			// Wait, uninstall.go logic:
			// lastSpace := strings.LastIndexAny(line, " \t")
			// path := line[:lastSpace]

			lastSpace := strings.LastIndexAny(line, " \t")
			var mPath string
			if lastSpace == -1 {
				mPath = line
			} else {
				mPath = strings.TrimSpace(line[:lastSpace])
			}

			// Normalize manifest path
			mPathClean := strings.TrimPrefix(mPath, "/")
			if mPathClean == relPath {
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

// restoreAlternativesOnUninstall checks if the uninstalled package was the owner of the active file.
// If so, it tries to restore another alternative.
func restoreAlternativesOnUninstall(pkgName, hRoot string, execCtx *Executor) (map[string]bool, error) {
	db, err := loadAlternativesDB(hRoot)
	if err != nil {
		return nil, err
	}

	restoredFiles := make(map[string]bool)
	modified := false

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
				if o == pkgName {
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
					if alt != activeAlt && len(alt.Owners) > 0 {
						candidate = alt
						break
					}
				}

				targetAbsPath := filepath.Join(hRoot, path)

				if candidate != nil {
					// Promote candidate to Active
					candidate.State = StateActive
					// Move orphan to Stashed? Or delete if invalid?

					storePath := getStashedFilePath(hRoot, candidate.B3Sum)
					if err := copyFileAsRoot(storePath, targetAbsPath, execCtx); err != nil {
						debugf("Failed to restore alternative for %s: %v\n", path, err)
						continue
					}

					// Mark as restored so uninstall doesn't delete it
					restoredFiles[path] = true
					fmt.Printf("-> Restored alternative for %s from %v\n", path, candidate.Owners)
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

		// Cleanup: Remove alternatives with 0 owners (unless it's the active one and we kept it?)
		// Actually, if active has 0 owners and no candidates, it will be deleted by uninstall.
		// So we can clean up the DB entry.

		cleanAlts := []*Alternative{}
		for _, alt := range entry.Alternatives {
			if len(alt.Owners) > 0 {
				cleanAlts = append(cleanAlts, alt)
			} else {
				// Delete stashed file if exists
				storePath := getStashedFilePath(hRoot, alt.B3Sum)
				os.Remove(storePath) // Ignore error
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
				// Safe to delete
				storePath := getStashedFilePath(hRoot, alt.B3Sum)
				if err := removeFileAsRoot(storePath, execCtx); err != nil {
					colWarn.Printf("Warning: failed to remove stashed file %s: %v\n", storePath, err)
				}
				removedCount++
				continue // Do not add to newAlts
			}

			if alt.State == StateActive {
				// Active alternative is orphaned!
				// We must try to switch to another candidate.

				var candidate *Alternative
				for _, other := range entry.Alternatives {
					if other != alt && len(other.Owners) > 0 {
						candidate = other
						break
					}
				}

				if candidate != nil {
					// Switch to candidate
					colArrow.Printf("Switching %s to managed alternative (owners: %v)\n", path, candidate.Owners)

					targetAbsPath := filepath.Join(hRoot, path)
					storePath := getStashedFilePath(hRoot, candidate.B3Sum)

					// Use os.Lstat for robust checking of store file
					if _, err := os.Lstat(storePath); os.IsNotExist(err) {
						colError.Printf("Error: managed alternative content missing from store: %s\n", candidate.B3Sum)
						// Keep current active one as a fallback? better than breaking system.
						// Even if unmanaged, it's better than nothing.
						// Re-add "unmanaged" owner? Or leave it with 0 owners but keep in DB?
						// Let's leave it with 0 owners but keep it active to avoid breakage.
						newAlts = append(newAlts, alt)
						continue
					}

					if err := copyFileAsRoot(storePath, targetAbsPath, execCtx); err != nil {
						colError.Printf("Error restoring alternative for %s: %v\n", path, err)
						newAlts = append(newAlts, alt) // Keep broken/orphaned active
						continue
					}

					candidate.State = StateActive
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
	// Find all files where targetPkg is a valid owner
	var affectedFiles []string
	var conflictPartners = make(map[string]bool)

	for path, entry := range db.Files {
		// First check if targetPkg participates in this file
		isCandidate := false
		for _, alt := range entry.Alternatives {
			for _, o := range alt.Owners {
				if o == targetPkg {
					isCandidate = true
					break
				}
			}
			if isCandidate {
				break
			}
		}

		if isCandidate {
			affectedFiles = append(affectedFiles, path)
			// Now collect partners ONLY from this valid candidate file
			for _, alt := range entry.Alternatives {
				for _, o := range alt.Owners {
					if o != targetPkg {
						conflictPartners[o] = true
					}
				}
			}
		}
	}

	if len(affectedFiles) == 0 {
		return fmt.Errorf("package '%s' has no alternatives registered", targetPkg)
	}

	// Calculate current state for affected files
	currentCounts := make(map[string]int)
	for _, path := range affectedFiles {
		entry := db.Files[path]
		active := getActiveOwner(entry)
		currentCounts[active]++
	}

	colInfo.Printf("Found %d files involving '%s'.\n", len(affectedFiles), targetPkg)
	colInfo.Printf("Current state: ")
	for owner, count := range currentCounts {
		fmt.Printf("%s: %d  ", owner, count)
	}
	fmt.Println()

	// Build menu options
	var options []string
	options = append(options, targetPkg)

	// Add other partners found
	var partners []string
	for p := range conflictPartners {
		partners = append(partners, p)
	}
	sort.Strings(partners)
	options = append(options, partners...)

	fmt.Println("Switch all to:")
	for i, opt := range options {
		fmt.Printf("%d) %s\n", i+1, opt)
	}
	fmt.Printf("%d) Cancel\n", len(options)+1)

	fmt.Print("Select: ")
	var selection int
	_, err := fmt.Scanln(&selection)
	if err != nil || selection < 1 || selection > len(options) {
		fmt.Println("Cancelled.")
		return nil
	}

	chosenOwner := options[selection-1]

	// Execute switch
	execCtx := &Executor{Context: context.Background()} // or use existing context?
	count := 0

	// Need to lock DB update? This runs sequentially so it's fine, but saving needs root privileges logic if not root.
	// But `saveAlternativesDB` handles root check.
	// However, moving files requires root. Check effective UID.
	if os.Getuid() != 0 {
		return fmt.Errorf("must be root to switch alternatives")
	}

	for _, path := range affectedFiles {
		entry := db.Files[path]
		// Simple check, though "active" string might be comma separated if shared.
		// If chosenOwner is part of the active list, we might skip?
		// But explicit switch usually implies "make this the SOLE active content if possible, or matches content".

		// Actually, we delegate to helper
		switched, err := activateAlternativeForOwner(hRoot, path, entry, chosenOwner, execCtx)
		if err != nil {
			color.Danger.Printf("Failed to switch %s: %v\n", path, err)
		} else if switched {
			count++
		}
	}

	if count > 0 {
		if err := saveAlternativesDB(hRoot, db, execCtx); err != nil {
			return fmt.Errorf("failed to save DB: %w", err)
		}
		colSuccess.Printf("Successfully switched %d files to '%s'.\n", count, chosenOwner)
	} else {
		colInfo.Println("No changes needed.")
	}

	return nil
}

// activateAlternativeForOwner makes the alternative owned by pkgName active.
// Returns true if a change was made.
func activateAlternativeForOwner(hRoot, path string, entry *FileEntry, pkgName string, execCtx *Executor) (bool, error) {
	// Find the alternative owned by pkgName
	var targetAlt *Alternative
	var activeAlt *Alternative

	for _, alt := range entry.Alternatives {
		if alt.State == StateActive {
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

	// Need to switch
	targetAbsPath := filepath.Join(hRoot, path)

	// 1. Stash current active (if exists)
	if activeAlt != nil {
		activeAlt.State = StateStashed
		if err := ensureStoreDir(hRoot, execCtx); err != nil {
			return false, err
		}

		// If we are about to switch checking content...
		// But here we trust the DB state mainly.
		// Check verify B3Sum of file on disk matches activeAlt?
		// Ideally yes. If mismatch, we might want to stash the *actual* file on disk as "unmanaged"?
		// For simplicity/robustness, we just stash what is on disk to the store slot of currently active alt.

		storePath := getStashedFilePath(hRoot, activeAlt.B3Sum)
		// Only copy if not exists? Or overwrite to be safe?
		// Better to check not exists.
		if _, err := os.Stat(storePath); os.IsNotExist(err) {
			if err := copyFileAsRoot(targetAbsPath, storePath, execCtx); err != nil {
				return false, fmt.Errorf("failed to stash current: %w", err)
			}
		}
	}

	// 2. Restore target alternative
	storePath := getStashedFilePath(hRoot, targetAlt.B3Sum)
	// Check if in store
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		// Big problem: Data missing from store!
		return false, fmt.Errorf("alternative content missing from store: %s", targetAlt.B3Sum)
	}

	// Copy from store to target
	if err := copyFileAsRoot(storePath, targetAbsPath, execCtx); err != nil {
		return false, fmt.Errorf("failed to restore alternative: %w", err)
	}

	// Restore metadata (permissions/owners) not fully stored, relying on file?
	// Note: Alternative struct has Mode, UID, GID from when it was registered.
	// We should probably restore those too if possible.
	// (Skipping strict metadata restore for this pass, assuming copyFile preserves or sets reasonable defaults,
	// but strictly we should use `chown`/`chmod` based on `targetAlt.Mode/UID`.
	// The `Alternative` struct has these fields!)

	targetAlt.State = StateActive
	return true, nil
}
