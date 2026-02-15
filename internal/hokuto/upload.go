package hokuto

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type uploadCacheEntry struct {
	Size  int64     `json:"size"`
	Mtime time.Time `json:"mtime"`
	Entry RepoEntry `json:"entry"`
}

func loadUploadCache(path string) map[string]uploadCacheEntry {
	cache := make(map[string]uploadCacheEntry)
	data, err := os.ReadFile(path)
	if err != nil {
		return cache
	}
	json.Unmarshal(data, &cache)
	return cache
}

func saveUploadCache(path string, cache map[string]uploadCacheEntry) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// handleUploadCommand implements the 'hokuto upload' command.
func handleUploadCommand(args []string, cfg *Config) error {
	ctx := context.Background()

	// 1. Parse Flags
	uploadCmd := flag.NewFlagSet("upload", flag.ContinueOnError)
	var cleanup = uploadCmd.Bool("cleanup", false, "Prompt to remove older versions on remote")
	var reindex = uploadCmd.Bool("reindex", false, "Regenerate the remote index by scanning the bucket")
	var sync = uploadCmd.Bool("sync", false, "Upload all local files missing on remote without prompt")
	var prompt = uploadCmd.Bool("prompt", false, "Prompt for each local file missing on remote (optionally filtered by name)")
	var syncdb = uploadCmd.Bool("syncdb", false, "Upload only the global package database (pkg-db.json.zst)")
	var deletePkg = uploadCmd.String("delete", "", "Delete all variants of a package from remote (use --delete=all to delete everything)")
	var migrate = uploadCmd.Bool("copy-from-r2", false, "Copy all files from Cloudflare R2 to current mirror")

	// Set output to stderr to avoid polluting stdout if captured
	uploadCmd.SetOutput(os.Stderr)

	if len(args) == 0 {
		fmt.Println("Usage: hk upload [options] [pkgname]")
		fmt.Println("")
		fmt.Println("Options:")
		uploadCmd.PrintDefaults()
		return nil
	}

	if err := uploadCmd.Parse(args); err != nil {
		return nil
	}

	filters := uploadCmd.Args()

	// Usage check
	if *deletePkg == "" && !*sync && !*prompt && !*cleanup && !*reindex && !*syncdb && !*migrate {
		fmt.Println("Usage: hk upload [options] [pkgname]")
		fmt.Println("")
		fmt.Println("Options:")
		uploadCmd.PrintDefaults()
		return nil
	}

	// --- Migration Logic ---
	if *migrate {
		if cfg.Values["HOKUTO_MIRROR_NAME"] == "" || cfg.Values["HOKUTO_MIRROR_NAME"] == "cloudflare-r2" {
			return fmt.Errorf("Copying requires an active mirror different from the default Cloudflare R2")
		}

		colArrow.Print("-> ")
		colSuccess.Printf("Copying from Cloudflare R2 to '%s'\n", cfg.Values["HOKUTO_MIRROR_NAME"])

		// 1. Destination Client (Active Mirror)
		destClient, err := NewR2Client(cfg)
		if err != nil {
			return fmt.Errorf("failed to connect to destination mirror: %w", err)
		}

		// 2. Source Client (R2)
		// Create a config copy and unset mirror name to force fallback
		legacyCfg := &Config{Values: make(map[string]string)}
		maps.Copy(legacyCfg.Values, cfg.Values)
		delete(legacyCfg.Values, "HOKUTO_MIRROR_NAME")

		sourceClient, err := NewR2Client(legacyCfg)
		if err != nil {
			return fmt.Errorf("failed to connect to R2: %w", err)
		}

		// 3. List Source
		colArrow.Print("-> ")
		colSuccess.Println("Listing files on R2")
		objects, err := sourceClient.ListObjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list R2 objects: %w", err)
		}

		colNote.Printf("Found %d objects. Checking destination\n", len(objects))

		var migratedCount int
		var skippedCount int

		destObjects, err := destClient.ListObjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list destination objects: %w", err)
		}
		destMap := make(map[string]int64)
		for _, o := range destObjects {
			destMap[o.Key] = o.Size
		}

		var toMigrate []R2Object
		for _, obj := range objects {
			if size, exists := destMap[obj.Key]; exists && size == obj.Size {
				skippedCount++
				continue
			}
			toMigrate = append(toMigrate, obj)
		}

		for i, obj := range toMigrate {
			// Download
			data, err := sourceClient.DownloadFile(ctx, obj.Key)
			if err != nil {
				colError.Printf("Failed to download: %v\n", err)
				continue
			}

			// Upload
			if err := destClient.UploadFile(ctx, obj.Key, data, i+1, len(toMigrate)); err != nil {
				colError.Printf("Failed to upload: %v\n", err)
				continue
			}
			migratedCount++
		}

		colSuccess.Printf("Copy complete. Copied: %d, Skipped: %d\n", migratedCount, skippedCount)
		return nil
	}

	// 2. Initialize R2 Client (Normal Flow)
	if cfg.Values["R2_ACCESS_KEY_ID"] == "" && cfg.Values["HOKUTO_MIRROR_NAME"] == "" {
		// Only check legacy keys if no named mirror is active.
		// NewR2Client checks specifics internally but this check preempts it.
		// We should relax this check if HOKUTO_MIRROR_NAME is set.
	}

	r2, err := NewR2Client(cfg)
	if err != nil {
		return err
	}

	if *syncdb {
		debugf("Flag -syncdb detected. Uploading DB\n")
		return uploadPkgDB(ctx, r2)
	}

	// 3. Fetch Remote Index
	colArrow.Print("-> ")
	colSuccess.Printf("Fetching remote index from %s\n", getMirrorDisplayName(cfg))
	remoteIndexData, err := r2.DownloadFile(ctx, "repo-index.json")
	var remoteIndex []RepoEntry
	if err != nil {
		debugf("Remote index not found or error fetching: %v\n", err)
	} else {
		remoteIndex, err = ParseRepoIndex(remoteIndexData)
		if err != nil {
			return fmt.Errorf("failed to parse remote index: %w", err)
		}
	}

	// 4. Scan Local BinDir and filter for LATEST only
	// (Skip if we are just cleaning up or reindexing and no sync/prompt requested, but reindexing needs scans?
	// The original logic scanned first. Let's keep it to support syncing.)
	colArrow.Print("-> ")
	colSuccess.Printf("Scanning local binaries in %s\n", BinDir)
	localFiles, err := filepath.Glob(filepath.Join(BinDir, "*.tar.zst"))
	if err != nil {
		return err
	}

	cachePath := filepath.Join(CacheDir, "upload-scanning-cache.json")
	cache := loadUploadCache(cachePath)
	cacheUpdated := false

	latestLocals := make(map[string]RepoEntry) // key: Name-Arch-Variant
	for _, file := range localFiles {
		filename := filepath.Base(file)

		info, err := os.Stat(file)
		if err != nil {
			debugf("Warning: skipping %s: %v\n", file, err)
			continue
		}

		var entry RepoEntry
		if cached, ok := cache[filename]; ok && cached.Size == info.Size() && cached.Mtime.Equal(info.ModTime()) {
			entry = cached.Entry
		} else {
			entry, err = ReadPackageMetadata(file)
			if err != nil {
				debugf("Warning: skipping %s: %v\n", file, err)
				continue
			}
			// --- NEW: Sanity Check ---
			if entry.Name == "" || entry.Version == "" {
				debugf("Warning: skipping %s: missing metadata Name or Version (corruption?)\n", filename)
				continue
			}
			cache[filename] = uploadCacheEntry{
				Size:  info.Size(),
				Mtime: info.ModTime(),
				Entry: entry,
			}
			cacheUpdated = true
		}

		key := fmt.Sprintf("%s-%s-%s-%s-%s", entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant)
		if existing, ok := latestLocals[key]; ok {
			// This case should only happen if we have duplicates of the exact same version/revision/arch/variant
			// which shouldn't happen with unique filenames, but good to be safe.
			if isNewer(entry, existing) {
				latestLocals[key] = entry
			}
		} else {
			latestLocals[key] = entry
		}
	}

	if cacheUpdated {
		if err := saveUploadCache(cachePath, cache); err != nil {
			debugf("Warning: failed to save upload scanning cache: %v\n", err)
		}
	}

	// 5. Compare with Remote and Upload
	newIndexMap := make(map[string]RepoEntry)
	for _, entry := range remoteIndex {
		key := fmt.Sprintf("%s-%s-%s-%s-%s", entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant)
		newIndexMap[key] = entry
	}

	// Handle --delete logic explicitly
	var deletionsOccurred bool
	if *deletePkg != "" {
		// Check if user wants to delete everything
		if *deletePkg == "all" {
			colArrow.Print("-> ")
			colError.Println("WARNING: This will delete ALL packages from the remote repository!")
			if !askForConfirmation(colError, "Are you absolutely sure you want to delete ALL remote packages? ") {
				colSuccess.Println("Deletion cancelled.")
				return nil
			}

			colArrow.Print("-> ")
			colSuccess.Println("Scanning all remote packages")

			remoteObjects, err := r2.ListObjects(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to list remote objects: %w", err)
			}

			var foundCount int
			for _, obj := range remoteObjects {
				if strings.HasSuffix(obj.Key, ".tar.zst") {
					if err := r2.DeleteFile(ctx, obj.Key); err != nil {
						fmt.Fprintf(os.Stderr, "Error deleting %s: %v\n", obj.Key, err)
					} else {
						foundCount++
						colSuccess.Printf("Deleted %s\n", obj.Key)
						deletionsOccurred = true
						// Clear the entire index since we're deleting everything
						for k, v := range newIndexMap {
							if v.Filename == obj.Key {
								delete(newIndexMap, k)
							}
						}
					}
				}
			}

			if foundCount == 0 {
				colWarn.Println("No remote packages found.")
			} else {
				colArrow.Print("-> ")
				colSuccess.Printf("Deleted %d packages from remote.\n", foundCount)
			}
		} else {
			// Delete specific package
			colArrow.Print("-> ")
			colSuccess.Printf("Scanning remote for package: %s\n", *deletePkg)

			remoteObjects, err := r2.ListObjects(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to list remote objects: %w", err)
			}

			// Pattern to match: pkgname-version-revision-arch-variant.tar.zst
			// We want to verify that the filename starts with "pkgname-" to avoid partial matches (e.g. "foobar" matching "foo")
			// But verify it carefully.
			// StandardizedRemoteName uses dashes.
			// A stricter check: matches "{pkgName}-*.tar.zst"
			prefix := *deletePkg + "-"

			var foundCount int
			for _, obj := range remoteObjects {
				if strings.HasPrefix(obj.Key, prefix) && strings.HasSuffix(obj.Key, ".tar.zst") {
					colArrow.Print("-> ")
					if askForConfirmation(colWarn, "Delete remote file %s? ", obj.Key) {
						if err := r2.DeleteFile(ctx, obj.Key); err != nil {
							fmt.Fprintf(os.Stderr, "Error deleting %s: %v\n", obj.Key, err)
						} else {
							foundCount++
							colSuccess.Printf("Deleted %s\n", obj.Key)
							// Update in-memory index
							deletionsOccurred = true
							for k, v := range newIndexMap {
								if v.Filename == obj.Key {
									delete(newIndexMap, k)
									// Do NOT break, in case of duplicate entries or just to be safe (though keys are unique)
								}
							}
						}
					}
				}
			}

			if foundCount == 0 {
				colWarn.Printf("No remote files found for package '%s'.\n", *deletePkg)
			} else {
				colArrow.Print("-> ")
				colSuccess.Println("Deletions complete.")
			}
		}
	}

	var reindexedCount int
	if *reindex {
		colArrow.Print("-> ")
		colSuccess.Printf("Re-indexing: Scanning all objects on %s\n", getMirrorDisplayName(cfg))
		remoteObjects, err := r2.ListObjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list remote objects for re-indexing: %w", err)
		}

		// Reconciliation Map: only items actually present on R2 will be in the final index
		reconciledMap := make(map[string]RepoEntry)

		// Index current remoteIndex by filename for fast reconciliation
		oldByFilename := make(map[string]RepoEntry)
		for _, e := range remoteIndex {
			oldByFilename[e.Filename] = e
		}

		localByFilename := make(map[string]RepoEntry)
		for _, entry := range latestLocals {
			localByFilename[entry.Filename] = entry
		}

		for _, obj := range remoteObjects {
			if !strings.HasSuffix(obj.Key, ".tar.zst") {
				continue
			}

			// 1. Check if we already have this in the OLD index and it matches the size
			// AND it has dependency info (Depends field is not empty if it should have some)
			// Actually, just check if it's missing Depends and force re-scan if so.
			if existing, ok := oldByFilename[obj.Key]; ok && existing.Size == obj.Size && len(existing.Depends) > 0 {
				key := fmt.Sprintf("%s-%s-%s-%s-%s", existing.Name, existing.Version, existing.Revision, existing.Arch, existing.Variant)
				reconciledMap[key] = existing
				continue
			}

			// 2. Check if we have it locally
			if local, ok := localByFilename[obj.Key]; ok && local.Size == obj.Size {
				key := fmt.Sprintf("%s-%s-%s-%s-%s", local.Name, local.Version, local.Revision, local.Arch, local.Variant)
				reconciledMap[key] = local
				reindexedCount++
				continue
			}

			// 3. Last resort: download and parse (expensive but necessary for new/changed files)
			colArrow.Print("-> ")
			colWarn.Printf("Remote file %s not in index or local cache. Fetching metadata\n", obj.Key)
			data, err := r2.DownloadFile(ctx, obj.Key)
			if err != nil {
				debugf("Warning: failed to download %s for re-indexing: %v\n", obj.Key, err)
				continue
			}

			// We need a temporary file to use ReadPackageMetadata logic or just use bytes
			tmpFile := filepath.Join(os.TempDir(), obj.Key)
			if err := os.WriteFile(tmpFile, data, 0644); err != nil {
				debugf("Warning: failed to write tmp file for %s: %v\n", obj.Key, err)
				continue
			}
			entry, err := ReadPackageMetadata(tmpFile)
			os.Remove(tmpFile)
			if err != nil {
				debugf("Warning: failed to parse metadata for %s: %v\n", obj.Key, err)
				continue
			}
			// --- NEW: Sanity Check ---
			if entry.Name == "" || entry.Version == "" {
				debugf("Warning: skipping remote file %s: missing metadata Name or Version\n", obj.Key)
				continue
			}

			key := fmt.Sprintf("%s-%s-%s-%s-%s", entry.Name, entry.Version, entry.Revision, entry.Arch, entry.Variant)
			reconciledMap[key] = entry
			reindexedCount++
		}

		newIndexMap = reconciledMap

		if reindexedCount > 0 {
			colSuccess.Printf("Re-indexing complete. Added/Updated %d files in the index.\n", reindexedCount)
		}
	}

	var uploadedCount int
	// Sort local keys for deterministic processing
	var sortedKeys []string
	for k := range latestLocals {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	// First, build a list of everything that definitely needs uploading (or might if prompted)
	type uploadTask struct {
		key    string
		local  RepoEntry
		prompt bool
		reason string
	}
	var tasks []uploadTask

	for _, key := range sortedKeys {
		local := latestLocals[key]
		if *sync && strings.HasPrefix(local.Name, "cuda") {
			continue
		}

		remote, exists := newIndexMap[key]
		needsUpload := false
		reason := ""
		if !exists {
			needsUpload = true
			reason = " (remote missing)"
			// Since we now include version in the key, "newer" logic in the map is less relevant
			// because existing remote versions are separate keys.
			// But if we are overwriting an EXACT match (same version/rev/arch/variant), check checksum.
		} else if local.B3Sum != remote.B3Sum {
			needsUpload = true
			reason = " (checksum mismatch)"
		}

		if needsUpload {
			activePrompt := *prompt
			if activePrompt && len(filters) > 0 {
				matched := false
				for _, f := range filters {
					if strings.Contains(local.Name, f) {
						matched = true
						break
					}
				}
				if !matched {
					activePrompt = false
				}
			}

			if !*sync && !activePrompt {
				continue
			}

			tasks = append(tasks, uploadTask{
				key:    key,
				local:  local,
				prompt: activePrompt,
				reason: reason,
			})
		}
	}

	for i, task := range tasks {
		if task.prompt {
			colArrow.Print("-> ")
			if !askForConfirmation(colWarn, "Upload %s %s-%s (%s, %s)%s? ", task.local.Name, task.local.Version, task.local.Revision, task.local.Arch, task.local.Variant, task.reason) {
				continue
			}
		}

		localPath := filepath.Join(BinDir, task.local.Filename)
		if err := r2.UploadLocalFile(ctx, task.local.Filename, localPath, i+1, len(tasks)); err != nil {
			return fmt.Errorf("failed to upload %s: %w", task.local.Name, err)
		}

		newIndexMap[task.key] = task.local
		uploadedCount++
	}

	// 6. Cleanup old versions on R2
	if *cleanup {
		colArrow.Print("-> ")
		colSuccess.Printf("Checking for old versions on %s to cleanup\n", getMirrorDisplayName(cfg))
		remoteObjects, err := r2.ListObjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list remote files: %w", err)
		}

		// Build a set of filenames currently in the index
		activeFiles := make(map[string]bool)
		for _, entry := range newIndexMap {
			activeFiles[entry.Filename] = true
		}
		activeFiles["repo-index.json"] = true

		var deletedCount int
		for _, obj := range remoteObjects {
			if !activeFiles[obj.Key] && strings.HasSuffix(obj.Key, ".tar.zst") {
				colArrow.Print("-> ")
				if askForConfirmation(colError, "Delete old version from %s: %s? ", getMirrorDisplayName(cfg), obj.Key) {
					if err := r2.DeleteFile(ctx, obj.Key); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: failed to delete %s: %v\n", obj.Key, err)
					} else {
						deletedCount++
					}
				}
			}
		}
		if deletedCount > 0 {
			colSuccess.Printf("Cleanup complete. Deleted %d old files.\n", deletedCount)
		}
	}

	// 7. Storage Reporting
	colArrow.Print("-> ")
	colSuccess.Println("Calculating storage usage")
	allObjects, err := r2.ListObjects(ctx, "")
	if err == nil {
		var totalSize int64
		for _, obj := range allObjects {
			totalSize += obj.Size
		}

		activeMirrorName := cfg.Values["HOKUTO_MIRROR_NAME"]
		mType := cfg.Values["MIRROR_"+activeMirrorName+"_TYPE"]
		isR2 := (activeMirrorName == "" && cfg.Values["R2_ACCOUNT_ID"] != "") ||
			strings.HasPrefix(strings.ToLower(activeMirrorName), "cloudflare") ||
			strings.ToLower(mType) == "r2"

		colArrow.Print("-> ")
		colSuccess.Printf("Storage used: ")
		if isR2 {
			const tenGB = 10 * 1024 * 1024 * 1024
			percent := (float64(totalSize) / float64(tenGB)) * 100
			colNote.Printf("%s / 10 GiB (%.1f%%)\n", humanReadableSize(totalSize), percent)

			if totalSize > (tenGB * 9 / 10) {
				colWarn.Printf("Warning: You are using over 90%% of your free %s storage limit!\n", getMirrorDisplayName(cfg))
			}
		} else {
			colNote.Printf("%s\n", humanReadableSize(totalSize))
		}
	}

	// 8. Finalize Index
	if uploadedCount > 0 || *cleanup || (*reindex && reindexedCount > 0) || deletionsOccurred {
		colArrow.Print("-> ")
		colSuccess.Println("Updating remote index")

		var finalizedIndex []RepoEntry
		for _, k := range sortedKeys {
			if entry, ok := newIndexMap[k]; ok {
				finalizedIndex = append(finalizedIndex, entry)
			}
		}
		// Also add entries from remote that weren't in sortedKeys (local)
		for k, entry := range newIndexMap {
			found := false
			for _, sk := range sortedKeys {
				if k == sk {
					found = true
					break
				}
			}
			if !found {
				finalizedIndex = append(finalizedIndex, entry)
			}
		}
		// Sort final index by Name, Arch, Variant for consistency
		sort.Slice(finalizedIndex, func(i, j int) bool {
			a, b := finalizedIndex[i], finalizedIndex[j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Arch != b.Arch {
				return a.Arch < b.Arch
			}
			if a.Variant != b.Variant {
				return a.Variant < b.Variant
			}
			// Sort by version (descending preferred? No, usually ls lists ascending, but let's stick to standard sort order)
			// Actually, for "ls", seeing versions in order is good.
			// Let's sort ascending by version, then revision.
			cmp := compareVersions(a.Version, b.Version)
			if cmp != 0 {
				return cmp < 0
			}
			ar, _ := strconv.Atoi(a.Revision)
			br, _ := strconv.Atoi(b.Revision)
			return ar < br
		})

		indexBytes, err := json.MarshalIndent(finalizedIndex, "", "  ")
		if err != nil {
			return err
		}
		if err := r2.UploadFile(ctx, "repo-index.json", indexBytes); err != nil {
			return fmt.Errorf("failed to upload index: %w", err)
		}

		// 9. Sign and upload index signature
		sigBytes, err := SignRepoIndex(indexBytes)
		if err != nil {
			colWarn.Printf("Warning: failed to sign repo index: %v. Continuing without signature.\n", err)
		} else {
			if err := r2.UploadFile(ctx, "repo-index.json.sig", sigBytes); err != nil {
				colWarn.Printf("Warning: failed to upload index signature: %v\n", err)
			} else {
				colSuccess.Println("Remote index signature updated.")
			}
		}

		colSuccess.Printf("Sync complete. Updated index with %d new uploads.\n", uploadedCount)
	} else {
		colArrow.Print("-> ")
		colSuccess.Printf("Everything up to date.\n")
	}

	if *sync {
		_ = uploadPkgDB(ctx, r2)
	}

	return nil
}

func uploadPkgDB(ctx context.Context, r2 *R2Client) error {
	colArrow.Print("-> ")
	colNote.Printf("Syncing global package database to %s\n", getMirrorDisplayName(r2.Config))

	debugf("Reading local database from %s\n", PkgDBPath)
	data, err := os.ReadFile(PkgDBPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("local database not found: %s. Generate it first with 'hokuto meta -db'", PkgDBPath)
		}
		return fmt.Errorf("failed to read local database: %w", err)
	}
	debugf("Read %d bytes from database\n", len(data))

	filename := filepath.Base(PkgDBPath)
	debugf("Uploading to R2 as %s\n", filename)
	if err := r2.UploadFile(ctx, filename, data); err != nil {
		return fmt.Errorf("failed to upload database: %w", err)
	}

	colArrow.Print("-> ")
	colSuccess.Println("Global package database synced successfully.")
	return nil
}

func humanReadableSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
