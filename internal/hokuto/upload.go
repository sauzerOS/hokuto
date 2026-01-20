package hokuto

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// handleUploadCommand implements the 'hokuto upload' command.
func handleUploadCommand(args []string, cfg *Config) error {
	ctx := context.Background()

	// 1. Parse Flags
	cleanup := false
	reindex := false
	sync := false
	prompt := false

	if len(args) == 0 {
		fmt.Println("Usage: hk upload [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --sync     Upload all local files missing on remote without prompt")
		fmt.Println("  --prompt   Prompt for confirmation for each local file missing on remote")
		fmt.Println("  --cleanup  Prompt to remove older versions on remote")
		fmt.Println("  --reindex  Regenerate the remote index by scanning the bucket")
		return nil
	}

	for _, arg := range args {
		switch arg {
		case "--cleanup", "-c":
			cleanup = true
		case "--reindex":
			reindex = true
		case "--sync":
			sync = true
		case "--prompt":
			prompt = true
		}
	}

	// 2. Initialize R2 Client
	r2, err := NewR2Client(cfg)
	if err != nil {
		return err
	}

	// 3. Fetch Remote Index
	colArrow.Print("-> ")
	colSuccess.Println("Fetching remote index from R2")
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
	colArrow.Print("-> ")
	colSuccess.Printf("Scanning local binaries in %s\n", BinDir)
	localFiles, err := filepath.Glob(filepath.Join(BinDir, "*.tar.zst"))
	if err != nil {
		return err
	}

	latestLocals := make(map[string]RepoEntry) // key: Name-Arch-Variant
	for _, file := range localFiles {
		entry, err := ReadPackageMetadata(file)
		if err != nil {
			debugf("Warning: skipping %s: %v\n", file, err)
			continue
		}
		key := fmt.Sprintf("%s-%s-%s", entry.Name, entry.Arch, entry.Variant)
		if existing, ok := latestLocals[key]; ok {
			if isNewer(entry, existing) {
				latestLocals[key] = entry
			}
		} else {
			latestLocals[key] = entry
		}
	}

	// 5. Compare with Remote and Upload
	newIndexMap := make(map[string]RepoEntry)
	for _, entry := range remoteIndex {
		key := fmt.Sprintf("%s-%s-%s", entry.Name, entry.Arch, entry.Variant)
		newIndexMap[key] = entry
	}

	var reindexedCount int
	if reindex {
		colArrow.Print("-> ")
		colSuccess.Println("Re-indexing: Scanning all objects on R2")
		remoteObjects, err := r2.ListObjects(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to list remote objects for re-indexing: %w", err)
		}

		localByFilename := make(map[string]RepoEntry)
		for _, entry := range latestLocals {
			localByFilename[entry.Filename] = entry
		}

		for _, obj := range remoteObjects {
			if !strings.HasSuffix(obj.Key, ".tar.zst") {
				continue
			}

			// Check if we already have this in the index map and it matches the size
			if existing, ok := newIndexMap[obj.Key]; ok && existing.Size == obj.Size {
				continue
			}

			// Check if we have it locally
			if local, ok := localByFilename[obj.Key]; ok && local.Size == obj.Size {
				key := fmt.Sprintf("%s-%s-%s", local.Name, local.Arch, local.Variant)
				newIndexMap[key] = local
				reindexedCount++
				continue
			}

			// Last resort: download and parse (expensive)
			colArrow.Print("-> ")
			colWarn.Printf("Remote file %s not in index or local cache. Fetching metadata...\n", obj.Key)
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

			key := fmt.Sprintf("%s-%s-%s", entry.Name, entry.Arch, entry.Variant)
			newIndexMap[key] = entry
			reindexedCount++
		}
		if reindexedCount > 0 {
			colSuccess.Printf("Re-indexing complete. Added %d files to the index.\n", reindexedCount)
		}
	}

	var uploadedCount int
	// Sort local keys for deterministic processing
	var sortedKeys []string
	for k := range latestLocals {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		local := latestLocals[key]
		remote, exists := newIndexMap[key]

		needsUpload := false
		if !exists {
			needsUpload = true
		} else if isNewer(local, remote) || local.B3Sum != remote.B3Sum {
			needsUpload = true
		}

		if needsUpload {
			if !sync && !prompt {
				// If neither --sync nor --prompt is used, we only upload if we have an explicit reason
				// but based on user request, hk upload without args shows help.
				// So if we are here, some other flag like --cleanup or --reindex was used.
				// In that case, we should probably SKIP uploads unless asked.
				continue
			}

			colArrow.Print("-> ")
			if prompt {
				if !askForConfirmation(colWarn, "Upload %s %s-%s (%s, %s)? ", local.Name, local.Version, local.Revision, local.Arch, local.Variant) {
					continue
				}
			}

			colArrow.Print("-> ")
			colSuccess.Printf("Uploading to R2: %s\n", local.Filename)
			localPath := filepath.Join(BinDir, local.Filename)
			if err := r2.UploadLocalFile(ctx, local.Filename, localPath); err != nil {
				return fmt.Errorf("failed to upload %s: %w", local.Name, err)
			}

			newIndexMap[key] = local
			uploadedCount++
		}
	}

	// 6. Cleanup old versions on R2
	if cleanup {
		colArrow.Print("-> ")
		colSuccess.Println("Checking for old versions on R2 to cleanup")
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
				if askForConfirmation(colError, "Delete old version from R2: %s? ", obj.Key) {
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

		const tenGB = 10 * 1024 * 1024 * 1024
		percent := (float64(totalSize) / float64(tenGB)) * 100
		colArrow.Print("-> ")
		colSuccess.Printf("Storage used: ")
		colNote.Printf("%s / 10 GiB (%.1f%%)\n", humanReadableSize(totalSize), percent)

		if totalSize > (tenGB * 9 / 10) {
			colWarn.Println("Warning: You are using over 90% of your free R2 storage limit!")
		}
	}

	// 8. Finalize Index
	if uploadedCount > 0 || cleanup || (reindex && reindexedCount > 0) {
		colArrow.Print("-> ")
		colSuccess.Println("Updating remote index")

		var finalizedIndex []RepoEntry
		for _, k := range sortedKeys {
			finalizedIndex = append(finalizedIndex, newIndexMap[k])
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
			return a.Variant < b.Variant
		})

		indexBytes, err := json.MarshalIndent(finalizedIndex, "", "  ")
		if err != nil {
			return err
		}
		if err := r2.UploadFile(ctx, "repo-index.json", indexBytes); err != nil {
			return fmt.Errorf("failed to upload index: %w", err)
		}
		colSuccess.Printf("Sync complete. Updated index with %d new uploads.\n", uploadedCount)
	} else {
		colArrow.Print("-> ")
		colSuccess.Printf("Everything up to date.\n")
	}

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
