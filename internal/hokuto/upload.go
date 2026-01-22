package hokuto

import (
	"context"
	"encoding/json"
	"flag"
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
	uploadCmd := flag.NewFlagSet("upload", flag.ContinueOnError)
	var cleanup = uploadCmd.Bool("cleanup", false, "Prompt to remove older versions on remote")
	var reindex = uploadCmd.Bool("reindex", false, "Regenerate the remote index by scanning the bucket")
	var sync = uploadCmd.Bool("sync", false, "Upload all local files missing on remote without prompt")
	var prompt = uploadCmd.Bool("prompt", false, "Prompt for confirmation for each local file missing on remote")
	var deletePkg = uploadCmd.String("delete", "", "Delete all variants of a package from remote")

	// Set output to stderr to avoid polluting stdout if captured
	uploadCmd.SetOutput(os.Stderr)

	if len(args) == 0 {
		fmt.Println("Usage: hk upload [options]")
		fmt.Println("")
		fmt.Println("Options:")
		uploadCmd.PrintDefaults()
		return nil
	}

	if err := uploadCmd.Parse(args); err != nil {
		// flag.ContinueOnError means parsing failed (e.g. unknown flag).
		// usage is accepted printed by Parse().
		return nil // Return nil to just "do nothing" as requested
	}

	// Usage check if not deleting
	if *deletePkg == "" && !*sync && !*prompt && !*cleanup && !*reindex {
		fmt.Println("Usage: hk upload [options]")
		fmt.Println("")
		fmt.Println("Options:")
		uploadCmd.PrintDefaults()
		return nil
	}

	// 2. Initialize R2 Client
	if cfg.Values["R2_ACCESS_KEY_ID"] == "" || cfg.Values["R2_SECRET_ACCESS_KEY"] == "" {
		return fmt.Errorf("R2 credentials (R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY) are missing. Upload requires authentication")
	}

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
	// (Skip if we are just cleaning up or reindexing and no sync/prompt requested, but reindexing needs scans?
	// The original logic scanned first. Let's keep it to support syncing.)
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

	// Handle --delete logic explicitly
	var deletionsOccurred bool
	if *deletePkg != "" {
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

	var reindexedCount int
	if *reindex {
		colArrow.Print("-> ")
		colSuccess.Println("Re-indexing: Scanning all objects on R2")
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
				key := fmt.Sprintf("%s-%s-%s", existing.Name, existing.Arch, existing.Variant)
				reconciledMap[key] = existing
				continue
			}

			// 2. Check if we have it locally
			if local, ok := localByFilename[obj.Key]; ok && local.Size == obj.Size {
				key := fmt.Sprintf("%s-%s-%s", local.Name, local.Arch, local.Variant)
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

			key := fmt.Sprintf("%s-%s-%s", entry.Name, entry.Arch, entry.Variant)
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
			if !*sync && !*prompt {
				// If neither --sync nor --prompt is used, we only upload if we have an explicit reason
				// but based on user request, hk upload without args shows help.
				// So if we are here, some other flag like --cleanup or --reindex was used.
				// In that case, we should probably SKIP uploads unless asked.
				continue
			}

			colArrow.Print("-> ")
			if *prompt {
				reasonText := ""
				if !exists {
					reasonText = " (remote missing)"
				} else if isNewer(local, remote) {
					reasonText = fmt.Sprintf(" (newer: %s-%s vs %s-%s)", local.Version, local.Revision, remote.Version, remote.Revision)
				} else if local.B3Sum != remote.B3Sum {
					reasonText = " (checksum mismatch)"
				}

				if !askForConfirmation(colWarn, "Upload %s %s-%s (%s, %s)%s? ", local.Name, local.Version, local.Revision, local.Arch, local.Variant, reasonText) {
					continue
				}
			}

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
	if *cleanup {
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
	if uploadedCount > 0 || *cleanup || (*reindex && reindexedCount > 0) || deletionsOccurred {
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
