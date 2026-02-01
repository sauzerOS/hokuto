package hokuto

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// KeyringEntry represents a trusted public key in the index.
type KeyringEntry struct {
	ID  string `json:"id"`
	Pub string `json:"pub"` // Hex encoded Ed25519 public key
}

// FetchKeyring downloads and verifies the remote keyring.
func FetchKeyring(cfg *Config) ([]KeyringEntry, error) {
	// Try to use a cached keyring if available and not too old?
	// For now, always fetch to ensure we have the latest trusted keys.

	var keyringData []byte
	var sigData []byte
	var fetchErr error

	// 1. Try BinaryMirror First (Public URL)
	if BinaryMirror != "" {
		tmpDir := os.TempDir()
		keyringPath := filepath.Join(tmpDir, "keyring.json")
		sigPath := filepath.Join(tmpDir, "keyring.json.sig")

		// Best effort cleanup
		defer os.Remove(keyringPath)
		defer os.Remove(sigPath)

		keyringURL := fmt.Sprintf("%s/keyring.json", BinaryMirror)
		sigURL := fmt.Sprintf("%s/keyring.json.sig", BinaryMirror)

		// Download keyring
		if err := downloadFileQuiet(keyringURL, keyringURL, keyringPath); err == nil {
			// Download signature
			if err := downloadFileQuiet(sigURL, sigURL, sigPath); err == nil {
				// Both succeeded
				keyringData, err = os.ReadFile(keyringPath)
				if err == nil {
					sigData, err = os.ReadFile(sigPath)
					if err == nil {
						// Success!
					} else {
						fetchErr = fmt.Errorf("failed to read downloaded signature: %w", err)
						keyringData = nil // Invalidate
					}
				} else {
					fetchErr = fmt.Errorf("failed to read downloaded keyring: %w", err)
				}
			} else {
				fetchErr = fmt.Errorf("failed to fetch keyring signature from mirror: %w", err)
			}
		} else {
			fetchErr = fmt.Errorf("failed to fetch keyring from mirror: %w", err)
		}
	}

	// 2. Fallback to R2 if Mirror failed
	if keyringData == nil {
		r2, err := NewR2Client(cfg)
		if err == nil {
			ctx := context.Background()
			keyringData, err = r2.DownloadFile(ctx, "keyring.json")
			if err == nil {
				sigData, err = r2.DownloadFile(ctx, "keyring.json.sig")
				if err != nil {
					// We have keyring but no signature from R2.
					keyringData = nil
					fetchErr = fmt.Errorf("R2 keyring found but signature missing: %w", err)
				}
			} else {
				fetchErr = fmt.Errorf("failed to fetch keyring from R2 (and mirror failed: %v): %w", fetchErr, err)
			}
		} else {
			// R2 client creation failed (likely no creds), and mirror failed
			if fetchErr == nil {
				fetchErr = fmt.Errorf("mirror not configured and R2 client init failed: %w", err)
			}
		}
	}

	if keyringData == nil {
		return nil, fmt.Errorf("failed to download keyring: %w", fetchErr)
	}

	// Verify keyring signature using the hardcoded master key
	masterPubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
	if err := VerifySignatureRaw(keyringData, sigData, masterPubKeyBytes); err != nil {
		return nil, fmt.Errorf("keyring integrity check failed: %w", err)
	}

	var keyring []KeyringEntry
	if err := json.Unmarshal(keyringData, &keyring); err != nil {
		return nil, fmt.Errorf("failed to parse keyring: %w", err)
	}

	return keyring, nil
}

// SyncKeyring synchronizes keys bidirectionally:
// - Downloads remote keyring and installs missing keys locally
// - Uploads local keys to update the remote keyring
func SyncKeyring(ctx context.Context, cfg *Config) error {
	r2, err := NewR2Client(cfg)
	if err != nil {
		return err
	}

	keyDir := DefaultKeyDir
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		keyDir = filepath.Join(root, "etc", "hokuto", "keys")
	}

	// 1. Download remote keyring (if it exists)
	colArrow.Print("-> ")
	colSuccess.Println("Fetching remote keyring...")
	remoteKeyring, err := FetchKeyring(cfg)
	if err != nil {
		colWarn.Printf("Warning: could not fetch remote keyring: %v\n", err)
		colWarn.Println("Will create new keyring from local keys only")
		remoteKeyring = []KeyringEntry{}
	}

	// 2. Install remote keys locally if they don't exist
	installedCount := 0
	for _, entry := range remoteKeyring {
		// Skip the official key (it's hardcoded)
		if entry.ID == officialKeyID {
			continue
		}

		pubPath := filepath.Join(keyDir, entry.ID+".pub")
		if _, err := os.Stat(pubPath); os.IsNotExist(err) {
			// Key doesn't exist locally, install it
			if err := writeRootFile(pubPath, []byte(entry.Pub), 0644, RootExec); err != nil {
				colWarn.Printf("Warning: failed to install key %s: %v\n", entry.ID, err)
				continue
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Installed public key: %s\n", entry.ID)
			installedCount++
		}
	}

	if installedCount > 0 {
		colSuccess.Printf("Installed %d new public key(s) from remote\n", installedCount)
	}

	// 3. Scan local /etc/hokuto/keys/ for .pub files
	files, err := filepath.Glob(filepath.Join(keyDir, "*.pub"))
	if err != nil {
		return fmt.Errorf("failed to scan for local keys: %w", err)
	}

	// 4. Build merged keyring (start with official key)
	mergedKeyring := []KeyringEntry{
		{ID: officialKeyID, Pub: officialPublicKeyHex},
	}

	foundIDs := make(map[string]bool)
	foundIDs[officialKeyID] = true

	// Add all local keys
	for _, file := range files {
		id := strings.TrimSuffix(filepath.Base(file), ".pub")
		if foundIDs[id] {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			colWarn.Printf("Warning: failed to read public key %s: %v\n", file, err)
			continue
		}

		pubHex := strings.TrimSpace(string(data))
		// Validate hex
		if len(pubHex) != 64 {
			colWarn.Printf("Warning: skipping invalid public key %s (expected 64 hex chars)\n", file)
			continue
		}
		if _, err := hex.DecodeString(pubHex); err != nil {
			colWarn.Printf("Warning: skipping invalid public key %s (invalid hex)\n", file)
			continue
		}

		mergedKeyring = append(mergedKeyring, KeyringEntry{ID: id, Pub: pubHex})
		foundIDs[id] = true
	}

	// Sort for consistency
	sort.Slice(mergedKeyring, func(i, j int) bool {
		return mergedKeyring[i].ID < mergedKeyring[j].ID
	})

	keyringBytes, err := json.MarshalIndent(mergedKeyring, "", "  ")
	if err != nil {
		return err
	}

	// 5. Prompt for master private key
	colArrow.Print("-> ")
	colNote.Println("Master private key required to sign keyring")
	masterPriv, err := PromptForMasterPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to get master private key: %w", err)
	}

	// 6. Sign the merged keyring
	sig := SignData(keyringBytes, masterPriv)
	sigHex := hex.EncodeToString(sig)

	// 7. Upload
	colArrow.Print("-> ")
	colSuccess.Println("Uploading updated keyring and signature to remote")
	if err := r2.UploadFile(ctx, "keyring.json", keyringBytes); err != nil {
		return fmt.Errorf("failed to upload keyring: %w", err)
	}
	if err := r2.UploadFile(ctx, "keyring.json.sig", []byte(sigHex)); err != nil {
		return fmt.Errorf("failed to upload keyring signature: %w", err)
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Keyring synchronized successfully with %d total keys\n", len(mergedKeyring))
	return nil
}
