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

	r2, err := NewR2Client(cfg)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	keyringData, err := r2.DownloadFile(ctx, "keyring.json")
	if err != nil {
		// If keyring doesn't exist, return empty or just the master key?
		// The master key is hardcoded, so we always have it.
		return nil, fmt.Errorf("failed to download keyring: %w", err)
	}

	sigData, err := r2.DownloadFile(ctx, "keyring.json.sig")
	if err != nil {
		return nil, fmt.Errorf("keyring signature missing: %w", err)
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

// SyncKeyring scans local keys, updates the keyring, and uploads it.
func SyncKeyring(ctx context.Context, cfg *Config) error {
	r2, err := NewR2Client(cfg)
	if err != nil {
		return err
	}

	// 1. Scan local /etc/hokuto/keys/ for .pub files
	keyDir := "/etc/hokuto/keys"
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		keyDir = filepath.Join(root, "etc", "hokuto", "keys")
	}

	files, err := filepath.Glob(filepath.Join(keyDir, "*.pub"))
	if err != nil {
		return fmt.Errorf("failed to scan for local keys: %w", err)
	}

	newKeyring := []KeyringEntry{
		{ID: officialKeyID, Pub: officialPublicKeyHex},
	}

	foundIDs := make(map[string]bool)
	foundIDs[officialKeyID] = true

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

		newKeyring = append(newKeyring, KeyringEntry{ID: id, Pub: pubHex})
		foundIDs[id] = true
	}

	// Sort for consistency
	sort.Slice(newKeyring, func(i, j int) bool {
		return newKeyring[i].ID < newKeyring[j].ID
	})

	keyringBytes, err := json.MarshalIndent(newKeyring, "", "  ")
	if err != nil {
		return err
	}

	// 2. Prompt for master private key
	masterPriv, err := PromptForMasterPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to get master private key: %w", err)
	}

	// 3. Sign the new keyring
	sig := SignData(keyringBytes, masterPriv)
	sigHex := hex.EncodeToString(sig)

	// 4. Upload
	colArrow.Print("-> ")
	colSuccess.Println("Uploading updated keyring and signature")
	if err := r2.UploadFile(ctx, "keyring.json", keyringBytes); err != nil {
		return fmt.Errorf("failed to upload keyring: %w", err)
	}
	if err := r2.UploadFile(ctx, "keyring.json.sig", []byte(sigHex)); err != nil {
		return fmt.Errorf("failed to upload keyring signature: %w", err)
	}

	colSuccess.Printf("Keyring updated successfully with %d keys.\n", len(newKeyring))
	return nil
}
