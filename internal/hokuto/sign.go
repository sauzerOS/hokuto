package hokuto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// Embedded public key for hokuto package verification.
// This is used to verify official repositories.
const officialKeyID = "official"
const officialPublicKeyHex = "b30f07098a4f98ec90bb169bdd49324d5e22fc09eab79e368e6fafc63453f5f2"

// DefaultKeyDir is the path on the host system where keys are stored.
// It is a variable so it can be overwritten in tests.
var DefaultKeyDir = "/etc/hokuto/keys"

// detectMultilib checks if the staging directory contains multilib libraries
// (checks for /usr/lib32 or /lib32 directories)
func detectMultilib(stagingDir string) bool {
	lib32Paths := []string{
		filepath.Join(stagingDir, "usr/lib32"),
		filepath.Join(stagingDir, "lib32"),
		filepath.Join(stagingDir, "usr/lib/rustlib/i686-unknown-linux-gnu"),
		filepath.Join(stagingDir, "usr/i686-w64-mingw32"),
		filepath.Join(stagingDir, "usr/lib/gcc/i686-w64-mingw32"),
	}
	for _, path := range lib32Paths {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// WritePackageInfo generates the pkginfo metadata file.
func WritePackageInfo(stagingDir, pkgName, pkgVer, pkgRev, arch, cflags string, generic bool, multilib bool, execCtx *Executor) error {
	metadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	pkgInfoPath := filepath.Join(metadataDir, "pkginfo")

	// Create directory using native or executor
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(metadataDir, 0755); err != nil {
			return fmt.Errorf("failed to create metadata directory natively: %w", err)
		}
	} else if execCtx != nil && execCtx.ShouldRunAsRoot {
		mkdirCmd := exec.Command("mkdir", "-p", metadataDir)
		if err := execCtx.Run(mkdirCmd); err != nil {
			return fmt.Errorf("failed to create metadata directory: %w", err)
		}
		chmodCmd := exec.Command("chmod", "755", metadataDir)
		if err := execCtx.Run(chmodCmd); err != nil {
			return fmt.Errorf("failed to set metadata directory permissions: %w", err)
		}
	} else {
		if err := os.MkdirAll(metadataDir, 0755); err != nil {
			return fmt.Errorf("failed to create metadata directory: %w", err)
		}
	}

	var pkgInfo strings.Builder
	pkgInfo.WriteString(fmt.Sprintf("name=%s\n", pkgName))
	pkgInfo.WriteString(fmt.Sprintf("version=%s\n", pkgVer))
	pkgInfo.WriteString(fmt.Sprintf("revision=%s\n", pkgRev))
	pkgInfo.WriteString(fmt.Sprintf("arch=%s\n", arch))
	pkgInfo.WriteString(fmt.Sprintf("cflags=%s\n", cflags))
	if generic {
		pkgInfo.WriteString("generic=1\n")
	} else {
		pkgInfo.WriteString("generic=0\n")
	}
	if multilib {
		pkgInfo.WriteString("multilib=1\n")
	} else {
		pkgInfo.WriteString("multilib=0\n")
	}

	// Write file using executor if running as root is needed
	if execCtx != nil && execCtx.ShouldRunAsRoot {
		// Write to a temp file first, then move it using executor
		tmpFile, err := os.CreateTemp("", "hokuto-pkginfo-")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		if _, err := tmpFile.WriteString(pkgInfo.String()); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write pkginfo to temp file: %w", err)
		}
		tmpFile.Close()

		// Copy using native if root, else executor
		if os.Geteuid() == 0 {
			if err := copyFile(tmpPath, pkgInfoPath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write pkginfo natively: %w", err)
			}
			if err := os.Chmod(pkgInfoPath, 0644); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to set pkginfo permissions natively: %w", err)
			}
		} else {
			// Copy using executor
			cpCmd := exec.Command("cp", tmpPath, pkgInfoPath)
			if err := execCtx.Run(cpCmd); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write pkginfo: %w", err)
			}
			chmodCmd := exec.Command("chmod", "644", pkgInfoPath)
			if err := execCtx.Run(chmodCmd); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to set pkginfo permissions: %w", err)
			}
		}
		os.Remove(tmpPath)
	} else {
		if err := os.WriteFile(pkgInfoPath, []byte(pkgInfo.String()), 0644); err != nil {
			return fmt.Errorf("failed to write pkginfo: %w", err)
		}
	}
	return nil
}

// getPrivateKey loads the Ed25519 private key based on activeKeyID.
func getPrivateKey() (ed25519.PrivateKey, error) {
	keyPath := filepath.Join(DefaultKeyDir, activeKeyID+".key")
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		keyPath = filepath.Join(root, "etc", "hokuto", "keys", activeKeyID+".key")
	}

	// Handle the default case where officialKeyID refers to hokuto.key
	if activeKeyID == officialKeyID {
		keyPath = filepath.Join(DefaultKeyDir, "hokuto.key")
		if root := os.Getenv("HOKUTO_ROOT"); root != "" {
			keyPath = filepath.Join(root, "etc", "hokuto", "keys", "hokuto.key")
		}
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		// Try reading as root if permission denied
		if os.IsPermission(err) {
			keyData, err = readFileAsRoot(keyPath)
			if err != nil {
				return nil, fmt.Errorf("private key not found at %s", keyPath)
			}
		} else {
			return nil, fmt.Errorf("private key not found at %s", keyPath)
		}
	}

	var privateKey ed25519.PrivateKey
	trimmedKey := strings.TrimSpace(string(keyData))

	if len(trimmedKey) == 128 {
		// Likely hex encoded
		decoded, err := hex.DecodeString(trimmedKey)
		if err == nil && len(decoded) == 64 {
			privateKey = ed25519.PrivateKey(decoded)
		}
	}

	if privateKey == nil {
		if len(keyData) == 64 {
			privateKey = ed25519.PrivateKey(keyData)
		} else {
			return nil, fmt.Errorf("invalid private key format at %s (expected 64 bytes raw or 128 hex chars, got %d)", keyPath, len(trimmedKey))
		}
	}
	return privateKey, nil
}

// GenerateKeyPair generates a new Ed25519 key pair and saves it.
func GenerateKeyPair(id string, execCtx *Executor) error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	keyDir := DefaultKeyDir
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		keyDir = filepath.Join(root, "etc", "hokuto", "keys")
	}

	privPath := filepath.Join(keyDir, id+".key")
	pubPath := filepath.Join(keyDir, id+".pub")

	// Ensure directories exist with proper permissions (0755 so users can access)
	if os.Geteuid() == 0 {
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
	} else if execCtx != nil && execCtx.ShouldRunAsRoot {
		if err := execCtx.Run(exec.Command("mkdir", "-p", keyDir)); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
		// Ensure directory is accessible
		if err := execCtx.Run(exec.Command("chmod", "755", keyDir)); err != nil {
			return fmt.Errorf("failed to set key directory permissions: %w", err)
		}
	}

	// Write private key (hex encoded) - only root can read
	privHex := hex.EncodeToString(priv)
	if err := writeRootFile(privPath, []byte(privHex), 0600, execCtx); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Write public key (hex encoded) - world readable
	pubHex := hex.EncodeToString(pub)
	if err := writeRootFile(pubPath, []byte(pubHex), 0644, execCtx); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	return nil
}

// writeRootFile is a helper to write a file with root privileges if needed.
func writeRootFile(path string, data []byte, perm os.FileMode, execCtx *Executor) error {
	if os.Geteuid() == 0 {
		return os.WriteFile(path, data, perm)
	}

	tmp, err := os.CreateTemp("", "hokuto-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	if err := execCtx.Run(exec.Command("mv", tmpPath, path)); err != nil {
		return err
	}
	return execCtx.Run(exec.Command("chmod", fmt.Sprintf("%o", perm), path))
}

// getPublicKey retrieves an Ed25519 public key by ID.
func getPublicKey(id string) (ed25519.PublicKey, error) {
	if id == officialKeyID || id == "" {
		pubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
		return ed25519.PublicKey(pubKeyBytes), nil
	}

	// Look in /etc/hokuto/keys/
	keyPath := filepath.Join(DefaultKeyDir, id+".pub")
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		rootKeyPath := filepath.Join(root, "etc", "hokuto", "keys", id+".pub")
		if _, err := os.Stat(rootKeyPath); err == nil {
			keyPath = rootKeyPath
		} else if root != "/" {
			// Fallback to host key if not found in root (and root is not host)
			if _, err := os.Stat(keyPath); err != nil {
				// Both missing, error will be caught by ReadFile below
			} else {
				// Found in host, keep keyPath as is
			}
		}
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("public key '%s' not found in keyring (%s)", id, keyPath)
	}

	trimmedKey := strings.TrimSpace(string(keyData))
	if len(trimmedKey) == 64 {
		// Hex encoded
		decoded, err := hex.DecodeString(trimmedKey)
		if err == nil && len(decoded) == 32 {
			return ed25519.PublicKey(decoded), nil
		}
	}

	if len(keyData) == 32 {
		return ed25519.PublicKey(keyData), nil
	}

	// 3. Fallback to verified keyring
	// We need a way to pass cfg here... but getPublicKey is used in VerifyPackageSignature.
	// We might need to fetch the keyring once and cache it globally or pass cfg around.
	// For now, let's try to fetch it if we can.
	// Note: this is expensive if called for every package.
	// TODO: Cache keyring.
	return nil, fmt.Errorf("public key '%s' not found in local keyring (%s)", id, keyPath)
}

// GetPublicKeyVerified retrieves a public key, checking the remote signed keyring if not found locally.
func GetPublicKeyVerified(id string, cfg *Config) (ed25519.PublicKey, error) {
	pub, err := getPublicKey(id)
	if err == nil {
		return pub, nil
	}

	// Try remote keyring
	keyring, err := FetchKeyring(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch keyring for key %s: %w", id, err)
	}

	for _, entry := range keyring {
		if entry.ID == id {
			pubBytes, err := hex.DecodeString(entry.Pub)
			if err != nil {
				return nil, fmt.Errorf("invalid public key in keyring for %s: %w", id, err)
			}
			return ed25519.PublicKey(pubBytes), nil
		}
	}

	return nil, fmt.Errorf("public key '%s' not found in keyring", id)
}

// SignRepoIndex signs the repo-index.json data.
func SignRepoIndex(indexData []byte) ([]byte, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to sign repo index: %w", err)
	}

	signature := ed25519.Sign(privateKey, indexData)
	return []byte(hex.EncodeToString(signature)), nil
}

// SignData signs arbitrary data with a private key.
func SignData(data []byte, privateKey ed25519.PrivateKey) []byte {
	return ed25519.Sign(privateKey, data)
}

// VerifySignatureRaw verifies a raw signature against public key bytes.
func VerifySignatureRaw(data, sigHex, pubKeyBytes []byte) error {
	signature, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	publicKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(publicKey, data, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// PromptForMasterPrivateKey securely prompts the user for the master private key,
// but first checks if hokuto.key exists in the local keyring.
func PromptForMasterPrivateKey() (ed25519.PrivateKey, error) {
	keyPath := filepath.Join(DefaultKeyDir, "hokuto.key")
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		keyPath = filepath.Join(root, "etc", "hokuto", "keys", "hokuto.key")
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		debugf("Using master private key from %s\n", keyPath)
		trimmedKey := strings.TrimSpace(string(data))
		if len(trimmedKey) == 128 {
			decoded, err := hex.DecodeString(trimmedKey)
			if err == nil && len(decoded) == 64 {
				priv := ed25519.PrivateKey(decoded)
				pub := priv.Public().(ed25519.PublicKey)
				masterPubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
				if hex.EncodeToString(pub) == hex.EncodeToString(masterPubKeyBytes) {
					return priv, nil
				}
			}
		}
	}

	fmt.Print("Enter Master Private Key (hex): ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // New line after password entry
	if err != nil {
		return nil, err
	}

	trimmedKey := strings.TrimSpace(string(bytePassword))
	if len(trimmedKey) != 128 {
		return nil, fmt.Errorf("invalid master private key length (expected 128 hex chars, got %d)", len(trimmedKey))
	}

	decoded, err := hex.DecodeString(trimmedKey)
	if err != nil || len(decoded) != 64 {
		return nil, fmt.Errorf("invalid master private key format: %w", err)
	}

	// Verify it matches the hardcoded master public key
	priv := ed25519.PrivateKey(decoded)
	pub := priv.Public().(ed25519.PublicKey)
	masterPubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)

	if hex.EncodeToString(pub) != hex.EncodeToString(masterPubKeyBytes) {
		return nil, errors.New("provided private key does not match the hardcoded master public key")
	}

	return priv, nil
}

// VerifyRepoIndexSignature verifies the repo-index.json signature.
func VerifyRepoIndexSignature(indexData, sigHex []byte, cfg *Config) error {
	signature, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil {
		return fmt.Errorf("invalid repo index signature format: %w", err)
	}

	// 1. Try master key first
	masterPubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
	masterPublicKey := ed25519.PublicKey(masterPubKeyBytes)

	if ed25519.Verify(masterPublicKey, indexData, signature) {
		return nil
	}

	// 2. Try keys from the keyring
	keyring, err := FetchKeyring(cfg)
	if err == nil {
		for _, entry := range keyring {
			if entry.ID == officialKeyID {
				continue
			}
			pubBytes, err := hex.DecodeString(entry.Pub)
			if err != nil {
				continue
			}
			publicKey := ed25519.PublicKey(pubBytes)
			if ed25519.Verify(publicKey, indexData, signature) {
				debugf("Repo index verified using trusted key: %s\n", entry.ID)

				// Automatically install this key locally if it doesn't exist
				keyDir := DefaultKeyDir
				if root := os.Getenv("HOKUTO_ROOT"); root != "" {
					keyDir = filepath.Join(root, "etc", "hokuto", "keys")
				}
				pubPath := filepath.Join(keyDir, entry.ID+".pub")
				if _, statErr := os.Stat(pubPath); os.IsNotExist(statErr) {
					// Key doesn't exist locally, install it
					if writeErr := writeRootFile(pubPath, []byte(entry.Pub), 0644, RootExec); writeErr != nil {
						debugf("Warning: failed to auto-install key %s: %v\n", entry.ID, writeErr)
					} else {
						colArrow.Print("-> ")
						colSuccess.Printf("Auto-installed public key from remote keyring: %s\n", entry.ID)
					}
				}

				return nil
			}
		}
	} else {
		debugf("Warning: could not fetch keyring for extended verification: %v\n", err)
	}

	// 3. Try local keys (both chroot and host)
	// We scan for *.pub files in both locations and try them.
	localKeyDirs := []string{}

	// Default/Host keys
	localKeyDirs = append(localKeyDirs, DefaultKeyDir)

	// Chroot keys (prioritized if exists)
	if root := os.Getenv("HOKUTO_ROOT"); root != "" {
		chrootKeys := filepath.Join(root, "etc", "hokuto", "keys")
		// Prepend to check chroot first
		localKeyDirs = append([]string{chrootKeys}, localKeyDirs...)
	}

	processedKeys := make(map[string]bool)

	for _, keyDir := range localKeyDirs {
		files, err := filepath.Glob(filepath.Join(keyDir, "*.pub"))
		if err != nil {
			continue
		}

		for _, file := range files {
			// Read key
			keyData, err := os.ReadFile(file)
			if err != nil {
				continue
			}

			// Clean and decode
			trimmedKey := strings.TrimSpace(string(keyData))
			var pubKeyBytes []byte
			if len(trimmedKey) == 64 {
				pubKeyBytes, err = hex.DecodeString(trimmedKey)
				if err != nil {
					continue
				}
			} else if len(keyData) == 32 {
				pubKeyBytes = keyData
			} else {
				continue
			}

			// Deduplicate checks (same key content might be in multiple files or both dirs)
			keyHex := hex.EncodeToString(pubKeyBytes)
			if processedKeys[keyHex] {
				continue
			}
			processedKeys[keyHex] = true

			publicKey := ed25519.PublicKey(pubKeyBytes)
			if ed25519.Verify(publicKey, indexData, signature) {
				id := strings.TrimSuffix(filepath.Base(file), ".pub")
				debugf("Repo index verified using local key: %s (%s)\n", id, file)
				return nil
			}
		}
	}

	return errors.New("REPO INDEX SIGNATURE VERIFICATION FAILED: the remote index has been tampered with or is from an unknown source")
}

// SignPackage signs a package manifest and metadata.
func SignPackage(stagingDir, pkgName string, execCtx *Executor, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	metadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	manifestPath := filepath.Join(metadataDir, "manifest")
	pkgInfoPath := filepath.Join(metadataDir, "pkginfo")
	signaturePath := filepath.Join(metadataDir, "signature")

	// 1. Read manifest and pkginfo for signing
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest for signing: %w", err)
	}

	pkgInfoData, err := os.ReadFile(pkgInfoPath)
	if err != nil {
		return fmt.Errorf("failed to read pkginfo for signing: %w", err)
	}

	// Data to sign: manifest + pkginfo
	dataToSign := append(manifestData, pkgInfoData...)

	// 3. Load private key
	privateKey, err := getPrivateKey()
	if err != nil {
		// If key doesn't exist, we just skip signing
		debugf("Signing skipped: %v\n", err)
		return nil
	}

	// 4. Sign
	signature := ed25519.Sign(privateKey, dataToSign)

	// 5. Use global Key ID
	keyID := activeKeyID

	// 6. Write signature [keyid]:sig
	signatureData := []byte(fmt.Sprintf("%s:%s", keyID, hex.EncodeToString(signature)))
	if execCtx != nil && execCtx.ShouldRunAsRoot {
		// Write to a temp file first, then copy it using executor
		tmpFile, err := os.CreateTemp("", "hokuto-signature-")
		if err != nil {
			return fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		if _, err := tmpFile.Write(signatureData); err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("failed to write signature to temp file: %w", err)
		}
		tmpFile.Close()

		// Copy using native if root, else executor
		if os.Geteuid() == 0 {
			if err := copyFile(tmpPath, signaturePath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write signature natively: %w", err)
			}
			if err := os.Chmod(signaturePath, 0644); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to set signature permissions natively: %w", err)
			}
		} else {
			// Copy using executor
			cpCmd := exec.Command("cp", tmpPath, signaturePath)
			if err := execCtx.Run(cpCmd); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write signature: %w", err)
			}
			chmodCmd := exec.Command("chmod", "644", signaturePath)
			if err := execCtx.Run(chmodCmd); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to set signature permissions: %w", err)
			}
		}
		os.Remove(tmpPath)
	} else {
		if err := os.WriteFile(signaturePath, signatureData, 0644); err != nil {
			return fmt.Errorf("failed to write signature: %w", err)
		}
	}

	fmt.Fprint(logger, colArrow.Sprint("-> "))
	fmt.Fprintf(logger, "%s", colSuccess.Sprintf("Package %s signed successfully\n", pkgName))

	return nil
}

// VerifyPackageSignature verifies the package signature in the staging directory.
func VerifyPackageSignature(stagingDir, pkgName string, cfg *Config, execCtx *Executor, logger io.Writer) error {
	if logger == nil {
		logger = os.Stdout
	}
	// If verification is disabled, skip everything
	if !VerifySignature {
		debugf("Skipping signature verification for %s (disabled)\n", pkgName)
		return nil
	}

	metadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	manifestPath := filepath.Join(metadataDir, "manifest")
	pkgInfoPath := filepath.Join(metadataDir, "pkginfo")
	signaturePath := filepath.Join(metadataDir, "signature")

	// Check if signature exists
	if _, err := os.Stat(signaturePath); os.IsNotExist(err) {
		// If verification is enforced, this is an error
		if VerifySignature {
			return fmt.Errorf("MISSING SIGNATURE: package %s is not signed and signature verification is enforced", pkgName)
		}
		debugf("Warning: package %s is not signed, skipping verification\n", pkgName)
		return nil
	}

	// 1. Read signature and extract Key ID
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		if os.IsPermission(err) {
			sigData, err = readFileAsRoot(signaturePath)
			if err != nil {
				return fmt.Errorf("failed to read signature (privileged): %w", err)
			}
		} else {
			return fmt.Errorf("failed to read signature: %w", err)
		}
	}

	rawSig := strings.TrimSpace(string(sigData))
	keyID := officialKeyID
	sigHex := rawSig

	if strings.Contains(rawSig, ":") {
		parts := strings.SplitN(rawSig, ":", 2)
		keyID = parts[0]
		sigHex = parts[1]
	}

	signature, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// 2. Read manifest and pkginfo
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsPermission(err) {
			manifestData, err = readFileAsRoot(manifestPath)
			if err != nil {
				return fmt.Errorf("failed to read manifest for verification (privileged): %w", err)
			}
		} else {
			return fmt.Errorf("failed to read manifest for verification: %w", err)
		}
	}
	pkgInfoData, err := os.ReadFile(pkgInfoPath)
	if err != nil {
		if os.IsPermission(err) {
			pkgInfoData, err = readFileAsRoot(pkgInfoPath)
			if err != nil {
				return fmt.Errorf("failed to read pkginfo for verification (privileged): %w", err)
			}
		} else {
			return fmt.Errorf("failed to read pkginfo for verification: %w", err)
		}
	}

	dataToVerify := append(manifestData, pkgInfoData...)

	// 3. Verify against identified key
	publicKey, err := GetPublicKeyVerified(keyID, cfg)
	if err != nil {
		return fmt.Errorf("signature verification aborted: %v", err)
	}

	if ed25519.Verify(publicKey, dataToVerify, signature) {
		fmt.Fprint(logger, colArrow.Sprint("-> "))
		fmt.Fprintf(logger, "%s", colSuccess.Sprintf("Package %s signature OK\n", pkgName))

		// 4. Verify integrity of all files against the signed manifest
		if err := VerifyPackageIntegrity(stagingDir, pkgName, manifestPath, execCtx); err != nil {
			return err
		}

		return nil
	}

	// 5. Optional: check for user-provided public keys in /etc/hokuto/keys/
	// (Implementation of multiple trusted keys can go here later if needed)

	return fmt.Errorf("SIGNATURE VERIFICATION FAILED: package %s has an invalid signature", pkgName)
}

// VerifyPackageIntegrity checks all files in staging against the BLAKE3 checksums in the manifest.
func VerifyPackageIntegrity(stagingDir, pkgName, manifestPath string, execCtx *Executor) error {
	entries, err := parseManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to parse verified manifest: %w", err)
	}

	var filesToVerify []string
	expectedChecksums := make(map[string]string)

	metadataPrefix := filepath.Join("var", "db", "hokuto", "installed")

	for relPath, entry := range entries {
		// Clean the path to handle leading slashes
		cleanRel := strings.TrimPrefix(relPath, "/")

		// Skip directories (indicated by trailing slash in path or manifest format)
		if strings.HasSuffix(relPath, "/") {
			continue
		}
		// Skip symlinks (recorded with "000000" checksum)
		if entry.Checksum == "000000" {
			continue
		}
		// Skip metadata files (manifest, pkginfo, signature, etc.)
		// They are verified by the Ed25519 signature itself.
		if strings.HasPrefix(cleanRel, metadataPrefix) {
			continue
		}

		absPath := filepath.Join(stagingDir, cleanRel)
		filesToVerify = append(filesToVerify, absPath)
		expectedChecksums[absPath] = entry.Checksum
	}

	if len(filesToVerify) == 0 {
		return nil
	}

	debugf("Verifying integrity of %d files for %s\n", len(filesToVerify), pkgName)

	// Use parallel checksum computation
	computedChecksums, err := ComputeChecksums(filesToVerify, execCtx)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	// Compare checksums
	var mismatches []string
	for _, absPath := range filesToVerify {
		if computedChecksums[absPath] != expectedChecksums[absPath] {
			rel, _ := filepath.Rel(stagingDir, absPath)
			mismatches = append(mismatches, rel)
		}
	}

	if len(mismatches) > 0 {
		return errors.New(colError.Sprintf(
			"INTEGRITY CHECK FAILED: the following files in package %s have been tampered with: %s",
			pkgName, strings.Join(mismatches, ", "),
		))
	}

	debugf("Integrity check passed for %s\n", pkgName)
	return nil
}
