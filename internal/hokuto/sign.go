package hokuto

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Embedded public key for hokuto package verification.
// This is used to verify official repositories.
const officialPublicKeyHex = "b30f07098a4f98ec90bb169bdd49324d5e22fc09eab79e368e6fafc63453f5f2"

// detectMultilib checks if the staging directory contains multilib libraries
// (checks for /usr/lib32 or /lib32 directories)
func detectMultilib(stagingDir string) bool {
	lib32Paths := []string{
		filepath.Join(stagingDir, "usr/lib32"),
		filepath.Join(stagingDir, "lib32"),
		filepath.Join(stagingDir, "usr/lib/rustlib/i686-unknown-linux-gnu"),
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

	// Create directory using executor if running as root is needed
	if execCtx != nil && execCtx.ShouldRunAsRoot {
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
		os.Remove(tmpPath)
	} else {
		if err := os.WriteFile(pkgInfoPath, []byte(pkgInfo.String()), 0644); err != nil {
			return fmt.Errorf("failed to write pkginfo: %w", err)
		}
	}
	return nil
}

// getPrivateKey loads the Ed25519 private key from standard locations.
func getPrivateKey() (ed25519.PrivateKey, error) {
	keyPath := "/etc/hokuto/hokuto.key"
	if val, ok := os.LookupEnv("HOKUTO_SIGNING_KEY"); ok {
		keyPath = val
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("private key not found at %s", keyPath)
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

// SignRepoIndex signs the repo-index.json data.
func SignRepoIndex(indexData []byte) ([]byte, error) {
	privateKey, err := getPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to sign repo index: %w", err)
	}

	signature := ed25519.Sign(privateKey, indexData)
	return []byte(hex.EncodeToString(signature)), nil
}

// VerifyRepoIndexSignature verifies the repo-index.json signature.
func VerifyRepoIndexSignature(indexData, sigHex []byte) error {
	signature, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil {
		return fmt.Errorf("invalid repo index signature format: %w", err)
	}

	pubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
	publicKey := ed25519.PublicKey(pubKeyBytes)

	if !ed25519.Verify(publicKey, indexData, signature) {
		return errors.New("REPO INDEX SIGNATURE VERIFICATION FAILED: the remote index has been tampered with or is from an untrusted source")
	}

	return nil
}

// SignPackage signs a package manifest and metadata.
func SignPackage(stagingDir, pkgName string, execCtx *Executor) error {
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

	// 5. Write signature
	signatureData := []byte(hex.EncodeToString(signature))
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
		os.Remove(tmpPath)
	} else {
		if err := os.WriteFile(signaturePath, signatureData, 0644); err != nil {
			return fmt.Errorf("failed to write signature: %w", err)
		}
	}

	colArrow.Print("-> ")
	colSuccess.Printf("Package %s signed successfully\n", pkgName)

	return nil
}

// VerifyPackageSignature verifies the package signature in the staging directory.
func VerifyPackageSignature(stagingDir, pkgName string, execCtx *Executor) error {
	metadataDir := filepath.Join(stagingDir, "var", "db", "hokuto", "installed", pkgName)
	manifestPath := filepath.Join(metadataDir, "manifest")
	pkgInfoPath := filepath.Join(metadataDir, "pkginfo")
	signaturePath := filepath.Join(metadataDir, "signature")

	// Check if signature exists
	if _, err := os.Stat(signaturePath); os.IsNotExist(err) {
		// If verification is enforced, this is an error
		if os.Getenv("HOKUTO_VERIFY_SIGNATURE") != "0" {
			return fmt.Errorf("MISSING SIGNATURE: package %s is not signed and signature verification is enforced", pkgName)
		}
		debugf("Warning: package %s is not signed, skipping verification\n", pkgName)
		return nil
	}

	// 1. Read signature
	sigHex, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}
	signature, err := hex.DecodeString(strings.TrimSpace(string(sigHex)))
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// 2. Read manifest and pkginfo
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest for verification: %w", err)
	}
	pkgInfoData, err := os.ReadFile(pkgInfoPath)
	if err != nil {
		return fmt.Errorf("failed to read pkginfo for verification: %w", err)
	}

	dataToVerify := append(manifestData, pkgInfoData...)

	// 3. Verify against official key
	pubKeyBytes, _ := hex.DecodeString(officialPublicKeyHex)
	publicKey := ed25519.PublicKey(pubKeyBytes)

	if ed25519.Verify(publicKey, dataToVerify, signature) {
		colArrow.Print("-> ")
		colSuccess.Printf("Package ")
		colNote.Printf("%s", pkgName)
		colSuccess.Printf(" signature OK\n")

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
