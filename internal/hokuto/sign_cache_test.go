package hokuto

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateKeyIsReadOnce(t *testing.T) {
	oldDir := DefaultKeyDir
	DefaultKeyDir = t.TempDir()
	t.Setenv("HOKUTO_ROOT", "")
	forgetPrivateKeys()
	t.Cleanup(func() {
		DefaultKeyDir = oldDir
		forgetPrivateKeys()
	})

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := privateKeyPath()
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRepoIndex([]byte("index")); err != nil {
		t.Fatal(err)
	}

	// An upload reads the key when it starts; signing at its end must not
	// need the file again (reading it as root fails once interrupted).
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	sig, err := SignRepoIndex([]byte("index"))
	if err != nil {
		t.Fatalf("the key read earlier must still sign: %v", err)
	}
	raw, _ := hex.DecodeString(string(sig))
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte("index"), raw) {
		t.Fatal("signature does not verify")
	}

	forgetPrivateKeys()
	if _, err := SignRepoIndex([]byte("index")); err == nil {
		t.Fatal("a forgotten key must be read again")
	}
}
