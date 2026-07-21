package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeChecksumUsesInternalBlake3(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "file with spaces and \\ backslash")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}

	const want = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
	got, err := ComputeChecksum(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("unexpected checksum: got %s want %s", got, want)
	}
	if got := hashString("abc"); got != want {
		t.Fatalf("unexpected string checksum: got %s want %s", got, want)
	}
}
