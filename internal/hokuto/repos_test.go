package hokuto

import "testing"

func TestParseLFSPointer(t *testing.T) {
	ptr, ok := parseLFSPointer([]byte("version https://git-lfs.github.com/spec/v1\noid sha256:0123456789abcdef\nsize 42\n"))
	if !ok {
		t.Fatal("expected valid LFS pointer")
	}
	if ptr.OID != "0123456789abcdef" || ptr.Size != 42 {
		t.Fatalf("unexpected pointer: %+v", ptr)
	}
}

func TestParseLFSPointerRejectsMissingSize(t *testing.T) {
	if _, ok := parseLFSPointer([]byte("version https://git-lfs.github.com/spec/v1\noid sha256:0123456789abcdef\n")); ok {
		t.Fatal("expected pointer without size to be rejected")
	}
}
