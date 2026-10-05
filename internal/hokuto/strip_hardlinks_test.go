package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUniqueFilesByInodeStripsHardLinksOnce(t *testing.T) {
	dir := t.TempDir()
	ld := filepath.Join(dir, "usr", "bin", "aarch64-linux-gnu-ld")
	tooldirLd := filepath.Join(dir, "usr", "aarch64-linux-gnu", "bin", "ld")
	as := filepath.Join(dir, "usr", "bin", "aarch64-linux-gnu-as")
	for _, d := range []string{filepath.Dir(ld), filepath.Dir(tooldirLd)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{ld, as} {
		if err := os.WriteFile(f, []byte("elf"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(ld, tooldirLd); err != nil {
		t.Fatal(err)
	}
	got := uniqueFilesByInode([]string{ld, tooldirLd, as, ""})
	if want := []string{ld, as}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestRemoveStripLeftoversOnlyNewOnes(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ld")
	shipped := filepath.Join(dir, "stAbc123") // a real file that happens to match
	for _, f := range []string{bin, shipped} {
		if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	watch := snapshotStripTempNames([]string{bin})
	leftover := filepath.Join(dir, "stWa4lig")
	if err := os.WriteFile(leftover, []byte("tmp"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeStripLeftovers(watch, &Executor{Context: context.Background()})
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("strip's leftover should be removed: %v", err)
	}
	for _, f := range []string{bin, shipped} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s must stay: %v", f, err)
		}
	}
}
