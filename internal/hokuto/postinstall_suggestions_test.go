package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledOnlyForPostInstall(t *testing.T) {
	oldInstalled, oldWorld, oldWorldMake := Installed, WorldFile, WorldMakeFile
	dir := t.TempDir()
	Installed = filepath.Join(dir, "installed")
	WorldFile = filepath.Join(dir, "world")
	WorldMakeFile = filepath.Join(dir, "world_make")
	t.Cleanup(func() { Installed, WorldFile, WorldMakeFile = oldInstalled, oldWorld, oldWorldMake })

	pkg := func(name, depends string) {
		d := filepath.Join(Installed, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if depends != "" {
			if err := os.WriteFile(filepath.Join(d, "depends"), []byte(depends), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	pkg("dracut", "")
	pkg("linux", "kmod\ndracut post-install\n")
	pkg("linux-cachyos", "dracut post-install\nbtrfs-progs post-install\n")
	pkg("btrfs-progs", "")
	pkg("mkinitcpio-user", "dracut\n")
	pkg("plymouth", "")

	if installedOnlyForPostInstall("dracut") {
		t.Error("dracut with a normal runtime dependent must keep its suggestions")
	}
	os.RemoveAll(filepath.Join(Installed, "mkinitcpio-user"))
	if !installedOnlyForPostInstall("dracut") {
		t.Error("dracut needed only for post-install hooks should not prompt suggestions")
	}
	if err := os.WriteFile(WorldFile, []byte("dracut\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if installedOnlyForPostInstall("dracut") {
		t.Error("an explicitly installed package (in world) keeps its suggestions")
	}
	if installedOnlyForPostInstall("plymouth") {
		t.Error("a package nothing depends on is not post-install-only")
	}
}
