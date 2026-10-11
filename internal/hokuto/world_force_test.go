package hokuto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForcedReinstallKeepsDependenciesOutOfWorld(t *testing.T) {
	withTempDependencyRepo(t)
	root := t.TempDir()
	oldInstalled, oldWorld := Installed, WorldFile
	Installed = filepath.Join(root, "installed")
	WorldFile = filepath.Join(root, "world")
	t.Cleanup(func() { Installed, WorldFile = oldInstalled, oldWorld })

	writeInstalledTestPackage(t, "btrfs-progs")         // chosen by the user
	writeInstalledTestPackage(t, "python-pycryptodome") // a dependency of streamlink
	if err := os.WriteFile(WorldFile, []byte("btrfs-progs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requested := map[string]bool{"btrfs-progs": true, "python-pycryptodome": true, "libnvme": true}

	keep := forcedReinstallDependencies(requested, true)
	if !keep["python-pycryptodome"] {
		t.Fatal("a reinstalled dependency must stay out of world")
	}
	if keep["btrfs-progs"] || keep["libnvme"] {
		t.Fatalf("a world package, and one not installed yet, are the user's choice: %v", keep)
	}
	if len(forcedReinstallDependencies(requested, false)) != 0 {
		t.Fatal("without --force nothing changes")
	}
}
