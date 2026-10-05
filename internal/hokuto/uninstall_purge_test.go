package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPurgeOrphansOnlyWhatTheRemovalOrphans(t *testing.T) {
	withTempDependencyRepo(t)
	oldWorld, oldWorldMake := WorldFile, WorldMakeFile
	dir := t.TempDir()
	WorldFile = filepath.Join(dir, "world")
	WorldMakeFile = filepath.Join(dir, "world_make")
	t.Cleanup(func() { WorldFile, WorldMakeFile = oldWorld, oldWorldMake })

	if err := os.WriteFile(WorldFile, []byte("mpv\neditor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WorldMakeFile, []byte("meson\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// mpv needs ffmpeg (which needs x265), libass, and meson, a persistent
	// make dependency. The editor needs libass too. stale was already an
	// orphan and needs x265.
	writeInstalledDepends(t, "mpv", "ffmpeg\nlibass\nmeson\n")
	writeInstalledDepends(t, "ffmpeg", "x265\nlame\n")
	writeInstalledDepends(t, "x265", "")
	writeInstalledDepends(t, "lame", "")
	writeInstalledDepends(t, "libass", "")
	writeInstalledDepends(t, "meson", "")
	writeInstalledDepends(t, "editor", "libass\n")
	writeInstalledDepends(t, "stale", "x265\n")

	got, err := purgeOrphans(map[string]bool{"mpv": true})
	if err != nil {
		t.Fatal(err)
	}
	// ffmpeg and lame go. libass is the editor's, meson is kept on
	// purpose, stale predates the removal, and x265 is what stale needs.
	if want := []string{"ffmpeg", "lame"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("purge orphans = %v, want %v", got, want)
	}
}
