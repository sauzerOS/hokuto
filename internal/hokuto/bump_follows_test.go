package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFollowsRecipe(t *testing.T, repo, name, version, follows string) string {
	t.Helper()
	dir := filepath.Join(repo, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "version"), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if follows != "" {
		if err := os.WriteFile(filepath.Join(dir, bumpFollowsFile), []byte(follows), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRecipesFollowing(t *testing.T) {
	oldRepoPaths := repoPaths
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	core := filepath.Join(t.TempDir(), "core")
	extra := filepath.Join(t.TempDir(), "extra")
	writeFollowsRecipe(t, core, "linux", "7.2.8 2", "")
	live := writeFollowsRecipe(t, extra, "linux-live", "7.2.8 1", "linux\n")
	writeFollowsRecipe(t, extra, "linux-cachyos", "7.2.0 1", "")
	writeFollowsRecipe(t, extra, "other", "1.0 1", "glibc linux-headers")
	// A recipe found first in an earlier repository shadows a later one.
	writeFollowsRecipe(t, core, "shadowed", "1.0 1", "")
	writeFollowsRecipe(t, extra, "shadowed", "1.0 1", "linux")
	repoPaths = core + ":" + extra

	if got, want := recipesFollowing("linux"), map[string]string{"linux-live": live}; !reflect.DeepEqual(got, want) {
		t.Fatalf("recipesFollowing(linux) = %v, want %v", got, want)
	}
	if got := recipesFollowing("linux-live"); len(got) != 0 {
		t.Fatalf("recipesFollowing(linux-live) = %v, want none", got)
	}
}

func TestBumpFollowingRecipesSkipsSameVersion(t *testing.T) {
	oldRepoPaths := repoPaths
	t.Cleanup(func() { repoPaths = oldRepoPaths })

	extra := filepath.Join(t.TempDir(), "extra")
	live := writeFollowsRecipe(t, extra, "linux-live", "7.2.8 3", "linux\n")
	repoPaths = extra

	// linux got a new revision of the same version: linux-live is not bumped.
	bumped, err := bumpFollowingRecipes("linux", "7.2.8")
	if err != nil || len(bumped) != 0 {
		t.Fatalf("bumpFollowingRecipes = %v, %v; want nothing bumped", bumped, err)
	}
	data, err := os.ReadFile(filepath.Join(live, "version"))
	if err != nil || string(data) != "7.2.8 3\n" {
		t.Fatalf("linux-live version = %q, %v; want it unchanged", data, err)
	}
}
