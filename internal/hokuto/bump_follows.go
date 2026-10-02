package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// bumpFollowsFile names, in a recipe, the package whose version it shares:
// linux-live builds the same kernel as linux. Bumping that package to a new
// version bumps the recipe to it too.
const bumpFollowsFile = "bump-follows"

// recipesFollowing returns the recipes, by name, whose bump-follows file
// names leader. The first repository in HOKUTO_PATH wins for a name.
func recipesFollowing(leader string) map[string]string {
	recipes := make(map[string]string)
	seen := make(map[string]bool)
	for _, repoPath := range filepath.SplitList(repoPaths) {
		repoPath = strings.TrimSpace(repoPath)
		if repoPath == "" {
			continue
		}
		entries, err := os.ReadDir(repoPath)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || seen[name] {
				continue
			}
			pkgDir := filepath.Join(repoPath, name)
			if info, err := os.Stat(filepath.Join(pkgDir, "version")); err != nil || info.IsDir() {
				continue
			}
			seen[name] = true
			data, err := os.ReadFile(filepath.Join(pkgDir, bumpFollowsFile))
			if err != nil {
				continue
			}
			for _, followed := range strings.Fields(string(data)) {
				if followed == leader && name != leader {
					recipes[name] = pkgDir
					break
				}
			}
		}
	}
	return recipes
}

// bumpFollowingRecipes bumps every recipe that follows leader to version,
// unless it is there already: a new revision of leader is its own change. It
// returns the directories of the recipes it bumped, each committed, nothing
// pushed.
func bumpFollowingRecipes(leader, version string) ([]string, error) {
	recipes := recipesFollowing(leader)
	names := make([]string, 0, len(recipes))
	for name := range recipes {
		names = append(names, name)
	}
	sort.Strings(names)

	var bumped []string
	for _, name := range names {
		pkgDir := recipes[name]
		data, err := os.ReadFile(filepath.Join(pkgDir, "version"))
		if err != nil {
			return bumped, fmt.Errorf("%s: could not read version file", name)
		}
		if fields := strings.Fields(string(data)); len(fields) > 0 && fields[0] == version {
			debugf("%s follows %s and is at %s already\n", name, leader, version)
			continue
		}
		colArrow.Print("-> ")
		colSuccess.Printf("%s follows %s\n", name, leader)
		dir, err := bumpPackage(name, "", version, "")
		if err != nil {
			return bumped, err
		}
		bumped = append(bumped, dir)
	}
	return bumped, nil
}
