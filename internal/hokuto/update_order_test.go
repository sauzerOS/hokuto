package hokuto

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOrderByUpdateChains(t *testing.T) {
	cases := []struct {
		name   string
		in     []string
		chains [][]string
		want   []string
	}{
		{
			name:   "unrelated packages in between",
			in:     []string{"vulkan-tools", "foo", "vulkan-loader", "bar", "vulkan-headers"},
			chains: [][]string{{"vulkan-headers", "vulkan-loader", "vulkan-tools"}},
			want:   []string{"foo", "bar", "vulkan-headers", "vulkan-loader", "vulkan-tools"},
		},
		{
			name:   "alphabetical input, chains from hokuto.update",
			in:     []string{"aurorae", "breeze", "kdecoration", "libksysguard", "plasma-desktop", "plasma-workspace", "powerdevil"},
			chains: [][]string{{"kdecoration", "aurorae", "breeze"}, {"libksysguard", "plasma-workspace", "powerdevil", "plasma-desktop"}},
			want:   []string{"kdecoration", "aurorae", "breeze", "libksysguard", "plasma-workspace", "powerdevil", "plasma-desktop"},
		},
		{
			name:   "chain member not being bumped",
			in:     []string{"c", "a"},
			chains: [][]string{{"a", "b", "c"}},
			want:   []string{"a", "c"},
		},
		{
			name:   "no chain applies",
			in:     []string{"b", "a"},
			chains: [][]string{{"x", "y"}},
			want:   []string{"b", "a"},
		},
		{
			name:   "contradictory chains keep input order for the rest",
			in:     []string{"a", "b", "c"},
			chains: [][]string{{"a", "b"}, {"b", "a"}},
			want:   []string{"c", "a", "b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := orderByUpdateChains(tc.in, tc.chains, nil); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOrderAutoBumpCandidatesUsesPkgsetMembers(t *testing.T) {
	candidates := []AutoBumpCandidate{
		{PkgName: "kde-frameworks", IsPkgSet: true},
		{PkgName: "mesa"},
		{PkgName: "zz-app"},
	}
	sets := map[string][]string{"kde-frameworks": {"ki18n", "kio"}}
	// zz-app must follow kio, which only this run bumps as part of the set.
	chains := [][]string{{"kio", "zz-app"}, {"zz-app", "mesa"}}
	var got []string
	for _, c := range orderAutoBumpCandidates(candidates, sets, chains) {
		got = append(got, c.PkgName)
	}
	if want := []string{"kde-frameworks", "zz-app", "mesa"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLoadUpdateOrderChains(t *testing.T) {
	root := t.TempDir()
	old := rootDir
	rootDir = root
	t.Cleanup(func() { rootDir = old })
	if err := os.MkdirAll(filepath.Join(root, "etc", "hokuto"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := "# comment\n\nmesa\nvulkan-headers  vulkan-loader vulkan-tools\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "hokuto", "hokuto.update"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	chains := loadUpdateOrderChains()
	if len(chains) != 1 || !slices.Equal(chains[0], []string{"vulkan-headers", "vulkan-loader", "vulkan-tools"}) {
		t.Errorf("unexpected chains %v", chains)
	}
}

// withUpdateOrderRepo creates recipes with the given depends files and makes
// them the only repository. A value of nil creates no recipe at all.
func withUpdateOrderRepo(t *testing.T, recipes map[string]map[string]string) {
	t.Helper()
	repo := t.TempDir()
	old := repoPaths
	repoPaths = repo
	t.Cleanup(func() { repoPaths = old })
	for name, files := range recipes {
		dir := filepath.Join(repo, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, data := range files {
			path := filepath.Join(dir, file)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "version"), []byte("1.0 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrderUpdatePlanNeverBuildsBeforeADependency(t *testing.T) {
	withUpdateOrderRepo(t, map[string]map[string]string{
		"a":              {},
		"b":              {},
		"y":              {"depends": "b make\n"},
		"libsplit":       {"split/lib32-libsplit/depends": "\n"},
		"uses-split":     {"depends": "lib32-libsplit\n"},
		"vulkan-headers": {},
		"vulkan-loader":  {"depends": "vulkan-headers make\n"},
		"vulkan-tools":   {"depends": "vulkan-loader\n"},
		"foo":            {},
		"bar":            {},
		"dep":            {},
		"user":           {"depends": "dep\n"},
	})

	cases := []struct {
		name   string
		in     []string
		chains [][]string
		want   []string
	}{
		{
			// A naive chain sort would build y before its dependency b.
			name:   "chain delays a package something depends on",
			in:     []string{"b", "y", "a"},
			chains: [][]string{{"a", "b"}},
			want:   []string{"a", "b", "y"},
		},
		{
			name:   "chain contradicting a dependency is dropped",
			in:     []string{"dep", "user"},
			chains: [][]string{{"user", "dep"}},
			want:   []string{"dep", "user"},
		},
		{
			name:   "dependency on a split output of a listed recipe",
			in:     []string{"libsplit", "uses-split", "a"},
			chains: [][]string{{"a", "libsplit"}},
			want:   []string{"a", "libsplit", "uses-split"},
		},
		{
			name:   "unrelated packages between chain members",
			in:     []string{"foo", "vulkan-headers", "bar", "vulkan-loader", "vulkan-tools"},
			chains: [][]string{{"vulkan-headers", "vulkan-loader", "vulkan-tools"}},
			want:   []string{"foo", "vulkan-headers", "bar", "vulkan-loader", "vulkan-tools"},
		},
		{
			name:   "chain reorders independent packages",
			in:     []string{"b", "a", "foo"},
			chains: [][]string{{"a", "b"}},
			want:   []string{"a", "b", "foo"},
		},
		{
			// no-recipe cannot be analysed, so nothing may cross it.
			name:   "package without a recipe stays pinned",
			in:     []string{"b", "no-recipe", "a"},
			chains: [][]string{{"a", "b"}},
			want:   []string{"b", "no-recipe", "a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := orderUpdatePlan(tc.in, tc.chains); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyUpdateOrderUsesDependencySafeOrdering(t *testing.T) {
	withUpdateOrderRepo(t, map[string]map[string]string{
		"vulkan-headers": {}, "vulkan-loader": {}, "vulkan-tools": {}, "foo": {}, "bar": {},
	})
	root := t.TempDir()
	old := rootDir
	rootDir = root
	t.Cleanup(func() { rootDir = old })
	if err := os.MkdirAll(filepath.Join(root, "etc", "hokuto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "hokuto", "hokuto.update"), []byte("vulkan-headers vulkan-loader vulkan-tools\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The old priority sort returned this list unchanged.
	got, prereqs := applyUpdateOrder([]string{"vulkan-tools", "foo", "vulkan-loader", "bar", "vulkan-headers"})
	if want := []string{"foo", "bar", "vulkan-headers", "vulkan-loader", "vulkan-tools"}; !slices.Equal(got, want) {
		t.Errorf("order: got %v, want %v", got, want)
	}
	// Parallel prerequisites are generated exactly as before.
	if !slices.Equal(prereqs["vulkan-loader"], []string{"vulkan-headers"}) || !slices.Equal(prereqs["vulkan-tools"], []string{"vulkan-loader"}) {
		t.Errorf("unexpected prerequisites %v", prereqs)
	}
}
