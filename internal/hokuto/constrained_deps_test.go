package hokuto

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func glewIndex() []RepoEntry {
	e := func(version, variant string) RepoEntry {
		return RepoEntry{Name: "glew", Version: version, Revision: "1", Arch: "x86_64", Variant: variant,
			Filename:        "glew-" + version + "-1-x86_64-" + variant + ".tar.zst",
			MetadataVersion: repoEntryMetadataVersion, InstalledSize: 1}
	}
	return []RepoEntry{e("2.2.0", "optimized"), e("2.3.1", "optimized"), e("2.3.1", "generic"), e("1.13.0", "optimized")}
}

func TestPinnedReleaseFor(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	index := glewIndex()
	cases := []struct {
		name, op, version string
		want              string
		ok                bool
	}{
		// rpcs3: the current 2.3.1 does not satisfy it, 2.2.0 does.
		{"glew", "<", "2.3", "glew-2@2.2.0-1", true},
		{"glew", "<=", "2.2.0", "glew-2@2.2.0-1", true},
		{"glew", "<", "2", "glew-1@1.13.0-1", true},
		// The current release satisfies it: resolved as usual.
		{"glew", ">=", "2.0", "", false},
		{"glew", "", "", "", false},
		// Nothing on the mirror satisfies it.
		{"glew", "<", "1.0", "", false},
		// A parallel name recorded with a constraint, and without one.
		{"glew-2", "<", "2.3", "glew-2@2.2.0-1", true},
		{"glew-1", "", "", "glew-1@1.13.0-1", true},
		// glew-2 alone means the newest 2.x, the current release.
		{"glew-2", "", "", "glew", true},
		// A line longer than the major one keeps its own parallel name,
		// from a ==2.2* constraint or a recorded glew-2.2.
		{"glew", "==", "2.2*", "glew-2.2@2.2.0-1", true},
		{"glew-2.2", "", "", "glew-2.2@2.2.0-1", true},
		// ==2.3* is met by the current release.
		{"glew", "==", "2.3*", "", false},
	}
	for _, c := range cases {
		got, ok := pinnedReleaseFor(c.name, c.op, c.version, cfg, index)
		if got != c.want || ok != c.ok {
			t.Errorf("pinnedReleaseFor(%s %s %s) = %q, %v; want %q, %v", c.name, c.op, c.version, got, ok, c.want, c.ok)
		}
	}
	if got := pinnedInstallName("glew-2@2.2.0-1", cfg); got != "glew-2" {
		t.Errorf("install name = %q, want glew-2", got)
	}
}

func TestInstallPlanPinsConstrainedDependency(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	rpcs3 := RepoEntry{Name: "rpcs3", Version: "0.0.43", Revision: "2", Arch: "x86_64", Variant: "optimized",
		Depends: []string{"glew<2.3"}, MetadataVersion: repoEntryMetadataVersion, InstalledSize: 1}
	index := append(glewIndex(), rpcs3)
	withTestRemoteIndex(t, index)

	var plan []string
	if err := resolveBinaryDependencies("rpcs3", map[string]bool{}, &plan, false, true, cfg, index, true); err != nil {
		t.Fatal(err)
	}
	if want := []string{"glew-2@2.2.0-1", "rpcs3"}; !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %v, want %v", plan, want)
	}

	// The pinned release is found under its own archive name and installed
	// under its parallel one, without downloading anything to decide that.
	b, ok, err := locateBinaryPackageTarball("glew-2@2.2.0-1", cfg, false)
	if err != nil || !ok {
		t.Fatalf("locate: ok=%v err=%v", ok, err)
	}
	if b.name != "glew-2" || b.entry == nil || b.entry.Version != "2.2.0" ||
		filepath.Base(b.path) != "glew-2.2.0-1-x86_64-optimized.tar.zst" {
		t.Fatalf("located %+v (entry %+v)", b, b.entry)
	}

	// Once glew-2 2.2.0 is installed the constraint is met.
	writeInstalledTestPackage(t, "glew-2")
	if err := os.WriteFile(filepath.Join(Installed, "glew-2", "version"), []byte("2.2.0 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan = nil
	if err := resolveBinaryDependencies("rpcs3", map[string]bool{}, &plan, false, true, cfg, index, true); err != nil {
		t.Fatal(err)
	}
	if want := []string{"rpcs3"}; !reflect.DeepEqual(plan, want) {
		t.Fatalf("with glew-2 installed: plan = %v, want %v", plan, want)
	}
}

func TestUninstallSeesConstrainedDependent(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	root := t.TempDir()
	cfg.Values["HOKUTO_ROOT"] = root
	dbRoot := filepath.Join(root, "var", "db", "hokuto", "installed")
	for name, files := range map[string]map[string]string{
		"rpcs3":  {"depends": "glew<2.3\n", "version": "0.0.43 2\n"},
		"glew-2": {"version": "2.2.0 1\n"},
		"glew":   {"version": "2.3.1 1\n"},
	} {
		dir := filepath.Join(dbRoot, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for f, content := range files {
			if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// rpcs3 needs the glew-2 that meets glew<2.3, not the current glew.
	if got := installedDependents("glew-2", cfg, nil); strings.Join(got, ",") != "rpcs3" {
		t.Errorf("dependents of glew-2 = %v, want [rpcs3]", got)
	}
	if got := installedDependents("glew", cfg, nil); len(got) != 0 {
		t.Errorf("dependents of glew = %v, want none", got)
	}
}

func TestReleasesNeededByDependentsKeepsOlderReleases(t *testing.T) {
	entry := func(name, version, variant string, deps ...string) RepoEntry {
		return RepoEntry{Name: name, Version: version, Revision: "1", Arch: "x86_64", Variant: variant,
			Filename: name + "-" + version + "-1-x86_64-" + variant + ".tar.zst", Depends: deps}
	}
	index := []RepoEntry{
		entry("glew", "2.2.0", "optimized"), entry("glew", "2.3.1", "optimized"),
		entry("glew", "2.1.0", "optimized"),
		entry("rpcs3", "0.0.43", "optimized", "glew<2.3"),
		entry("libsigc++", "2.12.2", "optimized"), entry("libsigc++", "3.8.1", "optimized"),
		entry("gparted", "1.8", "optimized", "libsigc++-2", "glibc"),
		entry("tk", "9.0.3", "optimized", "tcl>=9.0.0"), entry("tcl", "9.0.3", "optimized"),
	}
	got := releasesNeededByDependents(index)
	for _, want := range []string{"glew-2.2.0-1-x86_64-optimized.tar.zst", "libsigc++-2.12.2-1-x86_64-optimized.tar.zst",
		"tcl-9.0.3-1-x86_64-optimized.tar.zst"} {
		if !got[want] {
			t.Errorf("%s should be kept; kept %v", want, got)
		}
	}
	// Only the newest release meeting the constraint.
	if got["glew-2.1.0-1-x86_64-optimized.tar.zst"] {
		t.Error("glew 2.1.0 is not needed: 2.2.0 meets glew<2.3")
	}
}

func TestPinnedReleaseForUsesLocalCache(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	// The mirror has only tcl 9; tcl 8 was built here from git history.
	index := []RepoEntry{{Name: "tcl", Version: "9.0.3", Revision: "1", Arch: "x86_64", Variant: "optimized"}}
	cached := filepath.Join(BinDir, "tcl-8.6.16-1-x86_64-optimized.tar.zst")
	writeTestBinaryTarball(t, cached, "tcl", "8.6.16", "1")
	if got, ok := pinnedReleaseFor("tcl", "<", "9.0", cfg, index); !ok || got != "tcl-8@8.6.16-1" {
		t.Fatalf("pinnedReleaseFor(tcl<9.0) = %q, %v; want tcl-8@8.6.16-1", got, ok)
	}
	b, ok, err := locateBinaryPackageTarball("tcl-8@8.6.16-1", cfg, true)
	if err != nil || !ok || b.path != cached || b.name != "tcl-8" || b.entry != nil {
		t.Fatalf("locate from the cache: %+v ok=%v err=%v", b, ok, err)
	}
}

func TestDottedParallelNamesInstallUnderTheirLine(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	e := func(name, version string, deps ...string) RepoEntry {
		return RepoEntry{Name: name, Version: version, Revision: "1", Arch: "x86_64", Variant: "optimized",
			Filename: name + "-" + version + "-1-x86_64-optimized.tar.zst", Depends: deps,
			MetadataVersion: repoEntryMetadataVersion, InstalledSize: 1}
	}
	// gparted as published records the bare parallel name; a rebuilt gtkmm3
	// records the wildcard constraint. Both need atkmm 2.28, the current is 2.36.
	index := []RepoEntry{
		e("atkmm", "2.36.4"), e("atkmm", "2.28.4"),
		e("gparted", "1.8", "atkmm-2.28"), e("gtkmm3", "3.24.10", "atkmm==2.28*"),
	}
	withTestRemoteIndex(t, index)

	for _, app := range []string{"gparted", "gtkmm3"} {
		var plan []string
		if err := resolveBinaryDependencies(app, map[string]bool{}, &plan, false, true, cfg, index, true); err != nil {
			t.Fatal(err)
		}
		if want := []string{"atkmm-2.28@2.28.4-1", app}; !reflect.DeepEqual(plan, want) {
			t.Fatalf("%s: plan = %v, want %v", app, plan, want)
		}
	}

	// The install loop: archive under the package's own name, installed
	// under the line's parallel name.
	if got := canonicalParallelPackageName("atkmm-2.28"); got != "atkmm" {
		t.Fatalf("archive name of atkmm-2.28 = %q, want atkmm", got)
	}
	if got := parallelInstallPackageName("atkmm-2.28", "2.28.4", cfg); got != "atkmm-2.28" {
		t.Fatalf("install name = %q, want atkmm-2.28", got)
	}
	b, ok, err := locateBinaryPackageTarball("atkmm-2.28@2.28.4-1", cfg, false)
	if err != nil || !ok || b.name != "atkmm-2.28" || filepath.Base(b.path) != "atkmm-2.28.4-1-x86_64-optimized.tar.zst" {
		t.Fatalf("locate: %+v ok=%v err=%v", b, ok, err)
	}
	// A cached archive is found under the package's own name too.
	cached := filepath.Join(BinDir, "atkmm-2.28.4-1-x86_64-optimized.tar.zst")
	writeTestBinaryTarball(t, cached, "atkmm", "2.28.4", "1")
	if path, version, revision, ok := findCachedRequestedBinaryTarball("atkmm-2.28@2.28.4-1", cfg); !ok || path != cached || version != "2.28.4" || revision != "1" {
		t.Fatalf("cached lookup: %q %q %q %v", path, version, revision, ok)
	}

	// Installed as atkmm-2.28, it meets both forms.
	writeInstalledTestPackage(t, "atkmm-2.28")
	if err := os.WriteFile(filepath.Join(Installed, "atkmm-2.28", "version"), []byte("2.28.4 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"gparted", "gtkmm3"} {
		var plan []string
		if err := resolveBinaryDependencies(app, map[string]bool{}, &plan, false, true, cfg, index, true); err != nil {
			t.Fatal(err)
		}
		if want := []string{app}; !reflect.DeepEqual(plan, want) {
			t.Fatalf("%s with atkmm-2.28 installed: plan = %v", app, plan)
		}
	}
}
