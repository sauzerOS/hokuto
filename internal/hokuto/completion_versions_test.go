package hokuto

import (
	"reflect"
	"testing"
)

func TestRemoteInstallCompletionVersions(t *testing.T) {
	cfg, _ := withTempDependencyRepo(t)
	cfg.Values["HOKUTO_ARCH"] = "x86_64"
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	entry := func(version, arch, variant string) RepoEntry {
		return RepoEntry{Name: "java-openjdk-jre", Version: version, Revision: "1", Arch: arch, Variant: variant}
	}
	withTestRemoteIndex(t, []RepoEntry{
		entry("17.0.20+7", "x86_64", "optimized"),
		entry("26.0.1+8", "x86_64", "optimized"),
		entry("26.0.1+8", "x86_64", "generic"), // same version, another variant
		entry("21.0.12+7", "x86_64", "optimized"),
		entry("99.0.0", "aarch64", "generic"), // not this architecture
		{Name: "other", Version: "1.0", Revision: "1", Arch: "x86_64", Variant: "optimized"},
	})

	got := remoteInstallCompletionVersions(cfg, "java-openjdk-jre")
	if want := []string{"26.0.1+8", "21.0.12+7", "17.0.20+7"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("versions = %v, want %v", got, want)
	}
	// The second call reads the cache written by the first.
	if again := remoteInstallCompletionVersions(cfg, "java-openjdk-jre"); !reflect.DeepEqual(again, got) {
		t.Fatalf("from the cache: %v", again)
	}
}
