package hokuto

import (
	"reflect"
	"slices"
	"testing"
)

// hokuto-builder build gparted: the gtkmm3 binary installed for gparted
// needs glibmm-2.66, atkmm-2.28 and pangomm-2.46, which are not on the
// mirror and are built in the same run. gparted was built first.
func TestBuildPlanOrdersRuntimeDepsOfInstalledDependency(t *testing.T) {
	cfg, repo := withTempDependencyRepo(t)
	writeTestPackage(t, repo, "gparted", "gtkmm3\nglibc\n")
	writeTestPackage(t, repo, "gtkmm3", "atkmm==2.28*\n")
	writeTestPackage(t, repo, "glibmm-2.66", "glibc\n")
	writeTestPackage(t, repo, "atkmm-2.28", "glibmm-2.66\n")
	writeTestPackage(t, repo, "pangomm-2.46", "glibmm-2.66\n")
	writeInstalledDepends(t, "glibc", "")
	// Installed from the mirror as a build dependency, its own runtime
	// dependencies still missing.
	writeInstalledDepends(t, "gtkmm3", "atkmm-2.28\nglibc\nglibmm-2.66\npangomm-2.46\n")

	targets := []string{"gparted", "glibmm-2.66", "atkmm-2.28", "pangomm-2.46"}
	requested := map[string]bool{"gparted": true}
	plan, err := resolveBuildPlan(targets, requested, false, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	gparted := slices.Index(plan.Order, "gparted")
	for _, dep := range []string{"glibmm-2.66", "atkmm-2.28", "pangomm-2.46"} {
		if i := slices.Index(plan.Order, dep); i < 0 || i > gparted {
			t.Fatalf("order %v: %s must come before gparted", plan.Order, dep)
		}
	}
	// The parallel builder reads gparted's recipe only: it gets them as
	// prerequisites.
	if got, want := plan.ManualPrereqs["gparted"], []string{"atkmm-2.28", "glibmm-2.66", "pangomm-2.46"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prerequisites of gparted = %v, want %v", got, want)
	}
	pm := &ParallelManager{
		Config: cfg, BuildPlan: plan, Completed: map[string]bool{"glibmm-2.66": true},
		Pending: []string{"atkmm-2.28", "pangomm-2.46", "gparted"},
	}
	if pm.canBuild("gparted") {
		t.Fatal("gparted must wait for atkmm-2.28 and pangomm-2.46")
	}
	pm.Completed["atkmm-2.28"], pm.Completed["pangomm-2.46"] = true, true
	pm.Pending = []string{"gparted"}
	if !pm.canBuild("gparted") {
		t.Fatal("gparted can build once its prerequisites are built")
	}
}
