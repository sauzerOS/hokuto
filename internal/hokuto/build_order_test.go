package hokuto

import (
	"reflect"
	"testing"
)

// The build list keeps the command-line order (it decides cycles such as
// gdk-pixbuf <-> librsvg) and is the same on every run.
func TestOrderedBuildListKeepsRequestedOrder(t *testing.T) {
	toBuild := map[string]bool{"zlib": true, "librsvg": true, "gdk-pixbuf": true, "aarch64-glib": true}
	want := []string{"gdk-pixbuf", "librsvg", "aarch64-glib", "zlib"}
	for i := 0; i < 20; i++ {
		got := orderedBuildList(toBuild, []string{"gdk-pixbuf", "notbuilt", "librsvg", "gdk-pixbuf"})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("orderedBuildList = %v, want %v", got, want)
		}
	}
}
