package hokuto

import (
	"testing"
	"time"
)

func TestFormatBuildElapsedWholeMinutes(t *testing.T) {
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{
		{0, "0 min"},
		{59 * time.Second, "0 min"},
		{61 * time.Second, "1 min"},
		{2*time.Hour + 5*time.Minute + 30*time.Second, "125 min"},
	} {
		if got := formatBuildElapsed(time.Now().Add(-c.ago)); got != c.want {
			t.Errorf("%v ago: got %q, want %q", c.ago, got, c.want)
		}
	}
	if got := formatBuildElapsed(time.Time{}); got != "0 min" {
		t.Errorf("unset start: %q", got)
	}
}
