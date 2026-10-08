package hokuto

import (
	"os"
	"testing"
)

// TestMain keeps the tests off the machine's own configuration: a
// /etc/hokuto/hokuto.prefer naming rust would change which alternative
// dependency the resolver tests get. Tests that need the file set their own.
func TestMain(m *testing.M) {
	PreferFile = "/nonexistent/hokuto-test/hokuto.prefer"
	os.Exit(m.Run())
}
