package hokuto

import (
	"strings"
	"testing"
)

func TestGitCommandAbortsStalledTransfers(t *testing.T) {
	cmd := gitCommand("pull")
	got := strings.Join(cmd.Args, " ")
	if !strings.HasPrefix(got, "git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 pull") {
		t.Fatalf("git command lacks the stall limits: %s", got)
	}

	// What git prints when the limits abort a transfer (curl error 28).
	stalled := "fatal: unable to access 'https://github.com/sauzerOS/kde/': Operation too slow. Less than 1000 bytes/sec transferred the last 60 seconds"
	if !gitTransferStalled(stalled) {
		t.Fatal("a transfer aborted by the stall limits must be recognised for a retry")
	}
	if gitTransferStalled("fatal: Authentication failed for 'https://github.com/x/y/'") {
		t.Fatal("other git errors must not be retried as stalls")
	}
}
