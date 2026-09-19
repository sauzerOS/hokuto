package hokuto

import (
	"io"
	"os"
	"strings"
	"testing"
)

// Debug mode is inherited by child processes through HOKUTO_DEBUG, and the
// __zstd-frames filter that tar drives through --use-compress-program hands tar
// the package archive on stdout. Anything debugf writes there is spliced into
// the tarball, which then fails to decompress. debugf must use stderr.
func TestDebugfWritesToStderrNotStdout(t *testing.T) {
	prev := Debug
	Debug = true
	t.Cleanup(func() { Debug = prev })

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	debugf("marker %d\n", 42)
	os.Stdout, os.Stderr = oldOut, oldErr
	outW.Close()
	errW.Close()

	gotOut, _ := io.ReadAll(outR)
	gotErr, _ := io.ReadAll(errR)

	if len(gotOut) != 0 {
		t.Fatalf("debugf wrote %q to stdout; that corrupts any child whose stdout is a data stream", gotOut)
	}
	if !strings.Contains(string(gotErr), "marker 42") {
		t.Fatalf("debugf output missing from stderr, got %q", gotErr)
	}
}
