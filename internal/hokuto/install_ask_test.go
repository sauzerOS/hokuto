package hokuto

import (
	"os"
	"testing"
)

func TestConfirmInstallPlanWithAskDefaultsToNo(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
		_ = w.Close()
	})
	if _, err := w.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if confirmInstallPlanWithAsk([]string{"dependency", "target"}, nil) {
		t.Fatal("empty response should decline the install plan")
	}
}

func TestConfirmInstallPlanWithAskAcceptsYes(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = oldStdin
		_ = r.Close()
		_ = w.Close()
	})
	if _, err := w.WriteString("yes\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	metas := map[string]MetaPackage{"desktop": {Name: "desktop"}}
	if !confirmInstallPlanWithAsk([]string{"dependency", "target"}, metas) {
		t.Fatal("yes response should accept the install plan")
	}
}
