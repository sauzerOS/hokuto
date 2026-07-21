package hokuto

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyPackageRecipeMetadataIncludesSources(t *testing.T) {
	tmp := t.TempDir()
	pkgDir := filepath.Join(tmp, "pkg")
	installedDir := filepath.Join(tmp, "installed")

	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(installedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{
		"version": "1.0 1\n",
		"sources": "https://example.com/source.tar.xz\n",
		"build":   "#!/bin/sh\n",
		"options": "binary\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	execCtx := &Executor{Context: context.Background(), Stdout: io.Discard, Stderr: io.Discard}
	if err := copyPackageRecipeMetadata(pkgDir, installedDir, execCtx); err != nil {
		t.Fatal(err)
	}

	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(installedDir, name))
		if err != nil {
			t.Fatalf("expected %s to be copied: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("unexpected %s contents: got %q want %q", name, string(got), want)
		}
	}
}
