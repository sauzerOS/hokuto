package hokuto

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAlternativeTempPatternsMatchNativeAndGNUConventions(t *testing.T) {
	goPattern, mktempTemplate := alternativeTempPatterns("/usr/bin/java")
	if goPattern != ".java.hokuto-alt-*" {
		t.Fatalf("unexpected os.MkdirTemp pattern: %q", goPattern)
	}
	if mktempTemplate != ".java.hokuto-alt-XXXXXX" {
		t.Fatalf("unexpected GNU mktemp template: %q", mktempTemplate)
	}
	if !strings.HasSuffix(filepath.Join("/usr/bin", mktempTemplate), "XXX") {
		t.Fatalf("GNU mktemp template must end in at least three X characters: %q", mktempTemplate)
	}
}

func TestCreateAlternativeTempDirUsesNativePattern(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "java")
	dir, err := createAlternativeTempDir(target, &Executor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeAlternativeTempDir(dir, &Executor{}) })
	if filepath.Dir(dir) != parent {
		t.Fatalf("temporary directory escaped target parent: %q", dir)
	}
	if !strings.HasPrefix(filepath.Base(dir), ".java.hokuto-alt-") {
		t.Fatalf("unexpected temporary directory name: %q", dir)
	}
}
