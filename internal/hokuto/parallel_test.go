package hokuto

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParallelUpdateDoesNotPromoteRequestedPackageToWorld(t *testing.T) {
	oldWorldFile := WorldFile
	WorldFile = filepath.Join(t.TempDir(), "world")
	t.Cleanup(func() { WorldFile = oldWorldFile })

	pm := &ParallelManager{UserRequested: map[string]bool{"vlc-plugin-foo": true}}
	pm.recordRequestedWorldPackage("vlc-plugin-foo")
	if data, err := os.ReadFile(WorldFile); err == nil && strings.TrimSpace(string(data)) != "" {
		t.Fatalf("update policy must preserve world membership, got %q", data)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	pm.AddRequestedToWorld = true
	pm.recordRequestedWorldPackage("vlc-plugin-foo")
	data, err := os.ReadFile(WorldFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "vlc-plugin-foo" {
		t.Fatalf("normal build/install policy should record requested package, got %q", data)
	}
}

func TestRunParallelBuildsClearsPromptHooksAfterUILoop(t *testing.T) {
	oldUserExec := UserExec
	oldRootExec := RootExec
	oldStartHook := promptStartHook
	oldEndHook := promptEndHook
	t.Cleanup(func() {
		UserExec = oldUserExec
		RootExec = oldRootExec
		SetPromptHooks(oldStartHook, oldEndHook)
	})

	UserExec = &Executor{Context: context.Background()}
	RootExec = &Executor{Context: context.Background()}

	temporaryInstalls, err := RunParallelBuilds(
		&BuildPlan{},
		&Config{Values: map[string]string{}},
		2,
		nil,
		true,
		false,
		false,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("empty parallel build should complete: %v", err)
	}
	if len(temporaryInstalls) != 0 {
		t.Fatalf("empty parallel build should not report temporary installs, got %v", temporaryInstalls)
	}
	if promptStartHook != nil || promptEndHook != nil {
		t.Fatal("parallel build should clear prompt hooks after stopping the UI loop")
	}
}
