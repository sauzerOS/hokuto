package hokuto

import (
	"context"
	"testing"
)

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
