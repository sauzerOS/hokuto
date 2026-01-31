package hokuto

// Code in this file was split out of main.go for readability.
// No behavior changes intended.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// interactiveMu ensures only one interactive prompt reads stdin at a time.
// This prevents background goroutines from hanging invisibly while waiting for input.
var interactiveMu sync.Mutex

// Hooks for UI coordination (e.g., pausing TUI updates during prompts)
var (
	promptStartHook func()
	promptEndHook   func()
)

// SetPromptHooks registers callbacks to be executed before and after an interactive prompt.
// These are useful for pausing/resuming background UI updates.
func SetPromptHooks(onStart, onEnd func()) {
	promptStartHook = onStart
	promptEndHook = onEnd
}

func askForConfirmation(p colorPrinter, format string, a ...any) bool {
	interactiveMu.Lock()
	defer interactiveMu.Unlock()

	if promptStartHook != nil {
		promptStartHook()
	}
	if promptEndHook != nil {
		defer promptEndHook()
	}

	reader := bufio.NewReader(os.Stdin)
	// First, create the main part of the prompt using the provided arguments.
	mainPrompt := fmt.Sprintf(format, a...)
	for {
		// Use our existing cPrintf helper to print the prompt with the desired color.
		// We print mainPrompt and the suffix separately to ensure the suffix keeps
		// the color 'p' even if mainPrompt contains internal color resets (like colNote).
		cPrintf(p, "%s", mainPrompt)
		cPrintf(p, " [Y/n]: ")

		response, err := reader.ReadString('\n')

		if err != nil {
			return false // On error (like Ctrl+D), default to "no"
		}
		response = strings.ToLower(strings.TrimSpace(response))

		if response == "y" || response == "yes" || response == "" {
			return true
		}
		if response == "n" || response == "no" {
			return false
		}
		cPrintln(colWarn, "Invalid input.")
	}
}

// WithPrompt executes a function within the prompt hooks (pausing UI).
// It also acquires the interactive lock.
func WithPrompt(fn func()) {
	interactiveMu.Lock()
	defer interactiveMu.Unlock()

	if promptStartHook != nil {
		promptStartHook()
	}
	if promptEndHook != nil {
		defer promptEndHook()
	}

	fn()
}
