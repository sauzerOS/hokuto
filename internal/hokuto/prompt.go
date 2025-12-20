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

func askForConfirmation(p colorPrinter, format string, a ...any) bool {
	interactiveMu.Lock()
	defer interactiveMu.Unlock()

	reader := bufio.NewReader(os.Stdin)
	// First, create the main part of the prompt using the provided arguments.
	mainPrompt := fmt.Sprintf(format, a...)
	// Then, create the final, full prompt string.
	fullPrompt := fmt.Sprintf("%s [Y/n]: ", mainPrompt)

	for {
		// Use our existing cPrintf helper to print the prompt with the desired color.
		// cPrintf will handle the case where 'p' is nil and print without color.
		cPrintf(p, "%s", fullPrompt)
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
