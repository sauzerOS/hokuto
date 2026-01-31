package hokuto

import (
	"fmt"
	"strings"
)

// color-compatible printer interface (works with *color.Theme and *color.Style)
type colorPrinter interface {
	Printf(format string, a ...any)
	Println(a ...any)
}

// cPrintf prints with a colored style or falls back to fmt.Printf when nil
func cPrintf(p colorPrinter, format string, a ...any) {
	if p == nil {
		fmt.Printf(format, a...)
		return
	}
	p.Printf(format, a...)
}

// cPrintln prints a line with the given style or falls back to fmt.Println when nil
func cPrintln(p colorPrinter, a ...any) {
	if p == nil {
		fmt.Println(a...)
		return
	}
	p.Println(a...)
}

// debugf prints debug messages when Debug is true
func debugf(format string, args ...any) {
	if Debug {
		fmt.Printf(format, args...)
	}
}

// PreprocessBuildArgs splits sticky flags like -j4 into -j 4
func PreprocessBuildArgs(args []string) []string {
	var newArgs []string
	for _, arg := range args {
		// Handle -j<number> (e.g., -j4)
		if len(arg) > 2 && strings.HasPrefix(arg, "-j") && !strings.Contains(arg, "=") {
			// Check if the rest are digits
			rest := arg[2:]
			isDigit := true
			for _, r := range rest {
				if r < '0' || r > '9' {
					isDigit = false
					break
				}
			}
			if isDigit {
				newArgs = append(newArgs, "-j", rest)
				continue
			}
		}
		newArgs = append(newArgs, arg)
	}
	return newArgs
}
