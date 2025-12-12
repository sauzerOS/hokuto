package hokuto

import "fmt"

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
