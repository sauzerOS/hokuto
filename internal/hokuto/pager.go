package hokuto

import (
	"fmt"
	"os"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// RunPager takes a slice of lines and displays them in a scrollable TUI if stdout is a TTY.
// If stdout is not a TTY, it prints the lines normally.
func RunPager(title string, lines []string) error {
	fd := int(os.Stdout.Fd())
	isTTY := term.IsTerminal(fd)

	// 1. If not TTY, print and return
	if !isTTY {
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	}

	// 2. Check terminal size
	_, height, err := term.GetSize(fd)
	// We use a buffer of 2 lines for the TUI border (top/bottom)
	// If it fits, just print it normally
	if err == nil && len(lines) <= height-2 {
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	}

	// 3. Create the tview application
	app := tview.NewApplication()

	// 3. Create the text view for content
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true).
		SetWrap(false)

	textView.SetBorder(true).SetTitle(" " + title + " ")

	// Ensure ANSI sequences are handled correctly
	ansiWriter := tview.ANSIWriter(textView)
	fmt.Fprint(ansiWriter, strings.Join(lines, "\n"))

	// 4. Create footer with help info
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("[gray]Use ↑/↓, PgUp/PgDn, Home/End to scroll. Press 'q' or 'Esc' to quit.[white]")

	// 5. Layout
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(textView, 0, 1, true).
		AddItem(footer, 1, 0, false)

	// 6. Key bindings
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyRune:
			if event.Rune() == 'q' {
				app.Stop()
				return nil
			}
		}
		return event
	})

	// 7. Run the application
	if err := app.SetRoot(flex, true).SetFocus(textView).Run(); err != nil {
		return fmt.Errorf("pager execution failed: %w", err)
	}

	return nil
}
