package hokuto

// Selection for `hokuto update --build-missing-binaries`: a full-screen list
// like `hokuto list`, with a blacklist. A blacklisted package is
// left out of later runs until its recipe's version or revision changes.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

// buildIgnoreEntry blacklists one recipe at one version-revision.
type buildIgnoreEntry struct {
	Package string    `json:"package"`
	Version string    `json:"version"` // version-revision, e.g. 4.1.0-8
	AddedAt time.Time `json:"added_at"`
}

func loadBuildIgnoreList() (map[string]buildIgnoreEntry, error) {
	ignores := make(map[string]buildIgnoreEntry)
	data, err := os.ReadFile(BuildIgnoreFile)
	if err != nil {
		if os.IsNotExist(err) {
			return ignores, nil
		}
		return ignores, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return ignores, nil
	}
	var entries []buildIgnoreEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return ignores, err
	}
	for _, entry := range entries {
		if entry.Package != "" && entry.Version != "" {
			ignores[entry.Package] = entry
		}
	}
	return ignores, nil
}

func saveBuildIgnoreList(ignores map[string]buildIgnoreEntry) error {
	entries := make([]buildIgnoreEntry, 0, len(ignores))
	for _, entry := range ignores {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Package < entries[j].Package })
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeStateFile(BuildIgnoreFile, append(data, '\n'))
}

// recipeRelease is a recipe's current "version-revision".
func recipeRelease(pkgName string) string {
	version, revision, err := getRepoVersion2(pkgName)
	if err != nil {
		return ""
	}
	return version + "-" + revision
}

// buildIgnored reports whether pkgName is blacklisted at its current
// version-revision. A new version or revision ends the blacklisting.
func buildIgnored(ignores map[string]buildIgnoreEntry, pkgName string) bool {
	entry, ok := ignores[pkgName]
	return ok && entry.Version == recipeRelease(pkgName)
}

// pruneBuildIgnores drops entries whose recipe moved on or is gone, and
// reports whether anything changed.
func pruneBuildIgnores(ignores map[string]buildIgnoreEntry) bool {
	changed := false
	for name := range ignores {
		if !buildIgnored(ignores, name) {
			delete(ignores, name)
			changed = true
		}
	}
	return changed
}

// missingBinaryEntry is one row of the selection list.
type missingBinaryEntry struct {
	Name   string
	Info   string // "4.1.0-4 -> 4.1.0-8 (icewm)"
	Reason string // "rebuild for libplist ABI change", or ""
	Commit string // full message of the commit that set the current version
}

// selectMissingBinaryPackages shows the list and returns the packages to
// build and the packages blacklisted in it. Blacklisting is a mark that is
// saved when the list closes, whichever way; building needs b.
func selectMissingBinaryPackages(entries []missingBinaryEntry) (build []string, blacklist []string, err error) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, nil, fmt.Errorf("interactive selection requires a terminal")
	}
	return runMissingBinarySelector(entries, nil)
}

// runMissingBinarySelector runs the list on screen, or on the terminal when
// screen is nil (tests pass a simulation screen).
func runMissingBinarySelector(entries []missingBinaryEntry, screen tcell.Screen) (build []string, blacklist []string, err error) {
	selected := make([]bool, len(entries))
	blacklisted := make([]bool, len(entries))

	app := tview.NewApplication()
	if screen != nil {
		app.SetScreen(screen)
	}
	table := tview.NewTable().SetSelectable(true, false).SetFixed(0, 0)
	table.SetBorder(true).SetTitle(fmt.Sprintf(" Missing binaries: %d packages ", len(entries)))
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	searchInput := tview.NewInputField().SetLabel("Search: ")
	bottomPages := tview.NewPages().
		AddPage("status", status, true, true).
		AddPage("search", searchInput, true, false)
	searching := false
	searchQuery := ""
	var visible []int

	footer := func(note string) {
		nSel, nBl := 0, 0
		for i := range entries {
			if selected[i] {
				nSel++
			}
			if blacklisted[i] {
				nBl++
			}
		}
		text := fmt.Sprintf("[gray]Space toggles, a selects all, n selects none, / searches, x blacklists/unblacklists, b builds, q quits.\nSelected: [green]%d[gray] | Blacklisted: [red]%d[gray] (kept until the version or revision changes)[white]", nSel, nBl)
		if note != "" {
			text = note + "\n" + text
		}
		status.SetText(text)
	}
	refreshRow := func(row, i int) {
		mark, markColor, nameColor, info, infoColor := "[ ]", tcell.ColorGray, tcell.ColorWhite, entries[i].Info, tcell.ColorGray
		switch {
		case blacklisted[i]:
			mark, markColor, nameColor, info, infoColor = "[-]", tcell.ColorRed, tcell.ColorGray, "blacklisted | "+entries[i].Info, tcell.ColorRed
		case selected[i]:
			mark, markColor = "[X]", tcell.ColorGreen
		}
		table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor))
		table.SetCell(row, 1, tview.NewTableCell(entries[i].Name).SetTextColor(nameColor))
		table.SetCell(row, 2, tview.NewTableCell(tview.Escape(info)).SetTextColor(infoColor))
		reasonColor := tcell.ColorDarkCyan
		if blacklisted[i] {
			reasonColor = tcell.ColorGray
		}
		table.SetCell(row, 3, tview.NewTableCell(tview.Escape(entries[i].Reason)).SetTextColor(reasonColor).SetExpansion(1))
	}
	// The full commit message of the highlighted package, which the reason
	// column only summarizes.
	commitView := tview.NewTextView().SetWrap(true).SetWordWrap(true)
	commitView.SetBorder(true).SetTitle(" Commit ")
	showCommit := func(row int) {
		if row < 0 || row >= len(visible) {
			commitView.SetText("")
			return
		}
		message := entries[visible[row]].Commit
		if message == "" {
			message = "(no commit changed this recipe's version)"
		}
		commitView.SetText(message).ScrollToBeginning()
	}
	table.SetSelectionChangedFunc(func(row, _ int) { showCommit(row) })
	refresh := func() {
		table.Clear()
		visible = visible[:0]
		query := strings.ToLower(strings.TrimSpace(searchQuery))
		for i := range entries {
			if query != "" && !strings.Contains(strings.ToLower(entries[i].Name), query) {
				continue
			}
			refreshRow(len(visible), i)
			visible = append(visible, i)
		}
		row, _ := table.GetSelection()
		showCommit(row)
	}
	refresh()
	footer("")

	searchInput.SetChangedFunc(func(text string) {
		searchQuery = text
		refresh()
	})
	searchInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			searchInput.SetText("")
			searchQuery = ""
			refresh()
		}
		searching = false
		bottomPages.SwitchToPage("status")
		app.SetFocus(table)
	})

	buildRequested := false
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if searching {
			return event
		}
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyRune:
		default:
			return event
		}
		row, _ := table.GetSelection()
		switch event.Rune() {
		case '/':
			searching = true
			bottomPages.SwitchToPage("search")
			app.SetFocus(searchInput)
		case 'q':
			app.Stop()
		case ' ':
			if row >= 0 && row < len(visible) {
				i := visible[row]
				if blacklisted[i] {
					footer("[yellow]" + entries[i].Name + " is blacklisted; x unblacklists it.[white]")
					return nil
				}
				selected[i] = !selected[i]
				refreshRow(row, i)
				footer("")
			}
		case 'a', 'n':
			for r, i := range visible {
				if !blacklisted[i] {
					selected[i] = event.Rune() == 'a'
					refreshRow(r, i)
				}
			}
			footer("")
		case 'x':
			// The selected packages, or the one under the cursor.
			var targets []int
			for _, i := range visible {
				if selected[i] {
					targets = append(targets, i)
				}
			}
			if len(targets) == 0 && row >= 0 && row < len(visible) {
				targets = []int{visible[row]}
			}
			for _, i := range targets {
				blacklisted[i] = !blacklisted[i]
				selected[i] = false
			}
			refresh()
			footer("")
		case 'b':
			for i := range entries {
				if selected[i] {
					buildRequested = true
					app.Stop()
					return nil
				}
			}
			footer("[yellow]Select at least one package to build.[white]")
		default:
			return event
		}
		return nil
	})

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(commitView, 6, 0, false).
		AddItem(bottomPages, 3, 0, false)
	if err := app.SetRoot(flex, true).SetFocus(table).Run(); err != nil {
		return nil, nil, err
	}
	for i, entry := range entries {
		if blacklisted[i] {
			blacklist = append(blacklist, entry.Name)
		} else if buildRequested && selected[i] {
			build = append(build, entry.Name)
		}
	}
	return build, blacklist, nil
}
