package hokuto

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

type alternativesTUIEntry struct {
	path  string
	entry *FileEntry
}

func alternativeHasOwner(alt *Alternative, owner string) bool {
	for _, current := range alt.Owners {
		if current == owner {
			return true
		}
	}
	return false
}

func entryHasAlternativeOwner(entry *FileEntry, owner string) bool {
	for _, alt := range entry.Alternatives {
		if alternativeHasOwner(alt, owner) {
			return true
		}
	}
	return false
}

func alternativeOwnerLabel(alt *Alternative) string {
	if len(alt.Owners) == 0 {
		return "unowned"
	}
	owners := append([]string(nil), alt.Owners...)
	sort.Strings(owners)
	return strings.Join(owners, ", ")
}

func alternativeProvidersLabel(entry *FileEntry) string {
	var active, stashed []string
	for _, alt := range entry.Alternatives {
		label := alternativeOwnerLabel(alt)
		if alt.State == StateActive {
			active = append(active, "● "+label)
		} else {
			stashed = append(stashed, label)
		}
	}
	sort.Strings(active)
	sort.Strings(stashed)
	return strings.Join(append(active, stashed...), "   ")
}

func alternativesForPackage(db *GlobalAlternativesDB, targetPkg string) []alternativesTUIEntry {
	entries := make([]alternativesTUIEntry, 0)
	for path, entry := range db.Files {
		if entryHasAlternativeOwner(entry, targetPkg) {
			entries = append(entries, alternativesTUIEntry{path: path, entry: entry})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return entries
}

func selectedAlternativeEntries(selected []bool, visible []int, row int) []int {
	var indices []int
	for idx, chosen := range selected {
		if chosen {
			indices = append(indices, idx)
		}
	}
	if len(indices) == 0 && row >= 1 && row-1 < len(visible) {
		indices = append(indices, visible[row-1])
	}
	return indices
}

func commonAlternativeProviders(entries []alternativesTUIEntry, indices []int) []string {
	var common map[string]bool
	for _, idx := range indices {
		owners := make(map[string]bool)
		for _, alt := range entries[idx].entry.Alternatives {
			for _, owner := range alt.Owners {
				owners[owner] = true
			}
		}
		if common == nil {
			common = owners
			continue
		}
		for owner := range common {
			if !owners[owner] {
				delete(common, owner)
			}
		}
	}
	providers := make([]string, 0, len(common))
	for provider := range common {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

func alternativeContent(hRoot, path string, alt *Alternative) ([]byte, error) {
	if normalizedAlternativeType(alt.Type) == AlternativeSymlink {
		target := alt.Target
		if target == "" {
			data, err := readFileAsRoot(getStashedFilePath(hRoot, alt.B3Sum))
			if err != nil {
				return nil, err
			}
			target = string(data)
		}
		return []byte("symlink -> " + target + "\n"), nil
	}
	if alt.State == StateActive {
		return readFileAsRoot(filepath.Join(hRoot, strings.TrimPrefix(path, "/")))
	}
	return readFileAsRoot(getStashedFilePath(hRoot, alt.B3Sum))
}

func alternativesDiff(hRoot string, item alternativesTUIEntry, targetPkg string) (string, error) {
	var targetAlt, comparison *Alternative
	for _, alt := range item.entry.Alternatives {
		if targetAlt == nil && alternativeHasOwner(alt, targetPkg) {
			targetAlt = alt
		}
	}
	if targetAlt == nil {
		return "", fmt.Errorf("%s does not provide %s", targetPkg, item.path)
	}
	for _, alt := range item.entry.Alternatives {
		if alt != targetAlt && alt.State == StateActive {
			comparison = alt
			break
		}
	}
	if comparison == nil {
		for _, alt := range item.entry.Alternatives {
			if alt != targetAlt {
				comparison = alt
				break
			}
		}
	}
	if comparison == nil {
		return "No second version is available for comparison.\n", nil
	}

	left, err := alternativeContent(hRoot, item.path, targetAlt)
	if err != nil {
		return "", fmt.Errorf("failed to read %s version: %w", alternativeOwnerLabel(targetAlt), err)
	}
	right, err := alternativeContent(hRoot, item.path, comparison)
	if err != nil {
		return "", fmt.Errorf("failed to read %s version: %w", alternativeOwnerLabel(comparison), err)
	}
	if bytes.IndexByte(left, 0) >= 0 || bytes.IndexByte(right, 0) >= 0 || !utf8.Valid(left) || !utf8.Valid(right) {
		return fmt.Sprintf("%s and %s differ (binary content cannot be displayed).\n", alternativeOwnerLabel(targetAlt), alternativeOwnerLabel(comparison)), nil
	}

	leftFile, err := os.CreateTemp("", "hokuto-alt-diff-left-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(leftFile.Name())
	rightFile, err := os.CreateTemp("", "hokuto-alt-diff-right-*")
	if err != nil {
		leftFile.Close()
		return "", err
	}
	defer os.Remove(rightFile.Name())
	if _, err := leftFile.Write(left); err != nil {
		leftFile.Close()
		rightFile.Close()
		return "", err
	}
	if _, err := rightFile.Write(right); err != nil {
		leftFile.Close()
		rightFile.Close()
		return "", err
	}
	leftFile.Close()
	rightFile.Close()

	cmd := exec.Command("diff", "-u", "--label", alternativeOwnerLabel(targetAlt), "--label", alternativeOwnerLabel(comparison), leftFile.Name(), rightFile.Name())
	output, diffErr := cmd.CombinedOutput()
	if diffErr != nil {
		if exitErr, ok := diffErr.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			return "", fmt.Errorf("diff failed: %w", diffErr)
		}
	}
	if len(output) == 0 {
		return "The two providers have identical content.\n", nil
	}
	return colorAlternativeDiff(string(output)), nil
}

func colorAlternativeDiff(diff string) string {
	var result strings.Builder
	for _, line := range strings.SplitAfter(diff, "\n") {
		escaped := tview.Escape(line)
		switch {
		case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "@@"):
			result.WriteString("[aqua]")
		case strings.HasPrefix(line, "+"):
			result.WriteString("[green]")
		case strings.HasPrefix(line, "-"):
			result.WriteString("[red]")
		default:
			result.WriteString("[white]")
		}
		result.WriteString(escaped)
	}
	return result.String()
}

func removeAlternativeOwner(alt *Alternative, owner string) {
	owners := alt.Owners[:0]
	for _, current := range alt.Owners {
		if current != owner {
			owners = append(owners, current)
		}
	}
	alt.Owners = owners
}

func pruneAlternativeEntry(db *GlobalAlternativesDB, path string, entry *FileEntry) {
	alternatives := entry.Alternatives[:0]
	for _, alt := range entry.Alternatives {
		if len(alt.Owners) > 0 {
			alternatives = append(alternatives, alt)
		}
	}
	entry.Alternatives = alternatives
	if len(entry.Alternatives) <= 1 {
		delete(db.Files, path)
	}
}

func updateAlternativeOwnerManifest(hRoot, pkgName, path string, alt *Alternative, execCtx *Executor) error {
	manifestPath := filepath.Join(hRoot, "var", "db", "hokuto", "installed", pkgName, "manifest")
	data, err := readFileAsRoot(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read %s manifest: %w", pkgName, err)
	}
	selfPath := "/var/db/hokuto/installed/" + pkgName + "/manifest"
	checksum := alt.B3Sum
	if normalizedAlternativeType(alt.Type) == AlternativeSymlink {
		checksum = "000000"
	}
	found := false
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		entryPath := parseManifestFilePath(line)
		switch entryPath {
		case selfPath:
			continue
		case path:
			line = fmt.Sprintf("%s  %s", path, checksum)
			found = true
		}
		lines = append(lines, line)
	}
	if !found {
		return fmt.Errorf("%s is not present in the %s manifest", path, pkgName)
	}
	body := strings.Join(lines, "\n") + "\n"
	updated := body + fmt.Sprintf("%s  %s\n", selfPath, hashString(body))
	if err := writeFileAsRoot(manifestPath, []byte(updated), 0o644, execCtx); err != nil {
		return fmt.Errorf("failed to update %s manifest: %w", pkgName, err)
	}
	return nil
}

func mergeUnmanagedAlternative(hRoot string, db *GlobalAlternativesDB, path, targetPkg string, execCtx *Executor) error {
	if targetPkg == "unmanaged" {
		return fmt.Errorf("merge destination must be an installed package")
	}
	entry := db.Files[path]
	if entry == nil || !entryHasAlternativeOwner(entry, targetPkg) {
		return fmt.Errorf("%s does not provide %s", targetPkg, path)
	}
	var unmanaged []*Alternative
	for _, alt := range entry.Alternatives {
		if alternativeHasOwner(alt, "unmanaged") {
			unmanaged = append(unmanaged, alt)
		}
	}
	if len(unmanaged) != 1 {
		return fmt.Errorf("%s has %d unmanaged versions; expected exactly one", path, len(unmanaged))
	}
	source := unmanaged[0]
	if source.State != StateActive {
		if _, err := activateAlternativeForOwner(hRoot, path, entry, "unmanaged", execCtx); err != nil {
			return err
		}
	}
	if err := updateAlternativeOwnerManifest(hRoot, targetPkg, path, source, execCtx); err != nil {
		return err
	}
	for _, alt := range entry.Alternatives {
		removeAlternativeOwner(alt, targetPkg)
	}
	removeAlternativeOwner(source, "unmanaged")
	addAlternativeOwner(source, targetPkg)
	pruneAlternativeEntry(db, path, entry)
	return saveAlternativesDB(hRoot, db, execCtx)
}

func discardUnmanagedAlternative(hRoot string, db *GlobalAlternativesDB, path, preferredPkg string, execCtx *Executor) error {
	entry := db.Files[path]
	if entry == nil || !entryHasAlternativeOwner(entry, "unmanaged") {
		return fmt.Errorf("%s has no unmanaged provider", path)
	}
	for _, alt := range entry.Alternatives {
		if alt.State != StateActive || !alternativeHasOwner(alt, "unmanaged") {
			continue
		}
		provider := preferredPkg
		if !entryHasAlternativeOwner(entry, provider) || provider == "unmanaged" {
			provider = ""
			for _, candidate := range entry.Alternatives {
				for _, owner := range candidate.Owners {
					if owner != "unmanaged" {
						provider = owner
						break
					}
				}
				if provider != "" {
					break
				}
			}
		}
		if provider == "" {
			return fmt.Errorf("%s has no managed provider to restore", path)
		}
		if _, err := activateAlternativeForOwner(hRoot, path, entry, provider, execCtx); err != nil {
			return err
		}
		break
	}
	for _, alt := range entry.Alternatives {
		removeAlternativeOwner(alt, "unmanaged")
	}
	pruneAlternativeEntry(db, path, entry)
	return saveAlternativesDB(hRoot, db, execCtx)
}

func runAlternativesTUI(hRoot string, db *GlobalAlternativesDB, targetPkg string) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("interactive alternatives selection requires a terminal")
	}
	entries := alternativesForPackage(db, targetPkg)
	if len(entries) == 0 {
		return fmt.Errorf("package '%s' has no alternatives registered", targetPkg)
	}

	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	table.SetBorder(true).SetTitle(" Alternatives for " + targetPkg + " ")
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	status.SetText("[gray]Space selects, a all, n none, / searches, s switches provider, m merges unmanaged, d displays diff, D discards unmanaged, q quits.[white]")
	searchInput := tview.NewInputField().SetLabel("Search: ")
	bottomPages := tview.NewPages().
		AddPage("status", status, true, true).
		AddPage("search", searchInput, true, false)
	diffView := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(false)
	diffView.SetBorder(true).SetTitle(" Alternative Diff ")
	pages := tview.NewPages().
		AddPage("files", table, true, true).
		AddPage("diff", diffView, true, false)
	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(pages, 0, 1, true).
		AddItem(bottomPages, 2, 0, false)
	selected := make([]bool, len(entries))
	visible := make([]int, 0, len(entries))
	searching := false
	showingDiff := false
	modalOpen := false
	searchQuery := ""

	refreshRow := func(row, idx int) {
		mark := "[ ]"
		markColor := tcell.ColorGray
		if selected[idx] {
			mark = "[X]"
			markColor = tcell.ColorGreen
		}
		providerColor := tcell.ColorWhite
		for _, alt := range entries[idx].entry.Alternatives {
			if alt.State != StateActive {
				continue
			}
			if alternativeHasOwner(alt, targetPkg) {
				providerColor = tcell.ColorGreen
			} else if alternativeHasOwner(alt, "unmanaged") {
				providerColor = tcell.ColorYellow
			}
			break
		}
		table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor).SetExpansion(0))
		table.SetCell(row, 1, tview.NewTableCell(entries[idx].path).SetTextColor(tcell.ColorWhite).SetExpansion(1))
		table.SetCell(row, 2, tview.NewTableCell(alternativeProvidersLabel(entries[idx].entry)).SetTextColor(providerColor).SetExpansion(1))
	}
	refresh := func() {
		table.Clear()
		table.SetCell(0, 0, tview.NewTableCell("").SetSelectable(false))
		table.SetCell(0, 1, tview.NewTableCell("Files").SetTextColor(tcell.ColorAqua).SetAttributes(tcell.AttrBold).SetSelectable(false))
		table.SetCell(0, 2, tview.NewTableCell("Providers (● active)").SetTextColor(tcell.ColorAqua).SetAttributes(tcell.AttrBold).SetSelectable(false))
		visible = visible[:0]
		query := strings.ToLower(strings.TrimSpace(searchQuery))
		for idx := range entries {
			providers := alternativeProvidersLabel(entries[idx].entry)
			if query != "" && !strings.Contains(strings.ToLower(entries[idx].path+" "+providers), query) {
				continue
			}
			visible = append(visible, idx)
			refreshRow(len(visible), idx)
		}
		if len(visible) > 0 {
			table.Select(1, 0)
		}
	}
	refresh()

	setError := func(err error) {
		if err != nil {
			status.SetText("[red]" + tview.Escape(err.Error()) + "[white]")
		}
	}
	actionIndices := func() []int {
		row, _ := table.GetSelection()
		return selectedAlternativeEntries(selected, visible, row)
	}
	refreshEntries := func() {
		entries = alternativesForPackage(db, targetPkg)
		selected = make([]bool, len(entries))
		refresh()
		if len(entries) == 0 {
			app.Stop()
		}
	}

	showProviderModal := func(indices []int) {
		providers := commonAlternativeProviders(entries, indices)
		if len(providers) == 0 {
			setError(fmt.Errorf("selected files have no provider in common"))
			return
		}
		buttons := append(append([]string(nil), providers...), "Cancel")
		modal := tview.NewModal().SetText("Switch selected files to which provider?").AddButtons(buttons)
		modal.SetDoneFunc(func(_ int, label string) {
			modalOpen = false
			if label == "Cancel" || label == "" {
				app.SetRoot(layout, true).SetFocus(table)
				return
			}
			for _, idx := range indices {
				item := entries[idx]
				changed, err := activateAlternativeForOwner(hRoot, item.path, item.entry, label, RootExec)
				if err != nil {
					setError(fmt.Errorf("%s: %w", item.path, err))
					break
				}
				if changed {
					if err := saveAlternativesDB(hRoot, db, RootExec); err != nil {
						setError(err)
						break
					}
				}
			}
			app.SetRoot(layout, true).SetFocus(table)
			refresh()
		})
		modalOpen = true
		app.SetRoot(modal, true).SetFocus(modal)
	}

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

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if modalOpen {
			if event.Key() == tcell.KeyEsc {
				modalOpen = false
				app.SetRoot(layout, true).SetFocus(table)
				return nil
			}
			return event
		}
		if searching {
			return event
		}
		if showingDiff {
			switch event.Key() {
			case tcell.KeyEsc:
				showingDiff = false
				pages.SwitchToPage("files")
				app.SetFocus(table)
				return nil
			case tcell.KeyRune:
				if event.Rune() == 'b' || event.Rune() == 'q' {
					showingDiff = false
					pages.SwitchToPage("files")
					app.SetFocus(table)
					return nil
				}
			}
			return event
		}
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				app.Stop()
			case '/':
				searching = true
				bottomPages.SwitchToPage("search")
				app.SetFocus(searchInput)
			case ' ':
				row, _ := table.GetSelection()
				if row >= 1 && row-1 < len(visible) {
					idx := visible[row-1]
					selected[idx] = !selected[idx]
					refreshRow(row, idx)
				}
			case 'a':
				for row, idx := range visible {
					selected[idx] = true
					refreshRow(row+1, idx)
				}
			case 'n':
				for row, idx := range visible {
					selected[idx] = false
					refreshRow(row+1, idx)
				}
			case 's':
				indices := actionIndices()
				if len(indices) == 0 {
					setError(fmt.Errorf("no files selected"))
				} else {
					showProviderModal(indices)
				}
			case 'm':
				indices := actionIndices()
				for _, idx := range indices {
					item := entries[idx]
					if err := mergeUnmanagedAlternative(hRoot, db, item.path, targetPkg, RootExec); err != nil {
						setError(fmt.Errorf("%s: %w", item.path, err))
						break
					}
				}
				refreshEntries()
			case 'd':
				row, _ := table.GetSelection()
				if row >= 1 && row-1 < len(visible) {
					item := entries[visible[row-1]]
					diff, err := alternativesDiff(hRoot, item, targetPkg)
					if err != nil {
						setError(err)
					} else {
						diffView.SetTitle(" Diff: " + item.path + " (b/Esc returns) ")
						diffView.SetText(diff).ScrollToBeginning()
						showingDiff = true
						pages.SwitchToPage("diff")
						app.SetFocus(diffView)
					}
				}
			case 'D':
				indices := actionIndices()
				for _, idx := range indices {
					item := entries[idx]
					if err := discardUnmanagedAlternative(hRoot, db, item.path, targetPkg, RootExec); err != nil {
						setError(fmt.Errorf("%s: %w", item.path, err))
						break
					}
				}
				refreshEntries()
			}
			return nil
		}
		return event
	})

	return app.SetRoot(layout, true).SetFocus(table).Run()
}
