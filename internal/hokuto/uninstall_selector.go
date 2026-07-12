package hokuto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

type tuiQueuedLogWriter struct {
	app  *tview.Application
	view *tview.TextView
}

func (w *tuiQueuedLogWriter) Write(p []byte) (int, error) {
	text := string(append([]byte(nil), p...))
	text = strings.ReplaceAll(text, "\r", "")
	w.app.QueueUpdateDraw(func() {
		fmt.Fprint(w.view, text)
		w.view.ScrollToEnd()
	})
	return len(p), nil
}

type tuiLogWriter struct {
	ansi io.Writer
}

func newTUILogWriter(app *tview.Application, view *tview.TextView) *tuiLogWriter {
	queued := &tuiQueuedLogWriter{app: app, view: view}
	return &tuiLogWriter{ansi: tview.ANSIWriter(queued)}
}

func (w *tuiLogWriter) Write(p []byte) (int, error) {
	return w.ansi.Write(p)
}

type uninstallListEntry struct {
	Name      string
	Size      int64
	Meta      string
	Protected bool
}

func installedUninstallListEntries() ([]uninstallListEntry, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read installed packages: %w", err)
	}

	var result []uninstallListEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		version := "unknown"
		if data, readErr := os.ReadFile(filepath.Join(Installed, name, "version")); readErr == nil {
			version = strings.TrimSpace(string(data))
		}
		size, _, _, _ := installedPackageSize(name)
		protected := name == protectedBasePackage
		if protected {
			version += " | protected base filesystem"
		}
		result = append(result, uninstallListEntry{Name: name, Size: size, Meta: version, Protected: protected})
	}
	for _, name := range installedMetaPackageNames() {
		meta := "metapackage"
		if pkg, ok := readInstalledMetaPackageMarker(name); ok && pkg.Description != "" {
			meta += " | " + pkg.Description
		}
		result = append(result, uninstallListEntry{Name: name, Meta: meta})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// orderPackagesForUninstall places dependents before their selected
// dependencies. This lets normal mode stop safely if a dependent fails instead
// of having already removed one of its requirements.
func orderPackagesForUninstall(packages []string) []string {
	selected := make(map[string]bool, len(packages))
	for _, name := range packages {
		selected[name] = true
	}
	adjacent := make(map[string][]string, len(packages))
	indegree := make(map[string]int, len(packages))
	for _, name := range packages {
		indegree[name] = 0
	}
	for _, name := range packages {
		deps, err := getInstalledDeps(name)
		if err != nil {
			continue
		}
		seen := make(map[string]bool)
		for _, dep := range deps {
			if !selected[dep] || seen[dep] {
				continue
			}
			seen[dep] = true
			adjacent[name] = append(adjacent[name], dep)
			indegree[dep]++
		}
	}

	var ready []string
	for name, degree := range indegree {
		if degree == 0 {
			ready = append(ready, name)
		}
	}
	sort.Strings(ready)
	ordered := make([]string, 0, len(packages))
	for len(ready) > 0 {
		name := ready[0]
		ready = ready[1:]
		ordered = append(ordered, name)
		for _, dep := range adjacent[name] {
			indegree[dep]--
			if indegree[dep] == 0 {
				ready = append(ready, dep)
				sort.Strings(ready)
			}
		}
	}
	if len(ordered) != len(packages) {
		var cyclic []string
		for name, degree := range indegree {
			if degree > 0 {
				cyclic = append(cyclic, name)
			}
		}
		sort.Strings(cyclic)
		ordered = append(ordered, cyclic...)
	}
	return ordered
}

func selectPackagesToUninstall(entries []uninstallListEntry, cfg *Config, initialForce bool) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("interactive package selection requires a terminal")
	}
	if len(entries) == 0 {
		return fmt.Errorf("no installed packages available for selection")
	}

	selected := make([]bool, len(entries))
	force := initialForce
	busy := false
	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(0, 0)
	table.SetBorder(true).SetTitle(" Installed Packages ")
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	logView := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	logView.SetBorder(true).SetTitle(" Uninstall Log ")
	logger := newTUILogWriter(app, logView)
	pages := tview.NewPages().
		AddPage("packages", table, true, true).
		AddPage("log", logView, true, false)
	showingLog := false
	logStatus := "[gray]l to return to packages, q to quit.[white]"
	var refreshStatus func()
	toggleLog := func() {
		showingLog = !showingLog
		if showingLog {
			pages.SwitchToPage("log")
			app.SetFocus(logView)
			status.SetText(logStatus)
		} else {
			pages.SwitchToPage("packages")
			app.SetFocus(table)
			refreshStatus()
		}
	}

	refreshRow := func(row int) {
		mark := "[ ]"
		if selected[row] {
			mark = "[X]"
		}
		markColor := tcell.ColorGreen
		nameColor := tcell.ColorWhite
		if entries[row].Protected {
			mark = "[!]"
			markColor = tcell.ColorYellow
			nameColor = tcell.ColorYellow
		}
		table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor).SetExpansion(0))
		table.SetCell(row, 1, tview.NewTableCell(entries[row].Name).SetTextColor(nameColor).SetExpansion(1))
		table.SetCell(row, 2, tview.NewTableCell(humanReadableSize(entries[row].Size)).SetTextColor(tcell.ColorYellow).SetExpansion(0).SetAlign(tview.AlignRight))
		table.SetCell(row, 3, tview.NewTableCell(entries[row].Meta).SetTextColor(tcell.ColorGray).SetExpansion(0))
	}
	refreshStatus = func() {
		mode := "[green]normal[white]"
		if force {
			mode = "[red]force[white]"
		}
		status.SetText(fmt.Sprintf("[gray]Space toggles, a selects all, n selects none, f toggles mode, u uninstalls, o cleans orphans, l toggles log, q quits.  Mode: %s", mode))
	}
	refreshTable := func() {
		table.Clear()
		for i := range entries {
			refreshRow(i)
		}
	}
	refreshTable()
	refreshStatus()

	runUninstall := func(packages []string, forceMode bool, actionName string) {
		defer func() { isCriticalAtomic.Store(0) }()
		isCriticalAtomic.Store(1)
		packages = orderPackagesForUninstall(packages)
		removing := make(map[string]bool, len(packages))
		for _, name := range packages {
			removing[name] = true
		}
		succeeded := make(map[string]bool)
		failedCount := 0
		tuiExec := *RootExec
		tuiExec.Interactive = false
		tuiExec.Stdout = io.Writer(logger)
		tuiExec.Stderr = io.Writer(logger)
		for _, name := range packages {
			fmt.Fprintf(logger, "-> Removing %s\n", name)
			var uninstallErr error
			if name == protectedBasePackage {
				uninstallErr = fmt.Errorf("protected base filesystem package cannot be removed")
			} else if isMetaPackageInstalled(name) {
				uninstallErr = removeMetaPackageMarker(name)
			} else {
				uninstallErr = pkgUninstallWithRemovalSet(name, cfg, &tuiExec, forceMode, true, logger, removing)
			}
			delete(removing, name)
			if uninstallErr != nil {
				failedCount++
				fmt.Fprintf(logger, "ERROR: failed to remove %s: %v\n", name, uninstallErr)
				continue
			}
			removeFromWorld(name)
			removeFromWorldMake(name)
			succeeded[name] = true
			fmt.Fprintf(logger, "-> %s removed successfully\n", name)
		}
		app.QueueUpdateDraw(func() {
			remaining := entries[:0]
			for _, entry := range entries {
				if !succeeded[entry.Name] {
					remaining = append(remaining, entry)
				}
			}
			entries = remaining
			selected = make([]bool, len(entries))
			refreshTable()
			busy = false
			if failedCount > 0 {
				logStatus = fmt.Sprintf("[yellow]%s finished with %d failure(s). l to return or press q to quit.[white]", actionName, failedCount)
			} else {
				logStatus = fmt.Sprintf("[green]%s completed. l to return or press q to quit.[white]", actionName)
			}
			if showingLog {
				status.SetText(logStatus)
			} else {
				refreshStatus()
			}
		})
	}

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune && event.Rune() == 'l' {
			toggleLog()
			return nil
		}
		if busy {
			return nil
		}
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				app.Stop()
				return nil
			case ' ':
				row, _ := table.GetSelection()
				if row >= 0 && row < len(selected) {
					if entries[row].Protected {
						status.SetText("[yellow]sauzeros-base is protected and cannot be uninstalled.[white]")
						return nil
					}
					selected[row] = !selected[row]
					refreshRow(row)
				}
				return nil
			case 'a':
				for i := range selected {
					selected[i] = !entries[i].Protected
					refreshRow(i)
				}
				return nil
			case 'n':
				for i := range selected {
					selected[i] = false
					refreshRow(i)
				}
				return nil
			case 'f':
				force = !force
				refreshStatus()
				return nil
			case 'u':
				var packages []string
				for i, chosen := range selected {
					if chosen {
						packages = append(packages, entries[i].Name)
					}
				}
				if len(packages) == 0 {
					status.SetText("[yellow]Select at least one package before uninstalling.[white]")
					return nil
				}
				busy = true
				logStatus = "[yellow]Uninstalling selected packages… l to return to packages.[white]"
				if !showingLog {
					toggleLog()
				} else {
					status.SetText(logStatus)
				}
				go runUninstall(packages, force, "Uninstall")
				return nil
			case 'o':
				busy = true
				logStatus = "[yellow]Checking for orphan packages… l to return to packages.[white]"
				if !showingLog {
					toggleLog()
				} else {
					status.SetText(logStatus)
				}
				go func() {
					fmt.Fprintln(logger, "-> Checking for orphan packages")
					runtimeOrphans, runtimeErr := findOrphans()
					makeOrphans, makeErr := findMakeOrphans()
					if runtimeErr != nil || makeErr != nil {
						app.QueueUpdateDraw(func() {
							busy = false
							logStatus = fmt.Sprintf("[red]Failed to calculate orphans: runtime=%v build=%v[white]", runtimeErr, makeErr)
							if showingLog {
								status.SetText(logStatus)
							} else {
								refreshStatus()
							}
						})
						return
					}
					seen := make(map[string]bool)
					var orphans []string
					for _, name := range append(runtimeOrphans, makeOrphans...) {
						if name == "" || name == protectedBasePackage || seen[name] {
							continue
						}
						seen[name] = true
						orphans = append(orphans, name)
					}
					sort.Strings(orphans)
					if len(orphans) == 0 {
						fmt.Fprintln(logger, "-> No orphan packages found.")
						app.QueueUpdateDraw(func() {
							busy = false
							logStatus = "[green]No orphan packages found. l to return or press q to quit.[white]"
							if showingLog {
								status.SetText(logStatus)
							} else {
								refreshStatus()
							}
						})
						return
					}
					fmt.Fprintf(logger, "-> Found %d orphan package(s): %s\n", len(orphans), strings.Join(orphans, ", "))
					app.QueueUpdateDraw(func() {
						logStatus = "[yellow]Cleaning orphan packages… l to return to packages.[white]"
						if showingLog {
							status.SetText(logStatus)
						}
					})
					runUninstall(orphans, false, "Orphan cleanup")
				}()
				return nil
			}
		}
		return event
	})

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(pages, 0, 1, true).
		AddItem(status, 1, 0, false)
	if err := app.SetRoot(flex, true).SetFocus(table).Run(); err != nil {
		return err
	}
	return nil
}
