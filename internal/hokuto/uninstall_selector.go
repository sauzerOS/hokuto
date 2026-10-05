package hokuto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

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

// installedListEntry is one row of "hokuto list": an installed package or
// metapackage.
type installedListEntry struct {
	Name      string
	Version   string
	Size      int64
	HasSize   bool
	Platform  string // arch and variant, "x86_64 native (multi)"
	BuildTime string
	Meta      string
	Protected bool
	IsMeta    bool
}

// installedListEntries lists the installed packages and metapackages, sorted
// by name. Sizes come from installedPackageSizes (the size recorded at
// install), not from walking manifests.
func installedListEntries() ([]installedListEntry, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read installed packages: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sizes := installedPackageSizes(names)

	var result []installedListEntry
	for _, name := range names {
		version := "unknown"
		if data, readErr := os.ReadFile(filepath.Join(Installed, name, "version")); readErr == nil {
			version = strings.TrimSpace(string(data))
		}
		size, hasSize := sizes[name]
		protected := name == protectedBasePackage
		meta := ""
		if protected {
			meta = "protected base filesystem"
		}
		result = append(result, installedListEntry{
			Name:      name,
			Version:   version,
			Size:      size,
			HasSize:   hasSize,
			Platform:  installedPackagePlatform(name),
			BuildTime: installedPackageBuildTime(name),
			Meta:      meta,
			Protected: protected,
		})
	}
	for _, name := range installedMetaPackageNames() {
		meta := ""
		if pkg, ok := readInstalledMetaPackageMarker(name); ok {
			meta = pkg.Description
		}
		result = append(result, installedListEntry{Name: name, Version: "metapackage", Meta: meta, IsMeta: true})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

// installedPackagePlatform is the arch and variant a package was built for,
// read from its pkginfo: "x86_64 native", "x86_64 generic (multi)".
func installedPackagePlatform(name string) string {
	data, err := os.ReadFile(filepath.Join(Installed, name, "pkginfo"))
	if err != nil {
		return "? ?"
	}
	meta := ParsePkgInfo(data)
	arch := meta["arch"]
	if arch == "" {
		arch = "?"
	}
	variant := "native"
	if meta["generic"] == "1" {
		variant = "generic"
	}
	if meta["multilib"] == "1" {
		variant += " (multi)"
	}
	return arch + " " + variant
}

// installedPackageBuildTime is how long the package took to build, as
// recorded at build time, or "" when unknown.
func installedPackageBuildTime(name string) string {
	data, err := os.ReadFile(filepath.Join(Installed, name, "buildtime"))
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return ""
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		// Old format: plain float seconds.
		if secs, err := strconv.ParseFloat(raw, 64); err == nil {
			return fmt.Sprintf("%.2fs", secs)
		}
		return raw
	}
	switch {
	case d >= time.Minute:
		return d.Truncate(time.Second).String()
	case d >= time.Second:
		return fmt.Sprintf("%.2fs", d.Seconds())
	case d >= time.Millisecond:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	default:
		return d.Truncate(time.Microsecond).String()
	}
}

func sortInstalledListEntries(entries []installedListEntry, sortMode string) {
	sort.SliceStable(entries, func(i, j int) bool {
		if sortMode == "alphabetical" {
			return entries[i].Name < entries[j].Name
		}
		if entries[i].HasSize != entries[j].HasSize {
			return entries[i].HasSize
		}
		if entries[i].Size == entries[j].Size {
			return entries[i].Name < entries[j].Name
		}
		if sortMode == "size-asc" {
			return entries[i].Size < entries[j].Size
		}
		return entries[i].Size > entries[j].Size
	})
}

func installedListSortLabel(sortMode string) string {
	switch sortMode {
	case "size-desc":
		return "size ↓"
	case "size-asc":
		return "size ↑"
	default:
		return "alphabetical"
	}
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

// runInstalledPackagesTUI is "hokuto list" on a terminal: the installed
// packages, searchable and sortable, selectable for removal. sortMode is the
// initial order (alphabetical, size-desc or size-asc) and search the initial
// search.
func runInstalledPackagesTUI(entries []installedListEntry, cfg *Config, sortMode, search string, initialForce bool) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("interactive package selection requires a terminal")
	}
	if len(entries) == 0 {
		return fmt.Errorf("no installed packages available for selection")
	}

	selected := make(map[string]bool, len(entries))
	sortInstalledListEntries(entries, sortMode)
	force := initialForce
	busy := false
	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(0, 0)
	table.SetBorder(true).SetTitle(" Installed Packages ")
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	searchInput := tview.NewInputField().SetLabel("Search: ")
	bottomPages := tview.NewPages().
		AddPage("status", status, true, true).
		AddPage("search", searchInput, true, false)
	searching := false
	searchQuery := search
	searchInput.SetText(search)
	var visibleIndices []int
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

	refreshRow := func(row, entryIndex int) {
		mark := "[ ]"
		if selected[entries[entryIndex].Name] {
			mark = "[X]"
		}
		markColor := tcell.ColorGreen
		nameColor := tcell.ColorWhite
		if entries[entryIndex].Protected {
			mark = "[!]"
			markColor = tcell.ColorYellow
			nameColor = tcell.ColorYellow
		}
		table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor).SetExpansion(0))
		table.SetCell(row, 1, tview.NewTableCell(entries[entryIndex].Name).SetTextColor(nameColor).SetExpansion(1))
		entry := entries[entryIndex]
		versionColor := tcell.ColorGreen
		if entry.IsMeta {
			versionColor = tcell.ColorGray
		}
		size := ""
		if entry.HasSize {
			size = humanReadableSize(entry.Size)
		} else if !entry.IsMeta {
			size = "?"
		}
		table.SetCell(row, 2, tview.NewTableCell(tview.Escape(entry.Version)).SetTextColor(versionColor).SetExpansion(0))
		table.SetCell(row, 3, tview.NewTableCell(size).SetTextColor(tcell.ColorYellow).SetExpansion(0).SetAlign(tview.AlignRight))
		table.SetCell(row, 4, tview.NewTableCell(tview.Escape(entry.Platform)).SetTextColor(tcell.ColorDarkCyan).SetExpansion(0))
		table.SetCell(row, 5, tview.NewTableCell(entry.BuildTime).SetTextColor(tcell.ColorYellow).SetExpansion(0).SetAlign(tview.AlignRight))
		table.SetCell(row, 6, tview.NewTableCell(tview.Escape(entry.Meta)).SetTextColor(tcell.ColorGray).SetExpansion(0))
	}
	refreshStatus = func() {
		mode := "[green]normal[white]"
		if force {
			mode = "[red]force[white]"
		}
		status.SetText(fmt.Sprintf("[gray]Space toggles, a selects all, n selects none, / searches, s sorts size, S sorts alphabetically, f toggles mode, u uninstalls, o cleans orphans, l toggles log, q quits.\nMode: %s | Sort: %s", mode, installedListSortLabel(sortMode)))
	}
	refreshTable := func() {
		table.Clear()
		visibleIndices = visibleIndices[:0]
		query := strings.ToLower(strings.TrimSpace(searchQuery))
		title := " Installed Packages | " + installedListSortLabel(sortMode) + " "
		if query != "" {
			title += "| search: " + tview.Escape(query) + " "
		}
		table.SetTitle(title)
		for i := range entries {
			if query != "" && !strings.Contains(strings.ToLower(entries[i].Name), query) {
				continue
			}
			row := len(visibleIndices)
			visibleIndices = append(visibleIndices, i)
			refreshRow(row, i)
		}
	}
	searchInput.SetChangedFunc(func(text string) {
		searchQuery = text
		refreshTable()
	})
	searchInput.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			searchInput.SetText("")
			searchQuery = ""
			refreshTable()
		}
		searching = false
		bottomPages.SwitchToPage("status")
		app.SetFocus(table)
		refreshStatus()
	})
	refreshTable()
	refreshStatus()

	runUninstall := func(packages []string, forceMode bool, actionName string) {
		// "hokuto list" starts unprivileged: authenticate on the first
		// removal, with the interface suspended so sudo or run0 can prompt.
		if os.Geteuid() != 0 && activePrivilegeBackend == privilegeBackendUnset {
			var authErr error
			if !app.Suspend(func() { authErr = authenticateOnce(false) }) {
				authErr = fmt.Errorf("unable to suspend the interface for authentication")
			}
			if authErr != nil {
				fcPrintf(logger, colArrow, "-> ")
				fcPrintf(logger, colError, "ERROR: ")
				fcPrintf(logger, colSuccess, "authentication failed: %v\n", authErr)
				app.QueueUpdateDraw(func() {
					busy = false
					logStatus = "[red]Authentication failed. l to return or press q to quit.[white]"
					if showingLog {
						status.SetText(logStatus)
					} else {
						refreshStatus()
					}
				})
				return
			}
		}
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
		tuiExec.Reauthenticate = func() error {
			var authErr error
			if !app.Suspend(func() {
				colArrow.Print("-> ")
				colSuccess.Println("Sudo ticket has expired. Re-authenticating")
				authErr = runInteractiveCommand(tuiExec.Context, "sudo", "-v")
				if authErr == nil {
					colArrow.Print("-> ")
					colSuccess.Println("Re-authenticated via sudo successfully.")
				}
			}) {
				return fmt.Errorf("unable to suspend the uninstall interface for sudo authentication")
			}
			return authErr
		}
		for _, name := range packages {
			fcPrintf(logger, colArrow, "-> ")
			fcPrintf(logger, colSuccess, "Removing ")
			fcPrintf(logger, colNote, "%s\n", name)
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
				fcPrintf(logger, colArrow, "-> ")
				fcPrintf(logger, colError, "ERROR: ")
				fcPrintf(logger, colSuccess, "failed to remove ")
				fcPrintf(logger, colNote, "%s", name)
				message := uninstallErr.Error()
				dependencyPrefix := fmt.Sprintf("cannot uninstall %s: other packages depend on it: ", name)
				if dependents, ok := strings.CutPrefix(message, dependencyPrefix); ok {
					fcPrintf(logger, colSuccess, ": cannot uninstall ")
					fcPrintf(logger, colNote, "%s", name)
					fcPrintf(logger, colSuccess, ": other packages depend on it: ")
					for i, dependent := range strings.Split(dependents, ", ") {
						if i > 0 {
							fcPrintf(logger, colSuccess, ", ")
						}
						fcPrintf(logger, colNote, "%s", dependent)
					}
					fcPrintf(logger, colSuccess, "\n")
				} else {
					fcPrintf(logger, colSuccess, ": %s\n", message)
				}
				continue
			}
			removeFromWorld(name)
			removeFromWorldMake(name)
			succeeded[name] = true
			fcPrintf(logger, colArrow, "-> ")
			fcPrintf(logger, colNote, "%s", name)
			fcPrintf(logger, colSuccess, " removed successfully\n")
		}
		app.QueueUpdateDraw(func() {
			remaining := entries[:0]
			for _, entry := range entries {
				if !succeeded[entry.Name] {
					remaining = append(remaining, entry)
				}
			}
			entries = remaining
			selected = make(map[string]bool, len(entries))
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
		if searching {
			return event
		}
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
			case '/':
				if showingLog {
					toggleLog()
				}
				searching = true
				bottomPages.SwitchToPage("search")
				app.SetFocus(searchInput)
				return nil
			case 'q':
				app.Stop()
				return nil
			case ' ':
				row, _ := table.GetSelection()
				if row >= 0 && row < len(visibleIndices) {
					entryIndex := visibleIndices[row]
					if entries[entryIndex].Protected {
						status.SetText("[yellow]sauzeros-base is protected and cannot be uninstalled.[white]")
						return nil
					}
					name := entries[entryIndex].Name
					selected[name] = !selected[name]
					refreshRow(row, entryIndex)
				}
				return nil
			case 'a':
				for row, entryIndex := range visibleIndices {
					selected[entries[entryIndex].Name] = !entries[entryIndex].Protected
					refreshRow(row, entryIndex)
				}
				return nil
			case 'n':
				for row, entryIndex := range visibleIndices {
					selected[entries[entryIndex].Name] = false
					refreshRow(row, entryIndex)
				}
				return nil
			case 'f':
				force = !force
				refreshStatus()
				return nil
			case 's':
				if sortMode == "size-desc" {
					sortMode = "size-asc"
				} else {
					sortMode = "size-desc"
				}
				sortInstalledListEntries(entries, sortMode)
				refreshTable()
				refreshStatus()
				return nil
			case 'S':
				sortMode = "alphabetical"
				sortInstalledListEntries(entries, sortMode)
				refreshTable()
				refreshStatus()
				return nil
			case 'u':
				var packages []string
				for _, entry := range entries {
					if selected[entry.Name] {
						packages = append(packages, entry.Name)
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
					fcPrintf(logger, colArrow, "-> ")
					fcPrintf(logger, colSuccess, "Checking for orphan packages\n")
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
						fcPrintf(logger, colArrow, "-> ")
						fcPrintf(logger, colSuccess, "No orphan packages found.\n")
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
					fcPrintf(logger, colArrow, "-> ")
					fcPrintf(logger, colSuccess, "Found %d orphan package(s): ", len(orphans))
					fcPrintf(logger, colNote, "%s\n", strings.Join(orphans, ", "))
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
		AddItem(bottomPages, 2, 0, false)
	if err := app.SetRoot(flex, true).SetFocus(table).Run(); err != nil {
		return err
	}
	return nil
}
