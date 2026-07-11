package hokuto

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

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

func selectPackagesToUninstall(entries []uninstallListEntry, initialForce bool) (packages []string, force bool, confirmed bool, err error) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return nil, initialForce, false, fmt.Errorf("interactive package selection requires a terminal")
	}
	if len(entries) == 0 {
		return nil, initialForce, false, fmt.Errorf("no installed packages available for selection")
	}

	selected := make([]bool, len(entries))
	force = initialForce
	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(0, 0)
	table.SetBorder(true).SetTitle(" Installed Packages ")
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)

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
	refreshStatus := func() {
		mode := "[green]normal[white]"
		if force {
			mode = "[red]force[white]"
		}
		status.SetText(fmt.Sprintf("[gray]Space toggles, a selects all, n selects none, f toggles mode, u uninstalls, q quits.  Mode: %s", mode))
	}
	for i := range entries {
		refreshRow(i)
	}
	refreshStatus()

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
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
				for i, chosen := range selected {
					if chosen {
						packages = append(packages, entries[i].Name)
					}
				}
				if len(packages) == 0 {
					status.SetText("[yellow]Select at least one package before uninstalling.[white]")
					return nil
				}
				confirmed = true
				app.Stop()
				return nil
			}
		}
		return event
	})

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(status, 1, 0, false)
	if err := app.SetRoot(flex, true).SetFocus(table).Run(); err != nil {
		return nil, force, false, err
	}
	return packages, force, confirmed, nil
}
