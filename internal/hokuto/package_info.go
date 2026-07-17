package hokuto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

const packageInfoStateFile = "var/db/hokuto/package-info-state.json"

type packageInfoStateEntry struct {
	Version   string `json:"version"`
	Read      bool   `json:"read,omitempty"`
	Dismissed bool   `json:"dismissed,omitempty"`
}

type packageInfoState struct {
	Packages map[string]packageInfoStateEntry `json:"packages"`
}

type installedPackageInfo struct {
	Name     string
	Version  string
	Info     string
	Read     bool
	Metadata PackageMetadata
}

var packageInfoReminderPending atomic.Bool

func packageInfoRoot(cfg *Config) string {
	if cfg != nil && cfg.Values["HOKUTO_ROOT"] != "" {
		return cfg.Values["HOKUTO_ROOT"]
	}
	if rootDir != "" {
		return rootDir
	}
	return "/"
}

func packageInfoStatePath(root string) string {
	return filepath.Join(root, packageInfoStateFile)
}

func loadPackageInfoState(root string) (*packageInfoState, error) {
	state := &packageInfoState{Packages: make(map[string]packageInfoStateEntry)}
	data, err := readFileAsRoot(packageInfoStatePath(root))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, state); err != nil {
			return nil, fmt.Errorf("failed to parse package info state: %w", err)
		}
	}
	if state.Packages == nil {
		state.Packages = make(map[string]packageInfoStateEntry)
	}
	return state, nil
}

func savePackageInfoState(root string, state *packageInfoState, execCtx *Executor) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := packageInfoStatePath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsPermission(err) {
		return err
	}
	return writeFileAsRoot(path, data, 0o644, execCtx)
}

func readInstalledMetadata(root, pkgName string, cfg *Config, allowDatabase bool) (PackageMetadata, bool) {
	metadataPath := filepath.Join(root, "var", "db", "hokuto", "installed", pkgName, "metadata.json")
	if data, err := readFileAsRoot(metadataPath); err == nil {
		var metadata PackageMetadata
		if json.Unmarshal(data, &metadata) == nil && hasMetadataEntry(&metadata) {
			return metadata, true
		}
	}
	if allowDatabase {
		if entry, found, err := lookupPackageMetadataDatabase(pkgName, cfg, true); err == nil && found {
			return entry.Metadata, hasMetadataEntry(&entry.Metadata)
		}
	}
	return PackageMetadata{}, false
}

func installedPackageInfoVersion(root, pkgName string) string {
	data, err := readFileAsRoot(filepath.Join(root, "var", "db", "hokuto", "installed", pkgName, "version"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func registerInstalledPackageInfo(root, pkgName string, cfg *Config) {
	metadata, found := readInstalledMetadata(root, pkgName, cfg, true)
	if !found || strings.TrimSpace(metadata.Info) == "" {
		return
	}
	metadataPath := filepath.Join(root, "var", "db", "hokuto", "installed", pkgName, "metadata.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		if data, marshalErr := json.MarshalIndent(metadata, "", "  "); marshalErr == nil {
			data = append(data, '\n')
			if writeErr := writeFileAsRoot(metadataPath, data, 0o644, RootExec); writeErr != nil {
				debugf("Failed to store resolved package metadata for %s: %v\n", pkgName, writeErr)
			}
		}
	}
	state, err := loadPackageInfoState(root)
	if err != nil {
		debugf("Failed to load package info state for %s: %v\n", pkgName, err)
		return
	}
	state.Packages[pkgName] = packageInfoStateEntry{Version: installedPackageInfoVersion(root, pkgName)}
	if err := savePackageInfoState(root, state, RootExec); err != nil {
		debugf("Failed to mark package info unread for %s: %v\n", pkgName, err)
		return
	}
	packageInfoReminderPending.Store(true)
}

func printPackageInfoReminderIfNeeded() {
	if !packageInfoReminderPending.Swap(false) {
		return
	}
	colArrow.Print("-> ")
	colSuccess.Println("Unread package info available, use hokuto info")
}

func collectInstalledPackageInfo(root string, cfg *Config, state *packageInfoState) ([]installedPackageInfo, error) {
	installedRoot := filepath.Join(root, "var", "db", "hokuto", "installed")
	entries, err := os.ReadDir(installedRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []installedPackageInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		metadata, found := readInstalledMetadata(root, name, cfg, true)
		if !found || strings.TrimSpace(metadata.Info) == "" {
			continue
		}
		version := installedPackageInfoVersion(root, name)
		stored := state.Packages[name]
		if stored.Dismissed && stored.Version == version {
			continue
		}
		result = append(result, installedPackageInfo{
			Name:     name,
			Version:  version,
			Info:     metadata.Info,
			Read:     stored.Read && stored.Version == version,
			Metadata: metadata,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Read != result[j].Read {
			return !result[i].Read
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func handlePackageInfoCommand(cfg *Config) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("package info viewer requires a terminal")
	}
	root := packageInfoRoot(cfg)
	state, err := loadPackageInfoState(root)
	if err != nil {
		return err
	}
	entries, err := collectInstalledPackageInfo(root, cfg, state)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		colInfo.Println("No installed package information is available.")
		return nil
	}

	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	table.SetBorder(true).SetTitle(" Installed Package Information ")
	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	status.SetText("[gray]Enter opens info, d deletes the notice, / searches, q quits.[white]")
	searchInput := tview.NewInputField().SetLabel("Search: ")
	bottomPages := tview.NewPages().
		AddPage("status", status, true, true).
		AddPage("search", searchInput, true, false)
	infoView := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetWrap(true)
	infoView.SetBorder(true).SetTitle(" Package Information ")
	pages := tview.NewPages().
		AddPage("list", table, true, true).
		AddPage("info", infoView, true, false)
	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(pages, 0, 1, true).
		AddItem(bottomPages, 2, 0, false)
	var visible []int
	searchQuery := ""
	searching := false
	showingInfo := false

	refresh := func() {
		table.Clear()
		table.SetCell(0, 0, tview.NewTableCell("").SetSelectable(false))
		table.SetCell(0, 1, tview.NewTableCell("Package").SetTextColor(tcell.ColorAqua).SetAttributes(tcell.AttrBold).SetSelectable(false))
		table.SetCell(0, 2, tview.NewTableCell("Status").SetTextColor(tcell.ColorAqua).SetAttributes(tcell.AttrBold).SetSelectable(false))
		visible = visible[:0]
		query := strings.ToLower(strings.TrimSpace(searchQuery))
		for idx, entry := range entries {
			if query != "" && !strings.Contains(strings.ToLower(entry.Name+" "+entry.Info), query) {
				continue
			}
			visible = append(visible, idx)
			row := len(visible)
			mark, label, markColor := "[ ]", "unread", tcell.ColorYellow
			if entry.Read {
				mark, label, markColor = "[X]", "read", tcell.ColorGreen
			}
			table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor))
			table.SetCell(row, 1, tview.NewTableCell(entry.Name).SetTextColor(tcell.ColorWhite).SetExpansion(1))
			table.SetCell(row, 2, tview.NewTableCell(label).SetTextColor(markColor))
		}
		if len(visible) > 0 {
			table.Select(1, 0)
		}
	}
	refresh()

	currentIndex := func() (int, bool) {
		row, _ := table.GetSelection()
		if row < 1 || row-1 >= len(visible) {
			return 0, false
		}
		return visible[row-1], true
	}
	saveEntryState := func(entry installedPackageInfo, read, dismissed bool) error {
		state.Packages[entry.Name] = packageInfoStateEntry{Version: entry.Version, Read: read, Dismissed: dismissed}
		return savePackageInfoState(root, state, RootExec)
	}
	openInfo := func(idx int) {
		entry := &entries[idx]
		if err := saveEntryState(*entry, true, false); err != nil {
			status.SetText("[red]" + tview.Escape(err.Error()) + "[white]")
			return
		}
		entry.Read = true
		content := fmt.Sprintf("[aqua::b]%s[-:-:-]\n[gray]Version %s[-]\n\n%s", tview.Escape(entry.Name), tview.Escape(entry.Version), tview.Escape(entry.Info))
		infoView.SetTitle(" Info: " + entry.Name + " (b/Esc returns) ")
		infoView.SetText(content).ScrollToBeginning()
		showingInfo = true
		pages.SwitchToPage("info")
		app.SetFocus(infoView)
		refresh()
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
		if searching {
			return event
		}
		if showingInfo {
			if event.Key() == tcell.KeyEsc || (event.Key() == tcell.KeyRune && (event.Rune() == 'b' || event.Rune() == 'q')) {
				showingInfo = false
				pages.SwitchToPage("list")
				app.SetFocus(table)
				return nil
			}
			return event
		}
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyEnter:
			if idx, ok := currentIndex(); ok {
				openInfo(idx)
			}
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				app.Stop()
			case '/':
				searching = true
				bottomPages.SwitchToPage("search")
				app.SetFocus(searchInput)
			case 'd':
				if idx, ok := currentIndex(); ok {
					entry := entries[idx]
					if err := saveEntryState(entry, entry.Read, true); err != nil {
						status.SetText("[red]" + tview.Escape(err.Error()) + "[white]")
						return nil
					}
					entries = append(entries[:idx], entries[idx+1:]...)
					refresh()
					if len(entries) == 0 {
						app.Stop()
					}
				}
			}
			return nil
		}
		return event
	})

	return app.SetRoot(layout, true).SetFocus(table).Run()
}
