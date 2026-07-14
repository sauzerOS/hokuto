package hokuto

import (
	"archive/tar"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*f = append(*f, value)
	return nil
}

type unmanagedOptions struct {
	CheckChecksums bool
	BackupPath     string
	RestorePath    string
	ExtraPaths     []string
}

type unmanagedEntry struct {
	Path   string
	Reason string
	Size   int64
}

type selectableEntry struct {
	Primary string
	Size    int64
	Meta    string
}

func selectableEntryMatches(entry selectableEntry, query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	return query == "" || strings.Contains(strings.ToLower(entry.Primary), query)
}

func selectableEntryColors(entry selectableEntry) (tcell.Color, tcell.Color) {
	switch {
	case strings.HasPrefix(entry.Meta, "modified:"):
		return tcell.ColorYellow, tcell.ColorRed
	case entry.Meta == "unmanaged":
		return tcell.ColorLightCyan, tcell.ColorAqua
	case entry.Meta == "extra":
		return tcell.ColorLightGoldenrodYellow, tcell.ColorYellow
	case entry.Meta == "archive":
		return tcell.ColorLightGreen, tcell.ColorGreen
	default:
		return tcell.ColorWhite, tcell.ColorGray
	}
}

func normalizeTrackedPath(root, path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" || strings.HasSuffix(path, "/") {
		return "", false
	}

	clean := filepath.ToSlash(filepath.Clean(canonicalizePath(root, path)))
	if clean == "/etc" || clean == "/usr" || strings.HasPrefix(clean, "/etc/") || strings.HasPrefix(clean, "/usr/") {
		return clean, true
	}
	return "", false
}

func manifestLineChecksum(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasSuffix(line, "/") {
		return ""
	}
	idx := strings.LastIndexAny(line, " \t")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx:])
}

func loadOwnedSystemFiles(root string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]struct{}{}, nil
		}
		return nil, fmt.Errorf("failed to read installed package db: %w", err)
	}

	owned := make(map[string]struct{})
	var ownedMu sync.Mutex

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	if len(entries) > 0 && workers > len(entries) {
		workers = len(entries)
	}

	jobs := make(chan os.DirEntry, workers)
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make(map[string]struct{})
			for entry := range jobs {
				if !entry.IsDir() {
					continue
				}
				manifestPath := filepath.Join(Installed, entry.Name(), "manifest")
				if err := collectOwnedManifestPaths(root, manifestPath, local); err != nil {
					errOnce.Do(func() { firstErr = err })
				}
			}

			ownedMu.Lock()
			for path := range local {
				owned[path] = struct{}{}
			}
			ownedMu.Unlock()
		}()
	}

	for _, entry := range entries {
		jobs <- entry
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	return owned, nil
}

func collectOwnedManifestPaths(root, manifestPath string, owned map[string]struct{}) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to open manifest %s: %w", manifestPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		path := parseManifestFilePath(scanner.Text())
		if normalized, ok := normalizeTrackedPath(root, path); ok {
			owned[normalized] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan manifest %s: %w", manifestPath, err)
	}
	return nil
}

func scanUnmanagedSystemFiles(root string, owned map[string]struct{}) ([]unmanagedEntry, error) {
	var unmanaged []unmanagedEntry
	for _, scanRoot := range []string{"etc", "usr"} {
		absRoot := filepath.Join(root, scanRoot)
		if _, err := os.Lstat(absRoot); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to access %s: %w", absRoot, err)
		}

		err := filepath.WalkDir(absRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				debugf("Skipping unmanaged scan path %s: %v\n", path, err)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			trackedPath := "/" + filepath.ToSlash(rel)
			canonicalPath := filepath.ToSlash(filepath.Clean(canonicalizePath(root, trackedPath)))
			if _, ok := owned[canonicalPath]; !ok {
				size := int64(0)
				if info, err := entry.Info(); err == nil {
					size = info.Size()
				}
				unmanaged = append(unmanaged, unmanagedEntry{Path: trackedPath, Reason: "unmanaged", Size: size})
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan %s: %w", absRoot, err)
		}
	}

	sortUnmanagedEntries(unmanaged)
	return unmanaged, nil
}

func scanModifiedManifestFiles(root string) ([]unmanagedEntry, error) {
	entries, err := os.ReadDir(Installed)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read installed package db: %w", err)
	}

	var modified []unmanagedEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(Installed, entry.Name(), "manifest")
		file, err := os.Open(manifestPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to open manifest %s: %w", manifestPath, err)
		}

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			manifestPath := parseManifestFilePath(line)
			expected := manifestLineChecksum(line)
			if manifestPath == "" || expected == "" || expected == "000000" {
				continue
			}
			normalized, ok := normalizeTrackedPath(root, manifestPath)
			if !ok {
				continue
			}
			diskPath := manifestPathOnDisk(root, normalized)
			info, err := os.Lstat(diskPath)
			if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			got, err := ComputeChecksum(diskPath, UserExec)
			if err != nil {
				debugf("Skipping checksum comparison for %s: %v\n", normalized, err)
				continue
			}
			if got != expected {
				modified = append(modified, unmanagedEntry{Path: normalized, Reason: "modified:" + entry.Name(), Size: info.Size()})
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to scan manifest %s: %w", manifestPath, err)
		}
		file.Close()
	}

	sortUnmanagedEntries(modified)
	return modified, nil
}

func addExtraBackupPaths(root string, entries []unmanagedEntry, extraPaths []string) ([]unmanagedEntry, error) {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Path] = true
	}

	for _, extra := range extraPaths {
		extra = strings.TrimSpace(extra)
		if extra == "" {
			continue
		}
		abs := extra
		if !filepath.IsAbs(abs) {
			cwd, err := os.Getwd()
			if err != nil {
				return nil, err
			}
			abs = filepath.Join(cwd, abs)
		}
		if info, err := os.Lstat(abs); err != nil {
			return nil, fmt.Errorf("failed to access extra path %s: %w", extra, err)
		} else if !info.IsDir() {
			entryPath, err := displayPathForDiskPath(root, abs)
			if err != nil {
				return nil, err
			}
			if !seen[entryPath] {
				entries = append(entries, unmanagedEntry{Path: entryPath, Reason: "extra", Size: info.Size()})
				seen[entryPath] = true
			}
			continue
		}

		err := filepath.WalkDir(abs, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				debugf("Skipping extra path %s: %v\n", path, err)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			entryPath, err := displayPathForDiskPath(root, path)
			if err != nil {
				return nil
			}
			if !seen[entryPath] {
				size := int64(0)
				if info, err := entry.Info(); err == nil {
					size = info.Size()
				}
				entries = append(entries, unmanagedEntry{Path: entryPath, Reason: "extra", Size: size})
				seen[entryPath] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to scan extra path %s: %w", extra, err)
		}
	}

	sortUnmanagedEntries(entries)
	return entries, nil
}

func displayPathForDiskPath(root, abs string) (string, error) {
	abs = filepath.Clean(abs)
	root = filepath.Clean(root)
	if rel, err := filepath.Rel(root, abs); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
		return "/" + filepath.ToSlash(rel), nil
	}
	return filepath.ToSlash(abs), nil
}

func sortUnmanagedEntries(entries []unmanagedEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Reason < entries[j].Reason
		}
		return entries[i].Path < entries[j].Path
	})
}

func unmanagedDisplayLines(entries []unmanagedEntry) []string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Reason == "" || entry.Reason == "unmanaged" {
			lines = append(lines, entry.Path)
		} else {
			lines = append(lines, fmt.Sprintf("%s  [%s]", entry.Path, entry.Reason))
		}
	}
	return lines
}

func archiveNameForDisplayPath(path string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(path)), "/")
}

type commandReadCloser struct {
	io.Reader
	wait func() error
}

func (r *commandReadCloser) Close() error {
	if r.wait == nil {
		return nil
	}
	return r.wait()
}

func openBackupFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err == nil {
		return file, nil
	}

	if os.IsPermission(err) && os.Geteuid() != 0 {
		if _, lookErr := exec.LookPath("run0"); lookErr != nil {
			return nil, err
		}
		cmd := exec.Command("run0", "--pipe", "cat", path)
		stdout, pipeErr := cmd.StdoutPipe()
		if pipeErr != nil {
			return nil, pipeErr
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if startErr := cmd.Start(); startErr != nil {
			return nil, startErr
		}
		return &commandReadCloser{
			Reader: stdout,
			wait: func() error {
				if waitErr := cmd.Wait(); waitErr != nil {
					msg := strings.TrimSpace(stderr.String())
					if msg != "" {
						return fmt.Errorf("%w: %s", waitErr, msg)
					}
					return waitErr
				}
				return nil
			},
		}, nil
	}

	return nil, err
}

func writeBackupArchive(root, archivePath string, entries []unmanagedEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("no files selected")
	}
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o755); err != nil && filepath.Dir(archivePath) != "." {
		return err
	}

	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer out.Close()

	zw, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	defer zw.Close()

	tw := tar.NewWriter(zw)
	defer tw.Close()

	for _, entry := range entries {
		diskPath := manifestPathOnDisk(root, entry.Path)
		info, err := os.Lstat(diskPath)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", entry.Path, err)
		}

		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(diskPath)
			if err != nil {
				return fmt.Errorf("failed to read symlink %s: %w", entry.Path, err)
			}
		}
		header, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return fmt.Errorf("failed to create archive header for %s: %w", entry.Path, err)
		}
		header.Name = archiveNameForDisplayPath(entry.Path)
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write archive header for %s: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		in, err := openBackupFile(diskPath)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", entry.Path, err)
		}
		if _, err := io.Copy(tw, in); err != nil {
			in.Close()
			return fmt.Errorf("failed to archive %s: %w", entry.Path, err)
		}
		if err := in.Close(); err != nil {
			return fmt.Errorf("failed to archive %s: %w", entry.Path, err)
		}
	}

	return nil
}

func listBackupArchive(archivePath string) ([]unmanagedEntry, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var entries []unmanagedEntry
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.FileInfo().IsDir() {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return nil, fmt.Errorf("unsafe archive path: %s", header.Name)
		}
		entries = append(entries, unmanagedEntry{Path: "/" + clean, Reason: "archive", Size: header.Size})
	}
	sortUnmanagedEntries(entries)
	return entries, nil
}

func restoreBackupArchive(root, archivePath string, selected map[string]bool) error {
	if len(selected) == 0 {
		return fmt.Errorf("no files selected")
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		displayPath := "/" + clean
		if !selected[displayPath] {
			continue
		}
		if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return fmt.Errorf("unsafe archive path: %s", header.Name)
		}

		dest := filepath.Join(root, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(header.Mode)
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
			if err != nil {
				return fmt.Errorf("failed to restore %s: %w", displayPath, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("failed to restore %s: %w", displayPath, err)
			}
			if err := out.Close(); err != nil {
				return err
			}
			_ = os.Chmod(dest, mode.Perm())
		case tar.TypeSymlink:
			_ = os.Remove(dest)
			if err := os.Symlink(header.Linkname, dest); err != nil {
				return fmt.Errorf("failed to restore symlink %s: %w", displayPath, err)
			}
		default:
			debugf("Skipping unsupported archive entry %s type %c\n", displayPath, header.Typeflag)
		}
	}
	return nil
}

func selectEntries(title, footerText string, actionKey rune, initiallySelected bool, entries []selectableEntry, action func([]int) error) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("interactive selection requires a terminal")
	}
	if len(entries) == 0 {
		return fmt.Errorf("no entries available for selection")
	}

	selected := make([]bool, len(entries))
	for i := range selected {
		selected[i] = initiallySelected
	}

	app := tview.NewApplication()
	table := tview.NewTable().SetSelectable(true, false).SetFixed(0, 0)
	table.SetBorder(true).SetTitle(" " + title + " ")
	var visibleIndices []int
	searchQuery := ""
	searching := false

	refreshRow := func(row, entryIndex int) {
		mark := "[ ]"
		markColor := tcell.ColorGray
		if selected[entryIndex] {
			mark = "[X]"
			markColor = tcell.ColorGreen
		}
		meta := entries[entryIndex].Meta
		if meta == "" {
			meta = "file"
		}
		primaryColor, metaColor := selectableEntryColors(entries[entryIndex])
		size := humanReadableSize(entries[entryIndex].Size)
		table.SetCell(row, 0, tview.NewTableCell(tview.Escape(mark)).SetTextColor(markColor).SetExpansion(0))
		table.SetCell(row, 1, tview.NewTableCell(entries[entryIndex].Primary).SetTextColor(primaryColor).SetExpansion(1))
		table.SetCell(row, 2, tview.NewTableCell(size).SetTextColor(tcell.ColorYellow).SetExpansion(0).SetAlign(tview.AlignRight))
		table.SetCell(row, 3, tview.NewTableCell(meta).SetTextColor(metaColor).SetExpansion(0))
	}
	refresh := func() {
		table.Clear()
		visibleIndices = visibleIndices[:0]
		for i := range entries {
			if !selectableEntryMatches(entries[i], searchQuery) {
				continue
			}
			row := len(visibleIndices)
			visibleIndices = append(visibleIndices, i)
			refreshRow(row, i)
		}
	}
	refresh()

	status := tview.NewTextView().SetDynamicColors(true).SetTextAlign(tview.AlignCenter)
	status.SetText(footerText)
	searchInput := tview.NewInputField().SetLabel("Search: ")
	bottomPages := tview.NewPages().
		AddPage("status", status, true, true).
		AddPage("search", searchInput, true, false)
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
		status.SetText(footerText)
	})

	var actionErr error
	runAction := func() {
		var chosen []int
		for i, ok := range selected {
			if ok {
				chosen = append(chosen, i)
			}
		}
		if err := action(chosen); err != nil {
			actionErr = err
			status.SetText("[red]" + err.Error())
			return
		}
		actionErr = nil
		app.Stop()
	}

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if searching {
			return event
		}
		switch event.Key() {
		case tcell.KeyEsc, tcell.KeyCtrlQ:
			app.Stop()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case '/':
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
					selected[entryIndex] = !selected[entryIndex]
					refreshRow(row, entryIndex)
				}
				return nil
			case 'a':
				for row, entryIndex := range visibleIndices {
					selected[entryIndex] = true
					refreshRow(row, entryIndex)
				}
				return nil
			case 'n':
				for row, entryIndex := range visibleIndices {
					selected[entryIndex] = false
					refreshRow(row, entryIndex)
				}
				return nil
			case actionKey:
				runAction()
				return nil
			}
		}
		return event
	})

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(table, 0, 1, true).
		AddItem(bottomPages, 2, 0, false)

	if err := app.SetRoot(flex, true).SetFocus(table).Run(); err != nil {
		return err
	}
	return actionErr
}

func selectUnmanagedEntries(title, footerText string, actionKey rune, initiallySelected bool, entries []unmanagedEntry, action func([]unmanagedEntry) error) error {
	displayEntries := make([]selectableEntry, len(entries))
	for i, entry := range entries {
		displayEntries[i] = selectableEntry{
			Primary: entry.Path,
			Size:    entry.Size,
			Meta:    entry.Reason,
		}
	}
	return selectEntries(title, footerText, actionKey, initiallySelected, displayEntries, func(indices []int) error {
		chosen := make([]unmanagedEntry, 0, len(indices))
		for _, idx := range indices {
			chosen = append(chosen, entries[idx])
		}
		return action(chosen)
	})
}

func deleteUnmanagedEntries(root string, entries []unmanagedEntry, execCtx *Executor) error {
	if len(entries) == 0 {
		return fmt.Errorf("no files selected")
	}
	for _, entry := range entries {
		diskPath := manifestPathOnDisk(root, entry.Path)
		if err := removeFileAsRoot(diskPath, execCtx); err != nil {
			return fmt.Errorf("failed to delete %s: %w", entry.Path, err)
		}
	}
	return nil
}

func handleUnmanagedCommand(cfg *Config, opts unmanagedOptions) error {
	root := "/"
	if cfg != nil && cfg.Values["HOKUTO_ROOT"] != "" {
		root = cfg.Values["HOKUTO_ROOT"]
	} else if rootDir != "" {
		root = rootDir
	}

	if opts.BackupPath != "" && opts.RestorePath != "" {
		return fmt.Errorf("--backup and --restore cannot be used together")
	}

	if opts.RestorePath != "" {
		entries, err := listBackupArchive(opts.RestorePath)
		if err != nil {
			return err
		}
		return selectUnmanagedEntries("Restore Backup", "[gray]Space toggles, a selects all, n selects none, / searches, r restores, q quits.[white]", 'r', true, entries, func(chosen []unmanagedEntry) error {
			selected := make(map[string]bool, len(chosen))
			for _, entry := range chosen {
				selected[entry.Path] = true
			}
			if err := restoreBackupArchive(root, opts.RestorePath, selected); err != nil {
				return err
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Restored %d file(s) from %s\n", len(chosen), opts.RestorePath)
			return nil
		})
	}

	colArrow.Print("-> ")
	colSuccess.Println("Loading installed package manifests")
	owned, err := loadOwnedSystemFiles(root)
	if err != nil {
		return err
	}

	colArrow.Print("-> ")
	colSuccess.Println("Scanning unmanaged files in /etc and /usr")
	entries, err := scanUnmanagedSystemFiles(root, owned)
	if err != nil {
		return err
	}

	if opts.CheckChecksums {
		colArrow.Print("-> ")
		colSuccess.Println("Checking installed file checksums")
		modified, err := scanModifiedManifestFiles(root)
		if err != nil {
			return err
		}
		entries = append(entries, modified...)
		sortUnmanagedEntries(entries)
	}

	if len(opts.ExtraPaths) > 0 {
		entries, err = addExtraBackupPaths(root, entries, opts.ExtraPaths)
		if err != nil {
			return err
		}
	}

	if len(entries) == 0 {
		colSuccess.Println("No unmanaged files found in /etc or /usr.")
		return nil
	}

	if opts.BackupPath != "" {
		return selectUnmanagedEntries("Unmanaged Backup", "[gray]Space toggles, a selects all, n selects none, / searches, b backs up, q quits.[white]", 'b', true, entries, func(chosen []unmanagedEntry) error {
			if err := writeBackupArchive(root, opts.BackupPath, chosen); err != nil {
				return err
			}
			colArrow.Print("-> ")
			colSuccess.Printf("Backed up %d file(s) to %s\n", len(chosen), opts.BackupPath)
			return nil
		})
	}

	colWarn.Printf("Found %d unmanaged/modified file(s) in /etc and /usr.\n", len(entries))
	return selectUnmanagedEntries("Unmanaged Files", "[gray]Space toggles, a selects all, n selects none, / searches, d deletes selected files, q quits.[white]", 'd', false, entries, func(chosen []unmanagedEntry) error {
		if err := deleteUnmanagedEntries(root, chosen, RootExec); err != nil {
			return err
		}
		colArrow.Print("-> ")
		colSuccess.Printf("Deleted %d selected file(s)\n", len(chosen))
		return nil
	})
}
