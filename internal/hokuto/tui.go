package hokuto

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type logInfo struct {
	path         string
	content      string
	buildDir     string // Extracted build directory path
	canDelete    bool   // Whether this build directory can be deleted
	deleteAction string // The delete command to show
	modTime      time.Time
}

var (
	tuiApp          *tview.Application
	tuiLogs         []logInfo
	tuiActiveIdx    int
	tuiPrevPath     string // The log shown at the last draw, to detect switches
	tuiHeaderBox    *tview.TextView
	tuiLogView      *tview.TextView
	tuiFooterBox    *tview.TextView
	tuiSearchField  *tview.InputField
	tuiFlex         *tview.Flex
	tuiUpdateChan   chan []logInfo
	tuiPrevContent  map[string]string // Track previous content per log path
	tuiFollowLog    bool              // Follow new output until the user scrolls manually
	tuiSearchActive bool
	tuiSearchQuery  string
	tuiSearchStatus string
	tuiSearchRow    int
)

var tuiANSISequence = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

func runTUI() int {
	// Initialize channels and maps
	tuiUpdateChan = make(chan []logInfo, 10)
	tuiPrevContent = make(map[string]string)
	tuiPrevPath = ""
	tuiSearchActive = false
	tuiSearchQuery = ""
	tuiSearchStatus = ""
	tuiSearchRow = -1
	tuiFollowLog = true

	// Create the application
	tuiApp = tview.NewApplication()

	// Create header box with border
	tuiHeaderBox = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetTextAlign(tview.AlignLeft)
	tuiHeaderBox.SetBorder(true)
	tuiHeaderBox.SetTitle("hokuto Build Log Viewer")

	// Create log view (scrollable text view) with border
	// SetDynamicColors(true) enables ANSI color code support (both tview format and ANSI escape sequences)
	tuiLogView = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetScrollable(true)
	tuiLogView.SetBorder(true)

	// Create footer box with border
	tuiFooterBox = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetTextAlign(tview.AlignLeft)
	tuiFooterBox.SetBorder(true)
	tuiSearchField = tview.NewInputField().
		SetLabel("Search: ").
		SetFieldWidth(0)
	tuiSearchField.SetBorder(true)
	tuiSearchField.SetDoneFunc(func(key tcell.Key) {
		query := strings.TrimSpace(tuiSearchField.GetText())
		tuiSearchActive = false
		tuiFlex.ResizeItem(tuiSearchField, 0, 0)
		tuiApp.SetFocus(tuiLogView)
		if key == tcell.KeyEnter && query != "" {
			if query != tuiSearchQuery {
				tuiSearchRow = -1
			}
			tuiSearchQuery = query
			findTUILogMatch(1, true)
		}
		updateTUI()
	})

	// Create flex layout: header (fixed) + log (flexible) + footer (fixed)
	tuiFlex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tuiHeaderBox, 3, 0, false). // Header: 3 lines (title + info + border)
		AddItem(tuiLogView, 0, 1, true).    // Log: flexible, takes remaining space
		AddItem(tuiSearchField, 0, 0, false).
		AddItem(tuiFooterBox, 5, 0, false)

	// Set up key handlers
	tuiFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if tuiSearchActive {
			return event
		}
		key := event.Key()
		rune := event.Rune()

		// Handle special keys
		switch key {
		case tcell.KeyCtrlQ, tcell.KeyEsc:
			tuiApp.Stop()
			return nil
		case tcell.KeyLeft:
			if len(tuiLogs) > 0 {
				tuiActiveIdx--
				if tuiActiveIdx < 0 {
					tuiActiveIdx = len(tuiLogs) - 1
				}
				tuiSearchRow = -1
				tuiSearchStatus = ""
				updateTUI()
			}
			return nil
		case tcell.KeyRight:
			if len(tuiLogs) > 0 {
				tuiActiveIdx++
				if tuiActiveIdx >= len(tuiLogs) {
					tuiActiveIdx = 0
				}
				tuiSearchRow = -1
				tuiSearchStatus = ""
				updateTUI()
			}
			return nil
		case tcell.KeyHome:
			tuiFollowLog = false
			tuiLogView.ScrollToBeginning()
			return nil
		case tcell.KeyEnd:
			tuiFollowLog = true
			tuiLogView.ScrollToEnd()
			return nil
		case tcell.KeyUp:
			// Scroll log view up
			tuiFollowLog = false
			row, _ := tuiLogView.GetScrollOffset()
			if row > 0 {
				tuiLogView.ScrollTo(row-1, 0)
			}
			return nil
		case tcell.KeyDown:
			// Scroll log view down
			tuiFollowLog = false
			row, _ := tuiLogView.GetScrollOffset()
			tuiLogView.ScrollTo(row+1, 0)
			return nil
		case tcell.KeyPgUp:
			tuiFollowLog = false
			row, _ := tuiLogView.GetScrollOffset()
			if row > 10 {
				tuiLogView.ScrollTo(row-10, 0)
			} else {
				tuiLogView.ScrollToBeginning()
			}
			return nil
		case tcell.KeyPgDn:
			tuiFollowLog = false
			row, _ := tuiLogView.GetScrollOffset()
			tuiLogView.ScrollTo(row+10, 0)
			return nil
		case tcell.KeyRune:
			// Handle rune keys
			switch rune {
			case '/':
				openTUISearch()
				return nil
			case 'n':
				findTUILogMatch(1, false)
				updateTUI()
				return nil
			case 'N':
				findTUILogMatch(-1, false)
				updateTUI()
				return nil
			case 'q':
				tuiApp.Stop()
				return nil
			case 'd':
				if tuiActiveIdx < len(tuiLogs) {
					log := tuiLogs[tuiActiveIdx]
					if log.canDelete {
						os.RemoveAll(log.buildDir)
						// Refresh logs
						go func() {
							logs := readAllBuildLogs()
							tuiUpdateChan <- logs
						}()
					}
				}
				return nil
			case 'o':
				if tuiActiveIdx < len(tuiLogs) {
					log := tuiLogs[tuiActiveIdx]
					cmd := exec.Command("code", log.path)
					_ = cmd.Start()
				}
				return nil
			case 'h':
				if len(tuiLogs) > 0 {
					tuiActiveIdx--
					if tuiActiveIdx < 0 {
						tuiActiveIdx = len(tuiLogs) - 1
					}
					tuiSearchRow = -1
					tuiSearchStatus = ""
					updateTUI()
				}
				return nil
			case 'l':
				if len(tuiLogs) > 0 {
					tuiActiveIdx++
					if tuiActiveIdx >= len(tuiLogs) {
						tuiActiveIdx = 0
					}
					tuiSearchRow = -1
					tuiSearchStatus = ""
					updateTUI()
				}
				return nil
			}
		}
		return event
	})

	// Start log update goroutine
	go func() {
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			logs := readAllBuildLogs()
			select {
			case tuiUpdateChan <- logs:
			default:
			}
		}
	}()

	// Start update handler goroutine
	go func() {
		for logs := range tuiUpdateChan {
			tuiApp.QueueUpdateDraw(func() {
				// Keep all shared TUI state on the application goroutine so search,
				// scrolling, and periodic refreshes cannot race each other.
				var currentLogPath string
				if tuiActiveIdx < len(tuiLogs) {
					currentLogPath = tuiLogs[tuiActiveIdx].path
				}
				tuiLogs = logs
				tuiActiveIdx = tuiSelectLog(tuiLogs, currentLogPath)
				updateTUI()
			})
		}
	}()

	// Set root first
	tuiApp.SetRoot(tuiFlex, true).SetFocus(tuiLogView)

	// Populate the first view on the application event loop. Writing through
	// ANSIWriter before Run initialized the screen could leave the first rows
	// unpainted until a later scroll forced another draw.
	tuiLogs = readAllBuildLogs()
	tuiActiveIdx = tuiSelectLog(tuiLogs, "")
	go tuiApp.QueueUpdateDraw(updateTUI)

	// Run the application
	if err := tuiApp.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		return 1
	}
	return 0
}

func updateTUI() {
	if tuiApp == nil || tuiHeaderBox == nil || tuiLogView == nil || tuiFooterBox == nil {
		return
	}

	// Update header
	var headerText strings.Builder
	if len(tuiLogs) == 0 {
		headerText.WriteString("[gray]No build logs found[white]")
	} else if tuiActiveIdx < len(tuiLogs) {
		log := tuiLogs[tuiActiveIdx]
		titleText := fmt.Sprintf("Build Log %d/%d: %s", tuiActiveIdx+1, len(tuiLogs), log.path)
		if log.canDelete {
			titleText += fmt.Sprintf(" | [red]Press 'd' to delete: %s[white]", log.deleteAction)
		}
		headerText.WriteString(fmt.Sprintf("[gray]%s[white]", titleText))
	} else {
		headerText.WriteString("[gray]No active log[white]")
	}
	tuiHeaderBox.SetText(headerText.String())

	// Update log content
	if len(tuiLogs) == 0 {
		tuiLogView.SetText("No build log yet. Run 'hokuto build <package>' to start a build.")
	} else if tuiActiveIdx < len(tuiLogs) {
		log := tuiLogs[tuiActiveIdx]
		logPath := log.path
		prevContent, hadPrevContent := tuiPrevContent[logPath]

		// Detect if we switched tabs: by the log, as its place in the list
		// changes when another build starts or ends.
		switchedTabs := tuiPrevPath != logPath
		if switchedTabs {
			tuiPrevPath = logPath
		}

		// Only update if content actually changed or we switched tabs
		if log.content != prevContent || switchedTabs {
			// Save current scroll position before clearing
			row, _ := tuiLogView.GetScrollOffset()

			// Clear the view first
			tuiLogView.Clear()
			// Use ANSIWriter to convert ANSI escape sequences to tview color tags
			ansiWriter := tview.ANSIWriter(tuiLogView)
			ansiWriter.Write(sanitizeTerminalLog([]byte(log.content)))

			// Render a newly opened log from the beginning once; scrolling to the end
			// during its initial draw can leave the top viewport incompletely painted.
			// Follow remains armed, so the next content update moves to the end.
			// Manual navigation disables following and preserves the exact viewport
			// until End explicitly resumes it.
			if switchedTabs && !hadPrevContent {
				tuiLogView.ScrollToBeginning()
			} else if tuiFollowLog {
				tuiLogView.ScrollToEnd()
			} else if hadPrevContent {
				tuiLogView.ScrollTo(row, 0)
			}

			tuiPrevContent[logPath] = log.content
		}
	} else {
		tuiLogView.SetText("")
	}

	// Update footer
	var footerSegments []string
	footerSegments = append(footerSegments, "Press 'q' or Ctrl+Q to quit")
	footerSegments = append(footerSegments, "← → (or h/l) to switch panes")
	footerSegments = append(footerSegments, "↑ ↓ to scroll")
	footerSegments = append(footerSegments, "Home/End to jump to start/end")
	if tuiFollowLog {
		footerSegments = append(footerSegments, "Follow: on")
	} else {
		footerSegments = append(footerSegments, "Follow: off (End resumes)")
	}
	footerSegments = append(footerSegments, "/ search, n/N next/previous")
	if tuiSearchQuery != "" {
		searchInfo := fmt.Sprintf("Search: %s", tuiSearchQuery)
		if tuiSearchStatus != "" {
			searchInfo += " (" + tuiSearchStatus + ")"
		}
		footerSegments = append(footerSegments, searchInfo)
	}
	footerSegments = append(footerSegments, "'o' to open in VS Code")
	if len(tuiLogs) > 0 && tuiActiveIdx < len(tuiLogs) && tuiLogs[tuiActiveIdx].canDelete {
		footerSegments = append(footerSegments, "'d' to delete")
	}
	footerText := strings.Join(footerSegments, " | ")
	tuiFooterBox.SetText(fmt.Sprintf("[gray]%s[white]", footerText))
}

func openTUISearch() {
	if tuiSearchField == nil || tuiFlex == nil || tuiApp == nil {
		return
	}
	tuiSearchActive = true
	tuiSearchField.SetText(tuiSearchQuery)
	tuiFlex.ResizeItem(tuiSearchField, 3, 0)
	tuiApp.SetFocus(tuiSearchField)
}

func findTUILogMatch(direction int, includeCurrent bool) bool {
	if tuiSearchQuery == "" || tuiLogView == nil || tuiActiveIdx >= len(tuiLogs) {
		return false
	}
	matches := matchingLogRows(tuiLogs[tuiActiveIdx].content, tuiSearchQuery)
	if len(matches) == 0 {
		tuiSearchStatus = "not found"
		return false
	}

	current, _ := tuiLogView.GetScrollOffset()
	if !includeCurrent && tuiSearchRow >= 0 {
		current = tuiSearchRow
	}
	selected := -1
	if direction >= 0 {
		for i, row := range matches {
			if row > current || (includeCurrent && row == current) {
				selected = i
				break
			}
		}
		if selected < 0 {
			selected = 0
		}
	} else {
		for i := len(matches) - 1; i >= 0; i-- {
			row := matches[i]
			if row < current || (includeCurrent && row == current) {
				selected = i
				break
			}
		}
		if selected < 0 {
			selected = len(matches) - 1
		}
	}
	tuiLogView.ScrollTo(matches[selected], 0)
	tuiFollowLog = false
	tuiSearchRow = matches[selected]
	tuiSearchStatus = fmt.Sprintf("match %d/%d", selected+1, len(matches))
	return true
}

func matchingLogRows(content, query string) []int {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	matches := make([]int, 0)
	for row, line := range lines {
		plain := tuiANSISequence.ReplaceAllString(line, "")
		if strings.Contains(strings.ToLower(plain), query) {
			matches = append(matches, row)
		}
	}
	return matches
}

func readAllBuildLogs() []logInfo {
	// Determine config file path based on HOKUTO_ROOT env variable
	configPath := ConfigFile
	if hokutoRoot := os.Getenv("HOKUTO_ROOT"); hokutoRoot != "" {
		configPath = filepath.Join(hokutoRoot, "etc", "hokuto", "hokuto.conf")
	}

	// Parse config to get TMPDIR and TMPDIR2
	cfg, err := loadConfig(configPath)
	if err != nil {
		return []logInfo{{path: "Error", content: fmt.Sprintf("Failed to load config: %v", err)}}
	}

	// Get HOKUTO_ROOT if set
	hokutoRoot := os.Getenv("HOKUTO_ROOT")

	tmpDir1 := cfg.Values["TMPDIR"]
	if tmpDir1 == "" {
		tmpDir1 = "/tmp"
	}
	// Prepend HOKUTO_ROOT if set
	if hokutoRoot != "" {
		tmpDir1 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir1, "/"))
	}

	tmpDir2 := cfg.Values["TMPDIR2"]
	if tmpDir2 == "" {
		tmpDir2 = "/var/tmpdir"
	}
	// Prepend HOKUTO_ROOT if set
	if hokutoRoot != "" {
		tmpDir2 = filepath.Join(hokutoRoot, strings.TrimPrefix(tmpDir2, "/"))
	}

	// Scan both directories for build logs
	var allPaths []string

	// Scan TMPDIR
	paths1, _ := filepath.Glob(filepath.Join(tmpDir1, "*", "log", "build-log.txt"))
	allPaths = append(allPaths, paths1...)

	// Scan TMPDIR2
	paths2, _ := filepath.Glob(filepath.Join(tmpDir2, "*", "log", "build-log.txt"))
	allPaths = append(allPaths, paths2...)

	if len(allPaths) == 0 {
		return []logInfo{{path: "No logs", content: "No build log yet. Run 'hokuto build <package>' to see logs here."}}
	}

	// A fixed order, by path: ordered by last write, the logs of parallel
	// builds swapped places at every refresh.
	sort.Strings(allPaths)

	// Read all logs (read entire file for infinite scrollback)
	logs := make([]logInfo, 0, len(allPaths))
	for _, path := range allPaths {
		content, err := readFullFile(path)
		if err != nil {
			content = fmt.Sprintf("failed to read log: %v", err)
		}

		// Extract build directory from log path
		// e.g., /var/tmpdir/hokuto/llvm/log/build-log.txt -> /var/tmpdir/hokuto/llvm/
		buildDir := extractBuildDir(path)
		canDelete, deleteAction := canDeleteBuildDir(buildDir, content)
		var modTime time.Time
		if info, err := os.Stat(path); err == nil {
			modTime = info.ModTime()
		}

		logs = append(logs, logInfo{
			path:         path,
			content:      content,
			buildDir:     buildDir,
			canDelete:    canDelete,
			deleteAction: deleteAction,
			modTime:      modTime,
		})
	}

	return logs
}

// tuiSelectLog returns the log to show after a refresh: the one shown before,
// wherever it now is in the list, or, once its build tree is gone (the build
// ended) and at start, the log written last.
func tuiSelectLog(logs []logInfo, currentPath string) int {
	newest := 0
	for i, log := range logs {
		if currentPath != "" && log.path == currentPath {
			return i
		}
		if log.modTime.After(logs[newest].modTime) {
			newest = i
		}
	}
	return newest
}

// extractBuildDir extracts the build directory from a log file path
// e.g., /var/tmpdir/hokuto/llvm/log/build-log.txt -> /var/tmpdir/hokuto/llvm/
func extractBuildDir(logPath string) string {
	// Remove /log/build-log.txt from the path
	dir := filepath.Dir(logPath) // Gets .../llvm/log
	dir = filepath.Dir(dir)      // Gets .../llvm
	return dir
}

// canDeleteBuildDir reports whether a build tree may be deleted, and the
// command shown for it: only once hokuto has marked its build failed. A
// build that writes nothing for a while (a long link) is still running, and
// a successful build removes its tree itself.
func canDeleteBuildDir(buildDir, logContent string) (bool, string) {
	if _, err := os.Stat(buildDir); err != nil {
		return false, ""
	}
	if !buildLogFailed(logContent) {
		return false, ""
	}
	return true, fmt.Sprintf("rm -rf %s", buildDir)
}

// buildLogFailed reports whether the last status line of a build log, which
// hokuto appends when a build ends (appendBuildLogStatus), says it failed.
func buildLogFailed(content string) bool {
	text := strings.TrimRight(tuiANSISequence.ReplaceAllString(content, ""), " \t\r\n")
	last := text[strings.LastIndexAny(text, "\r\n")+1:]
	return strings.HasPrefix(last, ">>> ") && strings.Contains(last, ": Build failed at ")
}

// readFullFile reads the entire file for infinite scrollback support
func readFullFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
