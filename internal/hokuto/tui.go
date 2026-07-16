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
}

var (
	tuiApp          *tview.Application
	tuiLogs         []logInfo
	tuiActiveIdx    int
	tuiPrevIdx      int // Track previous index to detect tab switches
	tuiHeaderBox    *tview.TextView
	tuiLogView      *tview.TextView
	tuiFooterBox    *tview.TextView
	tuiSearchField  *tview.InputField
	tuiFlex         *tview.Flex
	tuiUpdateChan   chan []logInfo
	tuiPrevContent  map[string]string // Track previous content per log path
	tuiShouldScroll bool              // Flag to force scroll to end on next update
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
	tuiPrevIdx = -1
	tuiSearchActive = false
	tuiSearchQuery = ""
	tuiSearchStatus = ""
	tuiSearchRow = -1

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
				tuiShouldScroll = true
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
				tuiShouldScroll = true
				tuiSearchRow = -1
				tuiSearchStatus = ""
				updateTUI()
			}
			return nil
		case tcell.KeyHome:
			tuiLogView.ScrollToBeginning()
			return nil
		case tcell.KeyEnd:
			tuiLogView.ScrollToEnd()
			return nil
		case tcell.KeyUp:
			// Scroll log view up
			row, _ := tuiLogView.GetScrollOffset()
			if row > 0 {
				tuiLogView.ScrollTo(row-1, 0)
			}
			return nil
		case tcell.KeyDown:
			// Scroll log view down
			row, _ := tuiLogView.GetScrollOffset()
			tuiLogView.ScrollTo(row+1, 0)
			return nil
		case tcell.KeyPgUp:
			row, _ := tuiLogView.GetScrollOffset()
			if row > 10 {
				tuiLogView.ScrollTo(row-10, 0)
			} else {
				tuiLogView.ScrollToBeginning()
			}
			return nil
		case tcell.KeyPgDn:
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
					tuiShouldScroll = true
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
					tuiShouldScroll = true
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
				if currentLogPath != "" {
					found := false
					for i, log := range tuiLogs {
						if log.path == currentLogPath {
							tuiActiveIdx = i
							found = true
							break
						}
					}
					if !found && tuiActiveIdx >= len(tuiLogs) && len(tuiLogs) > 0 {
						tuiActiveIdx = len(tuiLogs) - 1
					}
				}
				updateTUI()
			})
		}
	}()

	// Set root first
	tuiApp.SetRoot(tuiFlex, true).SetFocus(tuiLogView)

	// Populate the first view on the application event loop. Writing through
	// ANSIWriter before Run initialized the screen could leave the first rows
	// unpainted until a later scroll forced another draw.
	logs := readAllBuildLogs()
	tuiLogs = logs
	if len(tuiLogs) > 0 {
		tuiActiveIdx = 0
	}
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

		// Detect if we switched tabs
		switchedTabs := (tuiPrevIdx != tuiActiveIdx)
		if switchedTabs {
			tuiPrevIdx = tuiActiveIdx
		}

		// Only update if content actually changed or we switched tabs
		if log.content != prevContent || switchedTabs {
			// Save current scroll position before clearing
			row, _ := tuiLogView.GetScrollOffset()

			// Check if we're at the bottom (only relevant if not switching tabs)
			wasAtBottom := false
			if !switchedTabs && hadPrevContent {
				tuiLogView.ScrollTo(row+1, 0)
				newRow, _ := tuiLogView.GetScrollOffset()
				wasAtBottom = (newRow == row)
				tuiLogView.ScrollTo(row, 0)
			}

			// Clear the view first
			tuiLogView.Clear()
			// Use ANSIWriter to convert ANSI escape sequences to tview color tags
			ansiWriter := tview.ANSIWriter(tuiLogView)
			ansiWriter.Write(sanitizeTerminalLog([]byte(log.content)))

			// Scroll logic:
			// Newly opened logs must start at the first line. Previously this used
			// ScrollToEnd during the initial draw, which left the top viewport
			// incompletely painted until the user scrolled away and back.
			// 2. If content updated and we were at bottom, scroll to end
			// 3. Otherwise, try to maintain scroll position
			if switchedTabs {
				tuiLogView.ScrollToBeginning()
				tuiShouldScroll = false
			} else if tuiShouldScroll {
				tuiLogView.ScrollToEnd()
				tuiShouldScroll = false
			} else if wasAtBottom {
				tuiLogView.ScrollToEnd()
			} else if hadPrevContent {
				// Try to restore scroll position
				prevLines := strings.Count(prevContent, "\n")
				newLines := strings.Count(log.content, "\n")
				if newLines > prevLines {
					// Content grew, adjust scroll position
					linesAdded := newLines - prevLines
					tuiLogView.ScrollTo(row+linesAdded, 0)
				} else {
					// Try to restore exact position
					tuiLogView.ScrollTo(row, 0)
				}
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

	// Sort by modification time (newest first)
	sort.Slice(allPaths, func(i, j int) bool {
		ai, err1 := os.Stat(allPaths[i])
		aj, err2 := os.Stat(allPaths[j])
		if err1 != nil || err2 != nil {
			return allPaths[i] > allPaths[j]
		}
		return ai.ModTime().After(aj.ModTime())
	})

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
		canDelete, deleteAction := canDeleteBuildDir(buildDir)

		logs = append(logs, logInfo{
			path:         path,
			content:      content,
			buildDir:     buildDir,
			canDelete:    canDelete,
			deleteAction: deleteAction,
		})
	}

	return logs
}

// extractBuildDir extracts the build directory from a log file path
// e.g., /var/tmpdir/hokuto/llvm/log/build-log.txt -> /var/tmpdir/hokuto/llvm/
func extractBuildDir(logPath string) string {
	// Remove /log/build-log.txt from the path
	dir := filepath.Dir(logPath) // Gets .../llvm/log
	dir = filepath.Dir(dir)      // Gets .../llvm
	return dir
}

// canDeleteBuildDir checks if a build directory can be deleted
// Returns (canDelete, deleteAction)
// Can delete if the directory hasn't been modified in the last 5 minutes
func canDeleteBuildDir(buildDir string) (bool, string) {
	info, err := os.Stat(buildDir)
	if err != nil {
		return false, ""
	}

	// Check if directory hasn't been modified in the last 5 minutes
	now := time.Now()
	modTime := info.ModTime()
	timeSinceMod := now.Sub(modTime)

	// Also check all files in the directory to find the most recent modification
	mostRecentMod := modTime
	err = filepath.Walk(buildDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.ModTime().After(mostRecentMod) {
			mostRecentMod = info.ModTime()
		}
		return nil
	})
	if err == nil {
		timeSinceMod = now.Sub(mostRecentMod)
	}

	// Can delete if no modification in last 5 minutes
	canDelete := timeSinceMod >= 5*time.Minute
	deleteAction := fmt.Sprintf("rm -rf %s", buildDir)

	return canDelete, deleteAction
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
