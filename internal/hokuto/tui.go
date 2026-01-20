package hokuto

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	tuiApp         *tview.Application
	tuiLogs        []logInfo
	tuiActiveIdx   int
	tuiHeaderBox   *tview.TextView
	tuiLogView     *tview.TextView
	tuiFooterBox   *tview.TextView
	tuiFlex        *tview.Flex
	tuiUpdateChan  chan []logInfo
	tuiPrevContent string // Track previous content to detect changes
)

func runTUI() int {
	// Initialize channels
	tuiUpdateChan = make(chan []logInfo, 10)

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
		SetScrollable(true).
		SetChangedFunc(func() {
			tuiApp.Draw()
		})
	tuiLogView.SetBorder(true)

	// Create footer box with border
	tuiFooterBox = tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true).
		SetTextAlign(tview.AlignLeft)
	tuiFooterBox.SetBorder(true)

	// Create flex layout: header (fixed) + log (flexible) + footer (fixed)
	tuiFlex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tuiHeaderBox, 3, 0, false). // Header: 3 lines (title + info + border)
		AddItem(tuiLogView, 0, 1, true).    // Log: flexible, takes remaining space
		AddItem(tuiFooterBox, 4, 0, false)  // Footer: fixed height (same as header)

	// Set up key handlers
	tuiFlex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
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
				updateTUI()
			}
			return nil
		case tcell.KeyRight:
			if len(tuiLogs) > 0 {
				tuiActiveIdx++
				if tuiActiveIdx >= len(tuiLogs) {
					tuiActiveIdx = 0
				}
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
					updateTUI()
				}
				return nil
			case 'l':
				if len(tuiLogs) > 0 {
					tuiActiveIdx++
					if tuiActiveIdx >= len(tuiLogs) {
						tuiActiveIdx = 0
					}
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
			tuiLogs = logs
			// Ensure activeIdx is valid
			if tuiActiveIdx >= len(tuiLogs) && len(tuiLogs) > 0 {
				tuiActiveIdx = len(tuiLogs) - 1
			}
			// Use QueueUpdateDraw to ensure thread-safe UI updates
			tuiApp.QueueUpdateDraw(func() {
				updateTUI()
			})
		}
	}()

	// Set root first
	tuiApp.SetRoot(tuiFlex, true).SetFocus(tuiLogView)

	// Initial update - must happen after setting root
	logs := readAllBuildLogs()
	tuiLogs = logs
	if len(tuiLogs) > 0 {
		tuiActiveIdx = 0
	}
	updateTUI()

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
	// Use ANSIWriter to convert ANSI escape sequences to tview color tags
	if len(tuiLogs) == 0 {
		tuiLogView.SetText("No build log yet. Run 'hokuto build <package>' to start a build.")
		tuiPrevContent = ""
	} else if tuiActiveIdx < len(tuiLogs) {
		log := tuiLogs[tuiActiveIdx]
		// Only update if content actually changed
		if log.content != tuiPrevContent {
			// Save current scroll position before clearing
			row, _ := tuiLogView.GetScrollOffset()

			// Check if we're at the bottom by trying to scroll down
			// If we can't scroll down, we're at the bottom
			tuiLogView.ScrollTo(row+1, 0)
			newRow, _ := tuiLogView.GetScrollOffset()
			wasAtBottom := (newRow == row)
			// Restore original position
			tuiLogView.ScrollTo(row, 0)

			// Clear the view first
			tuiLogView.Clear()
			// Use ANSIWriter to convert ANSI escape sequences to tview color tags
			// ANSIWriter wraps an io.Writer and converts ANSI codes to tview format
			ansiWriter := tview.ANSIWriter(tuiLogView)
			ansiWriter.Write([]byte(log.content))

			// Only auto-scroll to bottom if user was already at bottom
			if wasAtBottom {
				tuiLogView.ScrollToEnd()
			} else {
				// Try to restore scroll position
				// Calculate relative position based on content length
				if len(tuiPrevContent) > 0 && len(log.content) > 0 {
					// Calculate approximate line number based on content growth
					prevLines := strings.Count(tuiPrevContent, "\n")
					newLines := strings.Count(log.content, "\n")
					if newLines > prevLines {
						// Content grew, try to maintain relative position
						// If we were at line X of Y, try to be at line X of (Y + growth)
						linesAdded := newLines - prevLines
						newRow := row + linesAdded
						tuiLogView.ScrollTo(newRow, 0)
					} else {
						// Content didn't grow or shrunk, try to restore exact position
						tuiLogView.ScrollTo(row, 0)
					}
				}
			}

			tuiPrevContent = log.content
		}
	} else {
		tuiLogView.SetText("")
		tuiPrevContent = ""
	}

	// Update footer
	var footerSegments []string
	footerSegments = append(footerSegments, "Press 'q' or Ctrl+Q to quit")
	footerSegments = append(footerSegments, "← → (or h/l) to switch panes")
	footerSegments = append(footerSegments, "↑ ↓ to scroll")
	footerSegments = append(footerSegments, "Home/End to jump to start/end")
	footerSegments = append(footerSegments, "'o' to open in VS Code")
	if len(tuiLogs) > 0 && tuiActiveIdx < len(tuiLogs) && tuiLogs[tuiActiveIdx].canDelete {
		footerSegments = append(footerSegments, "'d' to delete")
	}
	footerText := strings.Join(footerSegments, " | ")
	tuiFooterBox.SetText(fmt.Sprintf("[gray]%s[white]", footerText))
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
