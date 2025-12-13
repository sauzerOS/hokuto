package hokuto

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type buildLogMsg struct {
	logs []logInfo
}

type logInfo struct {
	path         string
	content      string
	buildDir     string // Extracted build directory path
	canDelete    bool   // Whether this build directory can be deleted
	deleteAction string // The delete command to show
}

type tuiModel struct {
	logs         []logInfo
	viewports    []viewport.Model
	prevContents []string // Track previous content to detect changes
	activeIdx    int
	width        int
	height       int
}

func runTUI() int {
	m := newTUIModel()

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		return 1
	}
	return 0
}

func newTUIModel() *tuiModel {
	m := &tuiModel{
		logs:      []logInfo{},
		viewports: []viewport.Model{},
		activeIdx: 0,
	}

	return m
}

func (m *tuiModel) Init() tea.Cmd {
	return tickBuildLog()
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resize()
		return m, nil

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlQ, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyRunes:
			// Check for 'q' to quit
			if len(msg.Runes) == 1 && msg.Runes[0] == 'q' {
				return m, tea.Quit
			}
			// Check for 'd' to delete build directory
			if len(msg.Runes) == 1 && msg.Runes[0] == 'd' {
				if m.activeIdx < len(m.logs) {
					log := m.logs[m.activeIdx]
					if log.canDelete {
						// Delete the build directory
						if err := os.RemoveAll(log.buildDir); err != nil {
							// Error will be visible when logs refresh
						}
						// Immediately refresh logs to reflect deletion
						return m, tickBuildLog()
					}
				}
			}
		case tea.KeyLeft:
			// Switch to previous pane
			if len(m.viewports) > 0 {
				m.activeIdx--
				if m.activeIdx < 0 {
					m.activeIdx = len(m.viewports) - 1
				}
			}
			return m, nil
		case tea.KeyRight:
			// Switch to next pane
			if len(m.viewports) > 0 {
				m.activeIdx++
				if m.activeIdx >= len(m.viewports) {
					m.activeIdx = 0
				}
			}
			return m, nil
		}
		// Allow viewport scrolling for active pane
		if len(m.viewports) > 0 && m.activeIdx < len(m.viewports) {
			var cmd tea.Cmd
			m.viewports[m.activeIdx], cmd = m.viewports[m.activeIdx].Update(msg)
			return m, cmd
		}
		return m, nil

	case buildLogMsg:
		// Check if this is the first load or if logs changed
		isFirstLoad := len(m.viewports) == 0
		logsChanged := len(m.logs) != len(msg.logs)

		// Update logs
		m.logs = msg.logs

		// Recreate viewports if number of logs changed
		if logsChanged || isFirstLoad {
			m.viewports = make([]viewport.Model, len(m.logs))
			m.prevContents = make([]string, len(m.logs))
			for i, log := range m.logs {
				vp := viewport.New(m.width, m.height-3)
				vp.SetContent(log.content)
				vp.GotoBottom() // Only on first load or when logs change
				m.viewports[i] = vp
				m.prevContents[i] = log.content
			}
		} else {
			// Update existing viewports, preserving scroll position unless content changed
			for i, log := range m.logs {
				if i < len(m.viewports) {
					prevContent := m.prevContents[i]
					// Only update if content actually changed
					if log.content != prevContent {
						// Check if user was at the bottom before update
						wasAtBottom := m.viewports[i].AtBottom()

						// Update content
						m.viewports[i].SetContent(log.content)
						m.prevContents[i] = log.content

						// Only auto-scroll to bottom if user was already at bottom
						if wasAtBottom {
							m.viewports[i].GotoBottom()
						}
						// Otherwise preserve scroll position
					}
				}
			}
		}

		// Ensure activeIdx is valid
		if m.activeIdx >= len(m.viewports) && len(m.viewports) > 0 {
			m.activeIdx = len(m.viewports) - 1
		}
		m.resize()
		return m, tickBuildLog()
	}

	return m, nil
}

func (m *tuiModel) View() string {
	header := lipgloss.NewStyle().Bold(true).Render("hokuto Build Log Viewer")

	var paneTitle string
	var body string

	if len(m.logs) == 0 {
		paneTitle = lipgloss.NewStyle().Faint(true).Render("No build logs found")
		body = "No build log yet. Run 'hokuto build <package>' to start a build."
	} else if m.activeIdx < len(m.viewports) {
		log := m.logs[m.activeIdx]
		titleText := fmt.Sprintf("Build Log %d/%d: %s", m.activeIdx+1, len(m.logs), log.path)
		if log.canDelete {
			deleteHint := lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Faint(true).Render(
				fmt.Sprintf(" | Press 'd' to delete: %s", log.deleteAction),
			)
			titleText += deleteHint
		}
		paneTitle = lipgloss.NewStyle().Faint(true).Render(titleText)
		body = m.viewports[m.activeIdx].View()
	} else {
		paneTitle = lipgloss.NewStyle().Faint(true).Render("No active log")
		body = ""
	}

	footerText := "Press 'q' or Ctrl+Q to quit | ← → to switch panes | ↑ ↓ to scroll"
	if len(m.logs) > 0 && m.activeIdx < len(m.logs) && m.logs[m.activeIdx].canDelete {
		footerText += " | 'd' to delete"
	}
	footer := lipgloss.NewStyle().Faint(true).Render(footerText)

	// Build view
	parts := []string{header, paneTitle, body, footer}
	return strings.Join(parts, "\n")
}

func (m *tuiModel) resize() {
	h := m.height - 3 // header(1) + paneTitle(1) + footer(1)
	if h < 1 {
		h = 1
	}

	for i := range m.viewports {
		m.viewports[i].Width = m.width
		m.viewports[i].Height = h
	}
}

func tickBuildLog() tea.Cmd {
	return tea.Tick(400*time.Millisecond, func(time.Time) tea.Msg {
		logs := readAllBuildLogs()
		return buildLogMsg{logs: logs}
	})
}

func readAllBuildLogs() []logInfo {
	// Determine config file path based on HOKUTO_ROOT env variable
	configPath := ConfigFile
	if hokutoRoot := os.Getenv("HOKUTO_ROOT"); hokutoRoot != "" {
		configPath = filepath.Join(hokutoRoot, "etc", "hokuto.conf")
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

	// Read all logs
	logs := make([]logInfo, 0, len(allPaths))
	for _, path := range allPaths {
		content, err := tailFileBytes(path, 128*1024)
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

func tailFileBytes(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}

	size := info.Size()
	var start int64
	if size > maxBytes {
		start = size - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
