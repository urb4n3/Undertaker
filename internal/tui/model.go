package tui

import (
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/urb4n3/undertaker/internal/models"
)

// AnalysisCompleteMsg is sent when the pipeline finishes.
type AnalysisCompleteMsg struct {
	Report *models.AnalysisReport
	Err    error
}

// ProgressMsg is sent from the pipeline on each progress step.
type ProgressMsg struct {
	Text string
}

// StatusMsg indicates a completed step for display.
type StatusMsg struct {
	Text string
}

// CopyResultMsg indicates clipboard copy result.
type CopyResultMsg struct {
	Err error
}

// ReportReadyMsg carries the markdown text and case directory from the CLI.
type ReportReadyMsg struct {
	Markdown string
	CaseDir  string
}

// Model is the Bubbletea model for the Undertaker TUI.
type Model struct {
	filePath   string
	report     *models.AnalysisReport
	markdown   string
	caseDir    string
	err        error
	done       bool
	quitting   bool
	spinner    spinner.Model
	progress   []string // completed steps
	current    string   // current step message
	width      int
	height     int
	scroll     int // scroll offset for results view
	copyStatus string
}

// NewModel creates a new TUI model for the given file path.
func NewModel(filePath string) Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = spinnerStyle
	return Model{
		filePath: filePath,
		spinner:  s,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}
