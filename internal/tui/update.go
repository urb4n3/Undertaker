package tui

import (
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		case "c":
			if m.done && m.markdown != "" {
				return m, copyToClipboard(m.markdown)
			}
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down", "j":
			m.scroll++
		case "pgup":
			m.scroll -= 20
			if m.scroll < 0 {
				m.scroll = 0
			}
		case "pgdown":
			m.scroll += 20
		case "home":
			m.scroll = 0
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case ProgressMsg:
		if m.current != "" {
			m.progress = append(m.progress, m.current)
		}
		m.current = msg.Text
		return m, nil

	case StatusMsg:
		m.progress = append(m.progress, msg.Text)
		return m, nil

	case AnalysisCompleteMsg:
		m.done = true
		m.report = msg.Report
		m.err = msg.Err
		return m, nil

	case ReportReadyMsg:
		m.markdown = msg.Markdown
		m.caseDir = msg.CaseDir
		return m, nil

	case CopyResultMsg:
		if msg.Err != nil {
			m.copyStatus = "Copy failed: " + msg.Err.Error()
		} else {
			m.copyStatus = "Report copied to clipboard!"
		}
		return m, nil

	case spinner.TickMsg:
		if !m.done {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	}

	return m, nil
}

func copyToClipboard(text string) tea.Cmd {
	return func() tea.Msg {
		err := clipboard.WriteAll(text)
		return CopyResultMsg{Err: err}
	}
}
