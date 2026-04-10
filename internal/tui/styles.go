package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors.
	colorPrimary   = lipgloss.Color("#7C3AED") // violet
	colorSecondary = lipgloss.Color("#A78BFA") // lighter violet
	colorSuccess   = lipgloss.Color("#22C55E") // green
	colorWarning   = lipgloss.Color("#F59E0B") // amber
	colorDanger    = lipgloss.Color("#EF4444") // red
	colorMuted     = lipgloss.Color("#6B7280") // gray
	colorText      = lipgloss.Color("#E5E7EB") // light gray

	// Styles.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(colorSecondary).
			Bold(true)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			Width(18)

	valueStyle = lipgloss.NewStyle().
			Foreground(colorText)

	successStyle = lipgloss.NewStyle().
			Foreground(colorSuccess)

	warningStyle = lipgloss.NewStyle().
			Foreground(colorWarning)

	dangerStyle = lipgloss.NewStyle().
			Foreground(colorDanger)

	mutedStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(0, 1).
			MarginBottom(1)

	spinnerStyle = lipgloss.NewStyle().
			Foreground(colorSecondary)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorMuted).
			MarginTop(1)
)
