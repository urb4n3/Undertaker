package tui

import (
	"fmt"
	"strings"

	"github.com/urb4n3/undertaker/internal/models"
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	if !m.done {
		return m.viewProgress()
	}

	if m.err != nil {
		return dangerStyle.Render(fmt.Sprintf("Analysis failed: %v", m.err)) + "\n"
	}

	return m.viewResults()
}

func (m Model) viewProgress() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("⚰ Undertaker"))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render(fmt.Sprintf("Analyzing: %s", m.filePath)))
	b.WriteString("\n\n")

	// Show completed steps.
	for _, step := range m.progress {
		b.WriteString(successStyle.Render("✓ "))
		b.WriteString(valueStyle.Render(step))
		b.WriteString("\n")
	}

	// Show current step with spinner.
	if m.current != "" {
		b.WriteString(m.spinner.View() + " ")
		b.WriteString(valueStyle.Render(m.current))
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) viewResults() string {
	r := m.report
	if r == nil {
		return dangerStyle.Render("No report available") + "\n"
	}

	var b strings.Builder

	// Title.
	b.WriteString(titleStyle.Render("⚰ Undertaker — Analysis Complete"))
	b.WriteString("\n")

	// Identity panel.
	identity := m.renderIdentity(r)
	b.WriteString(panelStyle.Render(identity))

	// Findings panel (if any interesting findings).
	findings := m.renderFindings(r)
	if findings != "" {
		b.WriteString(panelStyle.Render(findings))
	}

	// Stats.
	b.WriteString(m.renderStats(r))

	// Case dir.
	if m.caseDir != "" {
		b.WriteString("\n" + mutedStyle.Render(fmt.Sprintf("Reports saved to %s", m.caseDir)))
	}

	// Copy status.
	if m.copyStatus != "" {
		b.WriteString("\n" + successStyle.Render(m.copyStatus))
	}

	// Help.
	b.WriteString(helpStyle.Render("\n↑/↓ scroll • c copy report • q quit"))
	b.WriteString("\n")

	// Apply scrolling.
	lines := strings.Split(b.String(), "\n")
	viewHeight := m.height
	if viewHeight <= 0 {
		viewHeight = 50
	}
	if m.scroll >= len(lines) {
		m.scroll = len(lines) - 1
	}
	end := m.scroll + viewHeight
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[m.scroll:end], "\n")
}

func (m Model) renderIdentity(r *models.AnalysisReport) string {
	var b strings.Builder
	b.WriteString(subtitleStyle.Render("Identity"))
	b.WriteString("\n")

	rows := [][2]string{
		{"File", r.Sample.Path},
		{"Type", r.Sample.FileType},
		{"Size", formatSize(r.Sample.FileSize)},
		{"SHA-256", r.Sample.SHA256},
		{"MD5", r.Sample.MD5},
		{"SSDeep", r.Sample.SSDeep},
	}
	if r.Sample.ImpHash != "" {
		rows = append(rows, [2]string{"ImpHash", r.Sample.ImpHash})
	}

	for _, row := range rows {
		b.WriteString(labelStyle.Render(row[0]))
		b.WriteString(valueStyle.Render(row[1]))
		b.WriteString("\n")
	}
	return b.String()
}

func (m Model) renderFindings(r *models.AnalysisReport) string {
	var b strings.Builder
	b.WriteString(subtitleStyle.Render("Findings"))
	b.WriteString("\n")
	hasFindings := false

	// Packing.
	if r.Packing.Confidence == "high" || r.Packing.Confidence == "medium" {
		hasFindings = true
		b.WriteString(warningStyle.Render("⚠ Likely packed"))
		b.WriteString(mutedStyle.Render(fmt.Sprintf(" (entropy: %.2f)", r.Packing.Entropy)))
		b.WriteString("\n")
	}

	// Capabilities.
	if len(r.Capabilities) > 0 {
		hasFindings = true
		count := len(r.Capabilities)
		b.WriteString(labelStyle.Render("Capabilities"))
		b.WriteString(valueStyle.Render(fmt.Sprintf("%d detected", count)))
		b.WriteString("\n")
		// Show up to 5 techniques.
		shown := 0
		for _, cap := range r.Capabilities {
			if shown >= 5 {
				b.WriteString(mutedStyle.Render(fmt.Sprintf("  ... and %d more", count-5)))
				b.WriteString("\n")
				break
			}
			label := cap.TechniqueName
			if cap.TechniqueID != "" {
				label = cap.TechniqueID + " " + label
			}
			b.WriteString("  " + valueStyle.Render(label) + "\n")
			shown++
		}
	}

	// IOCs.
	if len(r.IOCs) > 0 {
		hasFindings = true
		b.WriteString(labelStyle.Render("IOCs"))
		b.WriteString(warningStyle.Render(fmt.Sprintf("%d found", len(r.IOCs))))
		b.WriteString("\n")
	}

	// YARA.
	if len(r.YARAMatches) > 0 {
		hasFindings = true
		b.WriteString(labelStyle.Render("YARA Matches"))
		b.WriteString(dangerStyle.Render(fmt.Sprintf("%d rules matched", len(r.YARAMatches))))
		b.WriteString("\n")
		for _, ym := range r.YARAMatches {
			b.WriteString("  " + dangerStyle.Render(ym.RuleName) + "\n")
		}
	}

	// Errors.
	if len(r.Errors) > 0 {
		hasFindings = true
		b.WriteString(labelStyle.Render("Errors"))
		b.WriteString(dangerStyle.Render(fmt.Sprintf("%d", len(r.Errors))))
		b.WriteString("\n")
	}

	if !hasFindings {
		return ""
	}
	return b.String()
}

func (m Model) renderStats(r *models.AnalysisReport) string {
	var b strings.Builder
	b.WriteString(subtitleStyle.Render("Stats"))
	b.WriteString("\n")

	rows := [][2]string{
		{"Strings", fmt.Sprintf("%d", len(r.Strings))},
		{"Imports", fmt.Sprintf("%d total, %d suspicious", r.Imports.TotalImports, len(r.Imports.SuspiciousImports))},
		{"Exports", fmt.Sprintf("%d", len(r.Exports))},
		{"Sections", fmt.Sprintf("%d", len(r.Metadata.Sections))},
	}

	for _, row := range rows {
		b.WriteString(labelStyle.Render(row[0]))
		b.WriteString(valueStyle.Render(row[1]))
		b.WriteString("\n")
	}
	return b.String()
}

func formatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
