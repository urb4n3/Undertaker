package tui

import (
	"bytes"
	"fmt"
	"image"
	_ "image/png"
	"strings"

	"github.com/urb4n3/undertaker/assets"
)

// logoCache avoids re-rendering the logo on every spinner tick.
var logoCache struct {
	width    int
	rendered string
}

func renderLogo(width int) string {
	if width <= 0 {
		width = 80
	}
	if logoCache.rendered != "" && logoCache.width == width {
		return logoCache.rendered
	}

	img, _, err := image.Decode(bytes.NewReader(assets.Logo))
	if err != nil {
		return titleStyle.Render("Undertaker") + "\n"
	}

	bounds := img.Bounds()
	imgW := bounds.Dx()
	imgH := bounds.Dy()

	// Half-block rendering: each terminal row covers 2 pixel rows (▀).
	// Correct for cell aspect ratio (~2:1 h:w) by multiplying by 0.5.
	targetH := int(float64(width) * float64(imgH) / float64(imgW) * 0.5)
	if targetH < 1 {
		targetH = 1
	}
	pixelH := targetH * 2

	var sb strings.Builder
	for row := 0; row < targetH; row++ {
		for col := 0; col < width; col++ {
			srcX := col * imgW / width
			srcY1 := (row * 2) * imgH / pixelH
			srcY2 := (row*2 + 1) * imgH / pixelH

			r1, g1, b1, _ := img.At(bounds.Min.X+srcX, bounds.Min.Y+srcY1).RGBA()
			r2, g2, b2, _ := img.At(bounds.Min.X+srcX, bounds.Min.Y+srcY2).RGBA()

			// ▀ — fg = upper pixel, bg = lower pixel
			sb.WriteString(fmt.Sprintf("\x1b[38;2;%d;%d;%dm\x1b[48;2;%d;%d;%dm▀",
				r1>>8, g1>>8, b1>>8, r2>>8, g2>>8, b2>>8))
		}
		sb.WriteString("\x1b[0m\n")
	}

	logoCache.width = width
	logoCache.rendered = sb.String()
	return logoCache.rendered
}

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

	b.WriteString(renderLogo(m.width))
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
	var b strings.Builder

	// Show all completed progress steps as a final checklist.
	for _, step := range m.progress {
		b.WriteString(successStyle.Render("✓ "))
		b.WriteString(valueStyle.Render(step))
		b.WriteString("\n")
	}
	if m.current != "" {
		b.WriteString(successStyle.Render("✓ "))
		b.WriteString(valueStyle.Render(m.current))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(successStyle.Render("Done!"))

	if m.caseDir != "" {
		b.WriteString("  " + mutedStyle.Render(fmt.Sprintf("Reports saved to %s", m.caseDir)))
	}
	b.WriteString("\n")

	if m.copyStatus != "" {
		b.WriteString(successStyle.Render(m.copyStatus) + "\n")
	}

	b.WriteString(helpStyle.Render("\nc copy report | q quit"))
	b.WriteString("\n")

	return b.String()
}

