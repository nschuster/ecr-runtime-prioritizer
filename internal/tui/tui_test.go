package tui

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/app"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func init() {
	lipgloss.SetColorProfile(termenv.TrueColor)
	lipgloss.SetHasDarkBackground(true)
}

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

func TestTableViewContainsBubblesTableAndControls(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	view := m.View()
	for _, want := range []string{"ECR Inspector Runtime Prioritizer", "Tier 1", "CVE-2025-12345", "enter details", "r report"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view missing %q\n%s", want, view)
		}
	}
	if len(m.table.Columns()) == 0 || len(m.table.Rows()) == 0 {
		t.Fatalf("expected Bubbles table to be populated")
	}
}

func TestTableHeaderHasNoBackgroundFill(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	view := m.View()
	for _, line := range strings.Split(view, "\n") {
		plain := stripANSI(line)
		if strings.Contains(plain, "Severity") && strings.Contains(plain, "Repository") {
			if strings.Contains(line, "48;2") || strings.Contains(line, "48;5") {
				t.Fatalf("table header should not use a background color: %q", line)
			}
			return
		}
	}
	t.Fatalf("table header not found\n%s", view)
}

func TestDetailAndReportModalViews(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 40})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	view := m.View()
	if !strings.Contains(view, "ECR Inspector Runtime Prioritizer") || !strings.Contains(view, "Finding Details") || !strings.Contains(view, "Runtime locations") {
		t.Fatalf("detail view missing expected content\n%s", view)
	}
	lines := strings.Split(view, "\n")
	if !strings.Contains(stripANSI(lines[len(lines)-1]), "esc/← back") {
		t.Fatalf("expected detail controls in bottom footer, got last line %q\n%s", lines[len(lines)-1], view)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	view = m.View()
	for _, want := range []string{"Generate report", "Prefix", "CSV", "JSON", "Markdown"} {
		if !strings.Contains(view, want) {
			t.Fatalf("report modal missing %q\n%s", want, view)
		}
	}
	if strings.Contains(view, "file picker") || strings.Contains(view, "press p") {
		t.Fatalf("report modal should not expose file picker controls\n%s", view)
	}
	lines = strings.Split(view, "\n")
	modalLine := -1
	for i, line := range lines {
		if strings.Contains(line, "Generate report") {
			modalLine = i
			break
		}
	}
	if modalLine <= 3 {
		t.Fatalf("expected modal to be centered/overlaid, got line %d\n%s", modalLine, view)
	}
}

func TestReportGenerationClosesModal(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	m.reportFocus = 4
	m.prefix.SetValue(t.TempDir() + "/report")

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.state != screenTable {
		t.Fatalf("expected report modal to close after generation, got state %v", m.state)
	}
	if strings.Contains(m.View(), "Generate report") {
		t.Fatalf("report modal still visible after generation\n%s", m.View())
	}
}

func TestSelectedRowMarqueeScrollsOverflowingCells(t *testing.T) {
	cols := []table.Column{{Title: "Image", Width: 8}}
	frame0 := stripANSI(renderCells(cols, []string{"very-long-image-tag"}, false, true, 0))
	frame4 := stripANSI(renderCells(cols, []string{"very-long-image-tag"}, false, true, 4))
	if frame0 == frame4 {
		t.Fatalf("expected selected overflowing cell to scroll, got same frame %q", frame0)
	}
	if strings.Contains(frame0, "…") || strings.Contains(frame4, "…") {
		t.Fatalf("selected marquee should scroll text instead of ellipsizing: %q / %q", frame0, frame4)
	}
	if len([]rune(strings.TrimRight(frame0, " "))) > 8 || len([]rune(strings.TrimRight(frame4, " "))) > 8 {
		t.Fatalf("marquee frames must stay within column width: %q / %q", frame0, frame4)
	}
}

func TestDetailViewUsesSemanticColorFormatting(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	view := m.View()
	if !strings.Contains(stripANSI(view), "Tier:") || !strings.Contains(stripANSI(view), "Runtime locations") {
		t.Fatalf("detail view missing expected text\n%s", view)
	}
	if !strings.Contains(view, "38;2") && !strings.Contains(view, "38;5") {
		t.Fatalf("detail view should include ANSI color formatting\n%s", view)
	}
}

func TestSelectedRowHighlightSpansRenderedRow(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	view := m.View()
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(stripANSI(line), "CVE-2025-12345") {
			plain := stripANSI(line)
			if !strings.Contains(line, "48;2") && !strings.Contains(line, "48;5") {
				t.Fatalf("expected selected row to have a background style: %q", line)
			}
			if !strings.Contains(plain, "1.1.1w") || strings.Index(plain, "CVE-2025-12345") > strings.Index(plain, "1.1.1w") {
				t.Fatalf("expected selected row highlight target to span through final columns, got %q", plain)
			}
			return
		}
	}
	t.Fatalf("selected row not found\n%s", view)
}
