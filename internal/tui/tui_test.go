package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/app"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

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

func TestDetailAndReportModalViews(t *testing.T) {
	m := New(context.Background(), model.Config{Demo: true}, app.DemoRows())
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if !strings.Contains(m.View(), "Finding Details") || !strings.Contains(m.View(), "Runtime locations") {
		t.Fatalf("detail view missing expected content\n%s", m.View())
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = updated.(Model)
	view := m.View()
	for _, want := range []string{"Generate report", "Prefix", "CSV", "JSON", "Markdown", "file picker"} {
		if !strings.Contains(view, want) {
			t.Fatalf("report modal missing %q\n%s", want, view)
		}
	}
	lines := strings.Split(view, "\n")
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
