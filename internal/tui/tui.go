package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/app"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

type screen int

const (
	screenTable screen = iota
	screenDetail
	screenReport
	screenPicker
)

var (
	accent       = lipgloss.Color("#12ABDB")
	danger       = lipgloss.Color("#FF5F87")
	warn         = lipgloss.Color("#FFAF5F")
	ok           = lipgloss.Color("#7DDE92")
	muted        = lipgloss.Color("#7A8499")
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(accent).Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(0, 1)
	mutedStyle   = lipgloss.NewStyle().Foreground(muted)
	panelStyle   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(accent).Padding(1, 2)
	modalStyle   = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(accent).Padding(1, 2)
	errorStyle   = lipgloss.NewStyle().Foreground(danger).Bold(true)
	successStyle = lipgloss.NewStyle().Foreground(ok).Bold(true)
)

type Model struct {
	ctx    context.Context
	cfg    model.Config
	rows   []model.Row
	table  table.Model
	detail viewport.Model
	state  screen
	width  int
	height int

	prefix      textinput.Model
	outDir      string
	formats     map[string]bool
	reportFocus int
	picker      filepicker.Model
	status      string
	err         string
}

func Run(ctx context.Context, cfg model.Config, rows []model.Row) error {
	m := New(ctx, cfg, rows)
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func New(ctx context.Context, cfg model.Config, rows []model.Row) Model {
	cols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "Tier", Width: 8},
		{Title: "Run", Width: 5},
		{Title: "Severity", Width: 10},
		{Title: "CVSS", Width: 6},
		{Title: "CVE", Width: 16},
		{Title: "Repository", Width: 22},
		{Title: "Image", Width: 20},
		{Title: "Package", Width: 18},
		{Title: "Fixed", Width: 14},
	}
	trs := make([]table.Row, 0, len(rows))
	for i, r := range rows {
		trs = append(trs, table.Row{
			strconv.Itoa(i + 1), r.Tier, yesNo(r.RunningOrDeployed), r.Severity,
			fmt.Sprintf("%.1f", r.CVSS), r.CVE, r.Repository, strings.Join(r.ImageTags, ","), r.Package, r.FixedVersion,
		})
	}
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).Foreground(lipgloss.Color("#E6EDF3")).Background(lipgloss.Color("#24324A"))
	styles.Selected = styles.Selected.Bold(true).Foreground(lipgloss.Color("#06111F")).Background(accent)
	t := table.New(table.WithColumns(cols), table.WithRows(trs), table.WithFocused(true), table.WithHeight(18), table.WithWidth(132), table.WithStyles(styles))

	prefix := textinput.New()
	prefix.Placeholder = "ecr-vulnerability-priorities"
	prefix.SetValue("ecr-vulnerability-priorities")
	prefix.Focus()

	picker := filepicker.New()
	picker.CurrentDirectory = "."
	picker.DirAllowed = true
	picker.FileAllowed = false
	picker.ShowSize = false
	picker.ShowPermissions = false
	picker.SetHeight(12)

	vp := viewport.New(120, 24)

	return Model{
		ctx: ctx, cfg: cfg, rows: rows, table: t, detail: vp, state: screenTable,
		prefix: prefix, outDir: ".", picker: picker,
		formats: map[string]bool{"csv": true, "json": true, "md": true},
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		tableHeight := max(8, msg.Height-8)
		m.table.SetHeight(tableHeight)
		m.table.SetWidth(max(80, msg.Width-4))
		m.detail.Width = max(60, msg.Width-8)
		m.detail.Height = max(10, msg.Height-8)
		m.picker.SetHeight(max(8, msg.Height-12))
	case tea.KeyMsg:
		if m.state != screenReport && m.state != screenPicker {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			}
		}
		switch m.state {
		case screenTable:
			return m.updateTable(msg)
		case screenDetail:
			return m.updateDetail(msg)
		case screenReport:
			return m.updateReport(msg)
		case screenPicker:
			return m.updatePicker(msg)
		}
	}
	return m, nil
}

func (m Model) updateTable(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "right":
		m.state = screenDetail
		m.detail.SetContent(m.selectedDetail())
		m.detail.GotoTop()
		return m, nil
	case "r":
		m.state = screenReport
		m.reportFocus = 0
		m.prefix.Focus()
		return m, nil
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m Model) updateDetail(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "left", "backspace":
		m.state = screenTable
		return m, nil
	case "r":
		m.state = screenReport
		return m, nil
	}
	var cmd tea.Cmd
	m.detail, cmd = m.detail.Update(msg)
	return m, cmd
}

func (m Model) updateReport(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.err = ""
	switch msg.String() {
	case "esc":
		m.state = screenTable
		return m, nil
	case "ctrl+c":
		return m, tea.Quit
	case "tab", "shift+tab", "up", "down":
		if msg.String() == "up" || msg.String() == "shift+tab" {
			m.reportFocus = (m.reportFocus + 4) % 5
		} else {
			m.reportFocus = (m.reportFocus + 1) % 5
		}
		if m.reportFocus == 0 {
			m.prefix.Focus()
		} else {
			m.prefix.Blur()
		}
		return m, nil
	case "p":
		m.state = screenPicker
		return m, m.picker.Init()
	case " ":
		switch m.reportFocus {
		case 1:
			m.formats["csv"] = !m.formats["csv"]
		case 2:
			m.formats["json"] = !m.formats["json"]
		case 3:
			m.formats["md"] = !m.formats["md"]
		}
		return m, nil
	case "enter":
		if m.reportFocus >= 1 && m.reportFocus <= 3 {
			return m.updateReport(tea.KeyMsg{Type: tea.KeySpace})
		}
		if m.reportFocus == 4 {
			m.generateReport()
			return m, nil
		}
	}
	if m.reportFocus == 0 {
		var cmd tea.Cmd
		m.prefix, cmd = m.prefix.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.state = screenReport
		return m, nil
	case "c":
		m.outDir = m.picker.CurrentDirectory
		m.state = screenReport
		m.status = "selected output directory: " + m.outDir
		return m, nil
	}
	var cmd tea.Cmd
	m.picker, cmd = m.picker.Update(msg)
	if m.picker.Path != "" {
		m.outDir = m.picker.Path
		m.picker.Path = ""
		m.state = screenReport
		m.status = "selected output directory: " + m.outDir
	}
	return m, cmd
}

func (m *Model) generateReport() {
	prefix := strings.TrimSpace(m.prefix.Value())
	if prefix == "" {
		m.err = "prefix is required"
		return
	}
	formats := []string{}
	for _, f := range []string{"csv", "json", "md"} {
		if m.formats[f] {
			formats = append(formats, f)
		}
	}
	if len(formats) == 0 {
		m.err = "select at least one file type"
		return
	}
	fullPrefix := filepath.Join(m.outDir, prefix)
	if err := app.WriteReports(fullPrefix, m.rows, formats); err != nil {
		m.err = err.Error()
		return
	}
	m.status = fmt.Sprintf("generated %s report(s) at %s.*", strings.Join(formats, ", "), fullPrefix)
}

func (m Model) View() string {
	switch m.state {
	case screenDetail:
		return m.wrap(m.detailView())
	case screenReport:
		base := m.wrap(m.tableView())
		return overlayCenter(base, m.reportModal(), max(m.width, 100), max(m.height, 30))
	case screenPicker:
		base := m.wrap(m.tableView())
		return overlayCenter(base, m.pickerModal(), max(m.width, 100), max(m.height, 30))
	default:
		return m.wrap(m.tableView())
	}
}

func (m Model) wrap(body string) string {
	return lipgloss.NewStyle().Padding(1, 2).Render(body)
}

func (m Model) tableView() string {
	t1, t2, rt := model.Summary(m.rows)
	status := mutedStyle.Render(fmt.Sprintf("%d findings · Tier 1: %d · Tier 2: %d · runtime matched: %d", len(m.rows), t1, t2, rt))
	help := mutedStyle.Render("↑/↓ move · enter details · r report · q quit")
	if m.status != "" {
		help += "\n" + successStyle.Render(m.status)
	}
	return titleStyle.Render("ECR Inspector Runtime Prioritizer") + "\n" + status + "\n\n" + colorizeTable(m.table.View()) + "\n" + help
}

func (m Model) detailView() string {
	return titleStyle.Render("Finding Details") + "\n" + mutedStyle.Render("esc/← back · r report · ↑/↓ scroll · q quit") + "\n\n" + panelStyle.Render(m.detail.View())
}

func (m Model) reportModal() string {
	lines := []string{"Generate report", ""}
	lines = append(lines, focusLine(m.reportFocus == 0, "Prefix", m.prefix.View()))
	lines = append(lines, focusLine(false, "Directory", m.outDir+"  "+mutedStyle.Render("(press p for file picker)")))
	lines = append(lines, checkbox(m.reportFocus == 1, m.formats["csv"], "CSV"))
	lines = append(lines, checkbox(m.reportFocus == 2, m.formats["json"], "JSON"))
	lines = append(lines, checkbox(m.reportFocus == 3, m.formats["md"], "Markdown"))
	button := "Generate"
	if m.reportFocus == 4 {
		button = lipgloss.NewStyle().Foreground(lipgloss.Color("#06111F")).Background(accent).Bold(true).Padding(0, 1).Render(button)
	}
	lines = append(lines, "", button)
	if m.err != "" {
		lines = append(lines, "", errorStyle.Render(m.err))
	}
	if m.status != "" {
		lines = append(lines, "", successStyle.Render(m.status))
	}
	lines = append(lines, "", mutedStyle.Render("tab focus · space toggle · enter activate · p picker · esc close"))
	return modalStyle.Width(72).Render(strings.Join(lines, "\n"))
}

func (m Model) pickerModal() string {
	content := fmt.Sprintf("Select output directory\n%s\n\n%s\n%s", mutedStyle.Render("enter/right opens directory · c selects current directory · esc back"), m.picker.View(), mutedStyle.Render("current: "+m.picker.CurrentDirectory))
	return modalStyle.Width(max(72, m.width-8)).Render(content)
}

func (m Model) selectedDetail() string {
	row := m.table.SelectedRow()
	idx := 0
	if len(row) > 0 {
		if parsed, err := strconv.Atoi(row[0]); err == nil && parsed > 0 && parsed <= len(m.rows) {
			idx = parsed - 1
		}
	}
	if len(m.rows) == 0 {
		return "No findings."
	}
	r := m.rows[idx]
	var b strings.Builder
	write := func(k string, v any) { b.WriteString(fmt.Sprintf("%-18s %v\n", k+":", v)) }
	write("Tier", r.Tier)
	write("Severity", r.Severity)
	write("CVSS", fmt.Sprintf("%.1f", r.CVSS))
	write("Exploit available", r.ExploitAvailable)
	write("Fix available", r.FixAvailable)
	write("CVE", r.CVE)
	write("Title", r.Title)
	write("Account", r.AccountID)
	write("Region", r.Region)
	write("Repository", r.Repository)
	write("Image tags", strings.Join(r.ImageTags, ", "))
	write("Image digest", r.ImageDigest)
	write("Image URI", r.ImageURI)
	write("Package", r.Package)
	write("Installed", r.InstalledVersion)
	write("Fixed", r.FixedVersion)
	write("Package manager", r.PackageManager)
	write("First observed", r.FirstObservedAt)
	write("Updated", r.UpdatedAt)
	write("Status", r.InspectorStatus)
	write("Finding ARN", r.FindingARN)
	b.WriteString("\nRuntime locations:\n")
	if len(r.RuntimeLocations) == 0 {
		b.WriteString("  none matched in EKS/ECS runtime inventory\n")
	} else {
		for _, h := range r.RuntimeLocations {
			b.WriteString("  - " + h.Compact() + "\n")
		}
	}
	return b.String()
}

func colorizeTable(view string) string {
	lines := strings.Split(view, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		line = strings.ReplaceAll(line, "Tier 1", lipgloss.NewStyle().Foreground(danger).Bold(true).Render("Tier 1"))
		line = strings.ReplaceAll(line, "Tier 2", lipgloss.NewStyle().Foreground(warn).Bold(true).Render("Tier 2"))
		line = strings.ReplaceAll(line, "CRITICAL", lipgloss.NewStyle().Foreground(danger).Bold(true).Render("CRITICAL"))
		line = strings.ReplaceAll(line, "HIGH", lipgloss.NewStyle().Foreground(warn).Bold(true).Render("HIGH"))
		line = strings.ReplaceAll(line, " YES ", " "+lipgloss.NewStyle().Foreground(ok).Bold(true).Render("YES")+" ")
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func overlayCenter(base, modal string, width, height int) string {
	if width <= 0 {
		width = max(lipgloss.Width(base), lipgloss.Width(modal))
	}
	if height <= 0 {
		height = max(lipgloss.Height(base), lipgloss.Height(modal))
	}
	baseLines := strings.Split(base, "\n")
	for len(baseLines) < height {
		baseLines = append(baseLines, "")
	}
	modalLines := strings.Split(modal, "\n")
	modalWidth := lipgloss.Width(modal)
	modalHeight := lipgloss.Height(modal)
	x := max(0, (width-modalWidth)/2)
	y := max(0, (height-modalHeight)/2)
	blank := strings.Repeat(" ", x)
	for i, modalLine := range modalLines {
		row := y + i
		if row >= len(baseLines) {
			break
		}
		baseLines[row] = blank + modalLine
	}
	return strings.Join(baseLines[:min(len(baseLines), height)], "\n")
}

func focusLine(active bool, label, value string) string {
	prefix := "  "
	if active {
		prefix = "▶ "
	}
	return prefix + label + ": " + value
}

func checkbox(active bool, checked bool, label string) string {
	mark := "[ ]"
	if checked {
		mark = "[x]"
	}
	line := mark + " " + label
	if active {
		return "▶ " + lipgloss.NewStyle().Foreground(accent).Bold(true).Render(line)
	}
	return "  " + line
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
