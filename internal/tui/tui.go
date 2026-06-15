package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/app"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

type screen int

type marqueeTickMsg time.Time

const (
	screenTable screen = iota
	screenDetail
	screenReport
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
	frame  int

	prefix      textinput.Model
	outDir      string
	formats     map[string]bool
	reportFocus int
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
	styles.Header = styles.Header.Bold(true).Foreground(lipgloss.Color("#E6EDF3"))
	styles.Selected = styles.Selected.Bold(true).Foreground(lipgloss.Color("#06111F")).Background(accent)
	t := table.New(table.WithColumns(cols), table.WithRows(trs), table.WithFocused(true), table.WithHeight(18), table.WithWidth(132), table.WithStyles(styles))

	prefix := textinput.New()
	prefix.Placeholder = "ecr-vulnerability-priorities"
	prefix.SetValue("ecr-vulnerability-priorities")
	prefix.Focus()

	vp := viewport.New(120, 24)

	return Model{
		ctx: ctx, cfg: cfg, rows: rows, table: t, detail: vp, state: screenTable,
		prefix: prefix, outDir: ".",
		formats: map[string]bool{"csv": true, "json": true, "md": true},
	}
}

func (m Model) Init() tea.Cmd { return marqueeTick() }

func marqueeTick() tea.Cmd {
	return tea.Tick(350*time.Millisecond, func(t time.Time) tea.Msg { return marqueeTickMsg(t) })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		tableHeight := max(8, msg.Height-8)
		m.table.SetHeight(tableHeight)
		m.table.SetWidth(max(80, msg.Width-4))
		m.detail.Width = max(60, msg.Width-8)
		m.detail.Height = max(10, msg.Height-12)
	case marqueeTickMsg:
		if m.state == screenTable {
			m.frame++
			return m, marqueeTick()
		}
		return m, marqueeTick()
	case tea.KeyMsg:
		if m.state != screenReport {
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
		return m, nil
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
			if m.generateReport() {
				m.state = screenTable
			}
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

func (m *Model) generateReport() bool {
	prefix := strings.TrimSpace(m.prefix.Value())
	if prefix == "" {
		m.err = "prefix is required"
		return false
	}
	formats := []string{}
	for _, f := range []string{"csv", "json", "md"} {
		if m.formats[f] {
			formats = append(formats, f)
		}
	}
	if len(formats) == 0 {
		m.err = "select at least one file type"
		return false
	}
	fullPrefix := prefix
	if !filepath.IsAbs(prefix) {
		fullPrefix = filepath.Join(m.outDir, prefix)
	}
	if err := app.WriteReports(fullPrefix, m.rows, formats); err != nil {
		m.err = err.Error()
		return false
	}
	m.status = fmt.Sprintf("generated %s report(s) at %s.*", strings.Join(formats, ", "), fullPrefix)
	return true
}

func (m Model) View() string {
	switch m.state {
	case screenDetail:
		return m.wrapDetail(m.detailView())
	case screenReport:
		base := m.wrap(m.tableView())
		return overlayCenter(base, m.reportModal(), max(m.width, 100), max(m.height, 30))
	default:
		return m.wrap(m.tableView())
	}
}

func (m Model) wrap(body string) string {
	return lipgloss.NewStyle().Padding(1, 2).Render(body)
}

func (m Model) wrapDetail(body string) string {
	return lipgloss.NewStyle().Padding(1, 2, 0, 2).Render(body)
}

func (m Model) tableView() string {
	t1, t2, rt := model.Summary(m.rows)
	status := mutedStyle.Render(fmt.Sprintf("%d findings · Tier 1: %d · Tier 2: %d · runtime matched: %d", len(m.rows), t1, t2, rt))
	help := mutedStyle.Render("↑/↓ move · enter details · r report · q quit")
	if m.status != "" {
		help += "\n" + successStyle.Render(m.status)
	}
	return titleStyle.Render("ECR Inspector Runtime Prioritizer") + "\n" + status + "\n\n" + m.renderOverviewTable() + "\n" + help
}

func (m Model) detailView() string {
	header := titleStyle.Render("ECR Inspector Runtime Prioritizer") + "\n" + mutedStyle.Render("Finding Details")
	panel := panelStyle.Width(max(60, m.detail.Width)).Height(max(8, m.detail.Height)).Render(m.detail.View())
	footer := mutedStyle.Render("esc/← back · r report · ↑/↓ scroll · q quit")
	content := header + "\n\n" + panel
	if m.height > 0 {
		used := lipgloss.Height(m.wrap(content)) + 1
		if gap := m.height - used - 1; gap > 0 {
			content += strings.Repeat("\n", gap)
		}
	}
	return content + "\n" + footer
}

func (m Model) reportModal() string {
	lines := []string{"Generate report", ""}
	lines = append(lines, focusLine(m.reportFocus == 0, "Prefix", m.prefix.View()))
	lines = append(lines, focusLine(false, "Directory", m.outDir))
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
	lines = append(lines, "", mutedStyle.Render("tab focus · space toggle · enter activate · esc close"))
	return modalStyle.Width(72).Render(strings.Join(lines, "\n"))
}

func (m Model) renderOverviewTable() string {
	cols := m.table.Columns()
	cursor := m.table.Cursor()
	height := max(1, m.height-10)
	if m.height == 0 {
		height = 18
	}
	start := 0
	if cursor >= height {
		start = cursor - height + 1
	}
	end := min(len(m.rows), start+height)
	var b strings.Builder
	b.WriteString(renderCells(cols, []string{"#", "Tier", "Run", "Severity", "CVSS", "CVE", "Repository", "Image", "Package", "Fixed"}, true, false, 0))
	b.WriteString("\n")
	for i := start; i < end; i++ {
		r := m.rows[i]
		cells := []string{
			strconv.Itoa(i + 1), r.Tier, yesNo(r.RunningOrDeployed), r.Severity,
			fmt.Sprintf("%.1f", r.CVSS), r.CVE, r.Repository, strings.Join(r.ImageTags, ","), r.Package, r.FixedVersion,
		}
		b.WriteString(renderCells(cols, cells, false, i == cursor, m.frame))
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func renderCells(cols []table.Column, cells []string, header, selected bool, frame int) string {
	parts := make([]string, 0, len(cols))
	for i, col := range cols {
		value := ""
		if i < len(cells) {
			value = cells[i]
		}
		cell := padCell(value, col.Width)
		if selected && !header {
			cell = marqueeCell(value, col.Width, frame)
		}
		if header {
			cell = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E6EDF3")).Render(cell)
		} else if !selected {
			cell = colorizeCell(value, cell)
		}
		parts = append(parts, cell)
	}
	line := strings.Join(parts, " ")
	if selected {
		line = lipgloss.NewStyle().Foreground(lipgloss.Color("#06111F")).Background(accent).Bold(true).Render(line)
	}
	return line
}

func marqueeCell(value string, width, frame int) string {
	if width <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value + strings.Repeat(" ", width-len(runes))
	}
	// Scroll right-to-left while selected, then leave a short blank gap before looping.
	gap := []rune("   ")
	track := append(append([]rune{}, runes...), gap...)
	cycle := len(track)
	start := frame % cycle
	window := make([]rune, 0, width)
	for len(window) < width {
		window = append(window, track[start%cycle])
		start++
	}
	return string(window)
}

func padCell(value string, width int) string {
	if width <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) > width {
		if width <= 1 {
			return string(runes[:width])
		}
		return string(runes[:width-1]) + "…"
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func colorizeCell(raw, padded string) string {
	switch raw {
	case "Tier 1":
		return lipgloss.NewStyle().Foreground(danger).Bold(true).Render(padded)
	case "Tier 2":
		return lipgloss.NewStyle().Foreground(warn).Bold(true).Render(padded)
	case "CRITICAL":
		return lipgloss.NewStyle().Foreground(danger).Bold(true).Render(padded)
	case "HIGH":
		return lipgloss.NewStyle().Foreground(warn).Bold(true).Render(padded)
	case "YES":
		return lipgloss.NewStyle().Foreground(ok).Bold(true).Render(padded)
	}
	return padded
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
	write := func(k string, v any) { b.WriteString(detailLine(k, fmt.Sprint(v)) + "\n") }
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
	b.WriteString("\n" + lipgloss.NewStyle().Foreground(accent).Bold(true).Render("Runtime locations:") + "\n")
	if len(r.RuntimeLocations) == 0 {
		b.WriteString("  " + mutedStyle.Render("none matched in EKS/ECS runtime inventory") + "\n")
	} else {
		for _, h := range r.RuntimeLocations {
			b.WriteString("  " + successStyle.Render("•") + " " + detailRuntime(h) + "\n")
		}
	}
	return b.String()
}

func detailLine(label, value string) string {
	labelPart := lipgloss.NewStyle().Foreground(muted).Bold(true).Render(fmt.Sprintf("%-18s", label+":"))
	return labelPart + " " + detailValue(label, value)
}

func detailValue(label, value string) string {
	s := lipgloss.NewStyle()
	switch label {
	case "Tier":
		if value == "Tier 1" {
			s = s.Foreground(danger).Bold(true)
		} else {
			s = s.Foreground(warn).Bold(true)
		}
	case "Severity":
		if value == "CRITICAL" {
			s = s.Foreground(danger).Bold(true)
		} else if value == "HIGH" {
			s = s.Foreground(warn).Bold(true)
		}
	case "Exploit available":
		if value == "YES" {
			s = s.Foreground(danger).Bold(true)
		} else {
			s = s.Foreground(muted)
		}
	case "Fix available", "Fixed":
		if value != "" && value != "NO" {
			s = s.Foreground(ok).Bold(true)
		}
	case "CVE":
		s = s.Foreground(accent).Bold(true)
	case "Repository", "Image tags", "Image digest", "Image URI", "Package", "Installed":
		s = s.Foreground(lipgloss.Color("#E6EDF3"))
	case "Status":
		if value == "ACTIVE" {
			s = s.Foreground(ok).Bold(true)
		}
	}
	return s.Render(value)
}

func detailRuntime(h model.RuntimeHit) string {
	platform := lipgloss.NewStyle().Foreground(ok).Bold(true).Render(h.Platform)
	where := lipgloss.NewStyle().Foreground(accent).Render(h.Region + ":" + h.Cluster)
	workload := lipgloss.NewStyle().Foreground(warn).Render(h.Namespace + "/" + h.Workload)
	container := lipgloss.NewStyle().Foreground(lipgloss.Color("#E6EDF3")).Render("pod=" + h.Pod + " container=" + h.Container)
	if h.Platform != "EKS" {
		return platform + ":" + where + ":" + lipgloss.NewStyle().Foreground(warn).Render(h.Workload) + " " + mutedStyle.Render("status="+h.Status)
	}
	return platform + ":" + where + ":" + workload + " " + container
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
