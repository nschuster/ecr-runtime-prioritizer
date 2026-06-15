package render

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

var (
	blue   = lipgloss.Color("#12ABDB")
	red    = lipgloss.Color("#FF5F87")
	orange = lipgloss.Color("#FFAF5F")
	green  = lipgloss.Color("#7DDE92")
	muted  = lipgloss.Color("#7A8499")
	title  = lipgloss.NewStyle().Bold(true).Foreground(blue).Border(lipgloss.RoundedBorder()).BorderForeground(blue).Padding(0, 1)
	th     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E6EDF3")).Background(lipgloss.Color("#24324A")).Padding(0, 1)
	cell   = lipgloss.NewStyle().Padding(0, 1)
)

func Table(rows []model.Row, limit int) string {
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	t1, t2, rt := model.Summary(rows)
	var b strings.Builder
	b.WriteString(title.Render("ECR Inspector Runtime Prioritizer") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(muted).Render(fmt.Sprintf("%d findings · Tier 1: %d · Tier 2: %d · runtime matched: %d", len(rows), t1, t2, rt)) + "\n\n")
	headers := []string{"Tier", "Run", "Severity", "CVSS", "CVE", "Repository", "Image", "Package", "Installed", "Fixed"}
	widths := []int{8, 5, 10, 6, 16, 22, 20, 18, 14, 14}
	for i, h := range headers {
		b.WriteString(th.Width(widths[i]).Render(h))
	}
	b.WriteString("\n")
	for _, r := range rows[:limit] {
		style := cell
		if r.Tier == "Tier 1" {
			style = style.Foreground(red)
		} else {
			style = style.Foreground(orange)
		}
		sevStyle := lipgloss.NewStyle().Padding(0, 1).Bold(true)
		if r.Severity == "CRITICAL" {
			sevStyle = sevStyle.Foreground(red)
		} else {
			sevStyle = sevStyle.Foreground(orange)
		}
		vals := []string{r.Tier, yesNo(r.RunningOrDeployed), r.Severity, fmt.Sprintf("%.1f", r.CVSS), r.CVE, r.Repository, strings.Join(r.ImageTags, ","), r.Package, r.InstalledVersion, r.FixedVersion}
		for i, v := range vals {
			s := style
			if i == 2 {
				s = sevStyle
			}
			if i == 1 && r.RunningOrDeployed {
				s = cell.Foreground(green).Bold(true)
			}
			b.WriteString(s.Width(widths[i]).MaxWidth(widths[i]).Render(trunc(v, widths[i]-2)))
		}
		b.WriteString("\n")
	}
	if len(rows) > limit {
		b.WriteString(lipgloss.NewStyle().Foreground(muted).Render(fmt.Sprintf("\n… %d more rows. Use --format csv/json/md for full output.\n", len(rows)-limit)))
	}
	return b.String()
}

func Markdown(rows []model.Row, limit int) string {
	if limit <= 0 || limit > len(rows) {
		limit = len(rows)
	}
	t1, t2, rt := model.Summary(rows)
	var b strings.Builder
	b.WriteString("# ECR Inspector Runtime Prioritizer Report\n\n")
	b.WriteString(fmt.Sprintf("- Findings: **%d**\n- Tier 1: **%d**\n- Tier 2: **%d**\n- Runtime matched: **%d**\n\n", len(rows), t1, t2, rt))
	b.WriteString("| Tier | Runtime | Severity | CVSS | CVE | Repository | Tags | Package | Installed | Fixed | Locations |\n")
	b.WriteString("|---|---:|---|---:|---|---|---|---|---|---|---|\n")
	for _, r := range rows[:limit] {
		locs := []string{}
		for _, h := range r.RuntimeLocations {
			locs = append(locs, h.Compact())
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %.1f | %s | %s | %s | %s | %s | %s | %s |\n", esc(r.Tier), yesNo(r.RunningOrDeployed), esc(r.Severity), r.CVSS, esc(r.CVE), esc(r.Repository), esc(strings.Join(r.ImageTags, ",")), esc(r.Package), esc(r.InstalledVersion), esc(r.FixedVersion), esc(strings.Join(locs, "; "))))
	}
	return b.String()
}

func GlowMarkdown(md string) string {
	r, err := glamour.NewTermRenderer(glamour.WithAutoStyle(), glamour.WithWordWrap(120))
	if err != nil {
		return md
	}
	out, err := r.Render(md)
	if err != nil {
		return md
	}
	return out
}

func WriteCSV(path string, rows []model.Row) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"tier", "runtime", "severity", "cvss", "cve", "region", "repository", "tags", "digest", "package", "installed", "fixed", "exploit_available", "fix_available", "locations", "finding_arn"})
	for _, r := range rows {
		locs := []string{}
		for _, h := range r.RuntimeLocations {
			locs = append(locs, h.Compact())
		}
		_ = w.Write([]string{r.Tier, yesNo(r.RunningOrDeployed), r.Severity, fmt.Sprintf("%.1f", r.CVSS), r.CVE, r.Region, r.Repository, strings.Join(r.ImageTags, ","), r.ImageDigest, r.Package, r.InstalledVersion, r.FixedVersion, r.ExploitAvailable, r.FixAvailable, strings.Join(locs, "; "), r.FindingARN})
	}
	return w.Error()
}

func WriteJSON(path string, rows []model.Row) error {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}
func WriteMD(path string, rows []model.Row) error {
	return os.WriteFile(path, []byte(Markdown(rows, 0)), 0644)
}
func JSONString(rows []model.Row) string {
	b, _ := json.MarshalIndent(rows, "", "  ")
	return string(b)
}
func CSVString(rows []model.Row) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"tier", "runtime", "severity", "cvss", "cve", "repository", "package", "fixed"})
	for _, r := range rows {
		_ = w.Write([]string{r.Tier, yesNo(r.RunningOrDeployed), r.Severity, fmt.Sprintf("%.1f", r.CVSS), r.CVE, r.Repository, r.Package, r.FixedVersion})
	}
	w.Flush()
	return buf.String()
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}
func trunc(s string, n int) string {
	if n <= 0 || len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
func esc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }
