package render

import (
	"encoding/csv"
	"strings"
	"testing"

	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

func TestCSVStringShape(t *testing.T) {
	out := CSVString([]model.Row{{Tier: "Tier 1", RunningOrDeployed: true, Severity: "CRITICAL", CVSS: 9.8, CVE: "CVE-1", Repository: "repo", Package: "openssl", FixedVersion: "1.2.3"}})
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header and one row, got %d records", len(records))
	}
	if got, want := strings.Join(records[0], ","), "tier,runtime,severity,cvss,cve,repository,package,fixed"; got != want {
		t.Fatalf("unexpected CSV header: %q", got)
	}
	if records[1][1] != "YES" || records[1][3] != "9.8" {
		t.Fatalf("unexpected CSV row: %#v", records[1])
	}
}

func TestMarkdownEscapesPipesAndNewlines(t *testing.T) {
	out := Markdown([]model.Row{{Tier: "Tier 1", Severity: "HIGH", CVE: "CVE|1", Repository: "repo\nname", Package: "pkg", FixedVersion: "fixed"}}, 0)
	if !strings.Contains(out, "CVE\\|1") {
		t.Fatalf("markdown did not escape pipe: %s", out)
	}
	if strings.Contains(out, "repo\nname") {
		t.Fatalf("markdown did not flatten newline: %s", out)
	}
}

func TestTableLimitAndTruncAreRuneSafe(t *testing.T) {
	if got := trunc("äöüß", 3); got != "äö…" {
		t.Fatalf("unexpected rune truncation: %q", got)
	}
	rows := []model.Row{{CVE: "CVE-1"}, {CVE: "CVE-2"}}
	out := Table(rows, 1)
	if !strings.Contains(out, "CVE-1") || strings.Contains(out, "CVE-2") || !strings.Contains(out, "1 more rows") {
		t.Fatalf("table limit not respected:\n%s", out)
	}
}
