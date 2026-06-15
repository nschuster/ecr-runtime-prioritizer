package app

import (
	"strings"
	"testing"

	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/render"
)

func TestDemoRowsSortAndRender(t *testing.T) {
	rows := DemoRows()
	model.SortRows(rows)
	if rows[0].Tier != "Tier 1" || rows[0].Severity != "CRITICAL" || !rows[0].RunningOrDeployed {
		t.Fatalf("unexpected top priority row: %+v", rows[0])
	}
	out := render.Table(rows, 4)
	for _, want := range []string{"ECR Inspector Runtime Prioritizer", "CVE-2025-12345", "checkout-api", "Tier 1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q:\n%s", want, out)
		}
	}
}
