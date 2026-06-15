package app

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/awsdata"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/render"
	runidx "github.com/nschuster/ecr-runtime-prioritizer/internal/runtime"
)

func Run(ctx context.Context, cfg model.Config) error {
	rows, err := CollectRows(ctx, cfg)
	if err != nil {
		return err
	}
	if cfg.OutPrefix != "" {
		if err := WriteReports(cfg.OutPrefix, rows, []string{"csv", "json", "md"}); err != nil {
			return err
		}
	}
	switch cfg.Format {
	case "json":
		fmt.Println(render.JSONString(rows))
	case "csv":
		fmt.Print(render.CSVString(rows))
	case "md":
		fmt.Print(render.GlowMarkdown(render.Markdown(rows, cfg.Limit)))
	default:
		fmt.Print(render.Table(rows, cfg.Limit))
	}
	return nil
}

func CollectRows(ctx context.Context, cfg model.Config) ([]model.Row, error) {
	log.Info("starting report", "format", cfg.Format, "demo", cfg.Demo)
	var rows []model.Row
	if cfg.Demo {
		rows = DemoRows()
	} else {
		s, err := awsdata.New(ctx, cfg.Profile)
		if err != nil {
			return nil, err
		}
		refs := []runidx.ImageRef{}
		if cfg.EKS {
			stopTunnel, err := startKubeTunnel(ctx, cfg)
			if err != nil {
				return nil, err
			}
			if stopTunnel != nil {
				defer stopTunnel()
			}
			refs = append(refs, s.CollectEKS(ctx, cfg)...)
		}
		if cfg.ECS {
			refs = append(refs, s.CollectECS(ctx, cfg.Regions)...)
		}
		idx := runidx.BuildIndex(refs)
		for _, region := range cfg.Regions {
			log.Info("scanning Inspector2 findings", "region", region)
			got, err := s.Findings(ctx, region, cfg.IncludeMedium, idx)
			if err != nil {
				log.Warn("region failed", "region", region, "err", err)
				continue
			}
			rows = append(rows, got...)
		}
	}
	rows = model.DeduplicateRows(rows)
	model.SortRows(rows)
	for _, r := range rows {
		log.Info("finding", "tier", r.Tier, "severity", r.Severity, "cve", r.CVE, "repository", r.Repository, "package", r.Package, "fixed", r.FixedVersion, "exploit", r.ExploitAvailable, "runtime", r.RunningOrDeployed)
	}
	t1, t2, rt := model.Summary(rows)
	log.Info("report complete", "rows", len(rows), "tier1", t1, "tier2", t2, "runtime_matched", rt)
	return rows, nil
}

func startKubeTunnel(ctx context.Context, cfg model.Config) (func(), error) {
	if strings.TrimSpace(cfg.KubeTunnelCommand) == "" {
		return nil, nil
	}
	log.Info("starting Kubernetes tunnel command", "command", cfg.KubeTunnelCommand)
	cmd := exec.CommandContext(ctx, "sh", "-c", cfg.KubeTunnelCommand)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start kube tunnel command: %w", err)
	}
	wait := cfg.KubeTunnelWait
	if wait <= 0 {
		wait = 3
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("kube tunnel command exited early: %w", err)
		}
		log.Info("Kubernetes tunnel command completed before scan; continuing")
		return nil, nil
	case <-time.After(time.Duration(wait) * time.Second):
		log.Info("Kubernetes tunnel command ready window elapsed", "wait_seconds", wait)
	}
	return func() {
		if cmd.Process != nil {
			log.Info("stopping Kubernetes tunnel command")
			_ = cmd.Process.Kill()
		}
	}, nil
}

func WriteReports(prefix string, rows []model.Row, formats []string) error {
	if prefix == "" {
		return fmt.Errorf("report prefix is required")
	}
	for _, format := range formats {
		switch strings.ToLower(strings.TrimSpace(format)) {
		case "csv":
			if err := render.WriteCSV(prefix+".csv", rows); err != nil {
				return err
			}
			log.Info("wrote report", "path", prefix+".csv", "format", "csv")
		case "json":
			if err := render.WriteJSON(prefix+".json", rows); err != nil {
				return err
			}
			log.Info("wrote report", "path", prefix+".json", "format", "json")
		case "md", "markdown":
			if err := render.WriteMD(prefix+".md", rows); err != nil {
				return err
			}
			log.Info("wrote report", "path", prefix+".md", "format", "md")
		case "":
			continue
		default:
			return fmt.Errorf("unsupported report format %q", format)
		}
	}
	return nil
}

func DemoRows() []model.Row {
	hit := model.RuntimeHit{Platform: "EKS", Region: "eu-central-1", Cluster: "prod-eks", Namespace: "payments", Workload: "ReplicaSet/checkout-api-6c8c9", Pod: "checkout-api-6c8c9-x2k9q", Container: "api", Image: "123456789012.dkr.ecr.eu-central-1.amazonaws.com/checkout-api:prod-2026-06-15", ImageID: "123456789012.dkr.ecr.eu-central-1.amazonaws.com/checkout-api@sha256:aaa", Status: "running"}
	return []model.Row{
		{Tier: "Tier 1", Severity: "CRITICAL", CVSS: 9.8, ExploitAvailable: "YES", FixAvailable: "YES", CVE: "CVE-2025-12345", Title: "openssl buffer overflow", AccountID: "123456789012", Region: "eu-central-1", Repository: "checkout-api", ImageTags: []string{"prod-2026-06-15", "latest"}, ImageDigest: "sha256:aaa", ImageURI: "123456789012.dkr.ecr.eu-central-1.amazonaws.com/checkout-api@sha256:aaa", Package: "openssl", InstalledVersion: "1.1.1k", FixedVersion: "1.1.1w", PackageManager: "OS", FirstObservedAt: "2026-06-15T08:00:00Z", UpdatedAt: "2026-06-15T09:00:00Z", FindingARN: "arn:aws:inspector2:eu-central-1:123456789012:finding/demo1", InspectorStatus: "ACTIVE", RunningOrDeployed: true, RuntimeLocations: []model.RuntimeHit{hit}},
		{Tier: "Tier 1", Severity: "HIGH", CVSS: 8.8, ExploitAvailable: "YES", FixAvailable: "YES", CVE: "CVE-2025-22222", Region: "eu-central-1", Repository: "worker", ImageTags: []string{"v1.42.0"}, ImageDigest: "sha256:bbb", Package: "glibc", InstalledVersion: "2.31", FixedVersion: "2.35", PackageManager: "OS", FindingARN: "arn:aws:inspector2:eu-central-1:123456789012:finding/demo2", InspectorStatus: "ACTIVE"},
		{Tier: "Tier 2", Severity: "CRITICAL", CVSS: 9.1, ExploitAvailable: "NO", FixAvailable: "YES", CVE: "CVE-2024-99999", Region: "eu-west-1", Repository: "frontend", ImageTags: []string{"2026-06-14"}, ImageDigest: "sha256:ccc", Package: "curl", InstalledVersion: "7.68.0", FixedVersion: "8.5.0", PackageManager: "OS", FindingARN: "arn:aws:inspector2:eu-west-1:123456789012:finding/demo3", InspectorStatus: "ACTIVE"},
		{Tier: "Tier 2", Severity: "HIGH", CVSS: 7.8, ExploitAvailable: "NO", FixAvailable: "YES", CVE: "CVE-2024-44444", Region: "eu-central-1", Repository: "reporting", ImageTags: []string{"stable"}, ImageDigest: "sha256:ddd", Package: "python", InstalledVersion: "3.10.8", FixedVersion: "3.10.14", PackageManager: "OS", FindingARN: "arn:aws:inspector2:eu-central-1:123456789012:finding/demo4", InspectorStatus: "ACTIVE"},
	}
}

func SplitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if q := strings.TrimSpace(p); q != "" {
			out = append(out, q)
		}
	}
	return out
}
