package main

import (
	"context"
	"fmt"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/log"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/app"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/awsdata"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
	uitool "github.com/nschuster/ecr-runtime-prioritizer/internal/tui"
	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	log.SetReportCaller(false)
	if err := fang.Execute(context.Background(), newRootCommand()); err != nil {
		log.Error("command failed", "err", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var regions, contexts string
	cfg := model.Config{Format: "table", Limit: 20, TUI: true}
	cmd := &cobra.Command{
		Use:   "ecr-prioritizer",
		Short: "Prioritize Amazon Inspector ECR CVEs by exploitability, fixability, and runtime usage",
		Long: `ecr-prioritizer scans Amazon Inspector2 ECR findings and enriches them with EKS/ECS runtime evidence.

Tiering:
  Tier 1 = exploitAvailable YES + fixAvailable YES
  Tier 2 = fixAvailable YES + everything else

Use --demo for a safe local preview without AWS credentials.`,
		Example: `  ecr-prioritizer --demo
  ecr-prioritizer --demo --tui=false
  ecr-prioritizer --regions eu-central-1 --eks
  ecr-prioritizer --regions eu-central-1,eu-west-1 --eks --out-prefix prod-ecr-vulns
  ecr-prioritizer --profile prod --regions eu-central-1 --eks --ecs --format md`,
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if regions != "" {
				cfg.Regions = app.SplitCSV(regions)
			} else {
				cfg.Regions = awsdata.RegionsDefault()
			}
			cfg.KubeContexts = app.SplitCSV(contexts)
			if len(cfg.Regions) == 0 && !cfg.Demo {
				return fmt.Errorf("at least one region is required")
			}
			if cfg.TUI && cfg.Format == "table" {
				rows, err := app.CollectRows(cmd.Context(), cfg)
				if err != nil {
					return err
				}
				if cfg.OutPrefix != "" {
					if err := app.WriteReports(cfg.OutPrefix, rows, []string{"csv", "json", "md"}); err != nil {
						return err
					}
				}
				return uitool.Run(cmd.Context(), cfg, rows)
			}
			return app.Run(cmd.Context(), cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.Profile, "profile", "", "optional AWS profile name; when omitted, uses the normal local AWS credential chain")
	cmd.Flags().StringVar(&regions, "regions", "", "comma-separated AWS regions (default: eu-central-1,eu-west-1,us-east-1)")
	cmd.Flags().BoolVar(&cfg.IncludeMedium, "include-medium", false, "include MEDIUM findings in addition to HIGH/CRITICAL")
	cmd.Flags().BoolVar(&cfg.EKS, "eks", false, "check EKS deployed/running pod images")
	cmd.Flags().BoolVar(&cfg.ECS, "ecs", false, "check ECS running/pending task images")
	cmd.Flags().StringVar(&contexts, "kube-contexts", "", "comma-separated kube contexts to inspect instead of discovering EKS clusters")
	cmd.Flags().BoolVar(&cfg.NoKubeconfig, "no-update-kubeconfig", false, "do not call aws eks update-kubeconfig for discovered clusters")
	cmd.Flags().StringVar(&cfg.Format, "format", "table", "output format: table, md, csv, json")
	cmd.Flags().StringVar(&cfg.OutPrefix, "out-prefix", "", "write CSV, JSON, and Markdown reports to this prefix")
	cmd.Flags().BoolVar(&cfg.TUI, "tui", true, "launch the interactive Bubble Tea TUI for table output; set --tui=false for plain table output")
	cmd.Flags().BoolVar(&cfg.Demo, "demo", false, "use built-in demo data instead of AWS APIs")
	cmd.Flags().IntVar(&cfg.Limit, "limit", 20, "maximum rows for terminal table/markdown output; 0 means all")
	return cmd
}
