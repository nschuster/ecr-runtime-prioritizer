package awsdata

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	etypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/charmbracelet/log"

	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
	runidx "github.com/nschuster/ecr-runtime-prioritizer/internal/runtime"
)

type Scanner struct{ cfg aws.Config }

func New(ctx context.Context, profile string) (*Scanner, error) {
	opts := []func(*awscfg.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(profile))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Scanner{cfg: cfg}, nil
}

func (s *Scanner) EKSClusters(ctx context.Context, region string) ([]string, error) {
	c := eks.NewFromConfig(s.cfg, func(o *eks.Options) { o.Region = region })
	var out []string
	p := eks.NewListClustersPaginator(c, &eks.ListClustersInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return out, err
		}
		out = append(out, page.Clusters...)
	}
	return out, nil
}

func (s *Scanner) CollectEKS(ctx context.Context, regions []string, kubeContexts []string, update bool) []runidx.ImageRef {
	var refs []runidx.ImageRef
	if len(kubeContexts) > 0 {
		got, _ := runidx.CollectEKS(ctx, regions, kubeContexts, false)
		return got
	}
	for _, region := range regions {
		clusters, err := s.EKSClusters(ctx, region)
		if err != nil {
			log.Warn("cannot list EKS clusters", "region", region, "err", err)
			continue
		}
		for _, cluster := range clusters {
			contextName := region + "/" + cluster
			if update {
				log.Info("updating kubeconfig", "region", region, "cluster", cluster)
				cmd := exec.CommandContext(ctx, "aws", "eks", "update-kubeconfig", "--region", region, "--name", cluster, "--alias", contextName)
				if b, err := cmd.CombinedOutput(); err != nil {
					log.Warn("update-kubeconfig failed", "cluster", cluster, "err", err, "output", string(b))
					continue
				}
			}
			got, _ := runidx.CollectEKS(ctx, []string{region}, []string{contextName}, false)
			refs = append(refs, got...)
		}
	}
	return refs
}

func (s *Scanner) CollectECS(ctx context.Context, regions []string) []runidx.ImageRef {
	var refs []runidx.ImageRef
	for _, region := range regions {
		c := ecs.NewFromConfig(s.cfg, func(o *ecs.Options) { o.Region = region })
		clusters := []string{}
		cp := ecs.NewListClustersPaginator(c, &ecs.ListClustersInput{})
		for cp.HasMorePages() {
			page, err := cp.NextPage(ctx)
			if err != nil {
				log.Warn("cannot list ECS clusters", "region", region, "err", err)
				break
			}
			clusters = append(clusters, page.ClusterArns...)
		}
		for _, cluster := range clusters {
			for _, desired := range []string{"RUNNING", "PENDING"} {
				tp := ecs.NewListTasksPaginator(c, &ecs.ListTasksInput{Cluster: aws.String(cluster), DesiredStatus: awstaskstatus(desired)})
				for tp.HasMorePages() {
					page, err := tp.NextPage(ctx)
					if err != nil {
						log.Warn("cannot list ECS tasks", "cluster", cluster, "err", err)
						break
					}
					for _, chunk := range chunks(page.TaskArns, 100) {
						d, err := c.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: chunk})
						if err != nil {
							continue
						}
						for _, t := range d.Tasks {
							for _, ctr := range t.Containers {
								refs = append(refs, runidx.ImageRef{Hit: model.RuntimeHit{Platform: "ECS", Region: region, Cluster: last(cluster), Workload: aws.ToString(t.TaskDefinitionArn), Pod: last(aws.ToString(t.TaskArn)), Container: aws.ToString(ctr.Name), Image: aws.ToString(ctr.Image), ImageID: aws.ToString(ctr.ImageDigest), Status: aws.ToString(t.LastStatus)}})
							}
						}
					}
				}
			}
		}
	}
	return refs
}

func awstaskstatus(s string) etypes.DesiredStatus { return etypes.DesiredStatus(s) }

func (s *Scanner) Findings(ctx context.Context, region string, includeMedium bool, runtime runidx.Index) ([]model.Row, error) {
	client := inspector2.NewFromConfig(s.cfg, func(o *inspector2.Options) { o.Region = region })
	sevs := []itypes.Severity{itypes.SeverityCritical, itypes.SeverityHigh}
	if includeMedium {
		sevs = append(sevs, itypes.SeverityMedium)
	}
	fc := &itypes.FilterCriteria{
		ResourceType:  []itypes.StringFilter{{Comparison: itypes.StringComparisonEquals, Value: aws.String("AWS_ECR_CONTAINER_IMAGE")}},
		Severity:      severityFilters(sevs),
		FindingStatus: []itypes.StringFilter{{Comparison: itypes.StringComparisonEquals, Value: aws.String("ACTIVE")}},
		FixAvailable:  []itypes.StringFilter{{Comparison: itypes.StringComparisonEquals, Value: aws.String("YES")}},
	}
	var rows []model.Row
	p := inspector2.NewListFindingsPaginator(client, &inspector2.ListFindingsInput{FilterCriteria: fc})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return rows, err
		}
		for _, f := range page.Findings {
			rows = append(rows, rowsFromFinding(f, region, runtime)...)
		}
	}
	return rows, nil
}

func severityFilters(sevs []itypes.Severity) []itypes.StringFilter {
	out := make([]itypes.StringFilter, 0, len(sevs))
	for _, s := range sevs {
		v := string(s)
		out = append(out, itypes.StringFilter{Comparison: itypes.StringComparisonEquals, Value: &v})
	}
	return out
}

func rowsFromFinding(f itypes.Finding, region string, idx runidx.Index) []model.Row {
	var ecr *itypes.AwsEcrContainerImageDetails
	if len(f.Resources) > 0 && f.Resources[0].Details != nil && f.Resources[0].Details.AwsEcrContainerImage != nil {
		ecr = f.Resources[0].Details.AwsEcrContainerImage
	}
	if ecr == nil {
		return nil
	}
	vuln := f.PackageVulnerabilityDetails
	cvss := 0.0
	if vuln != nil && len(vuln.Cvss) > 0 && vuln.Cvss[0].BaseScore != nil {
		cvss = *vuln.Cvss[0].BaseScore
	}
	tier := "Tier 2"
	if f.ExploitAvailable == itypes.ExploitAvailableYes && f.FixAvailable == itypes.FixAvailableYes {
		tier = "Tier 1"
	}
	registry := aws.ToString(ecr.Registry)
	repo := aws.ToString(ecr.RepositoryName)
	digest := aws.ToString(ecr.ImageHash)
	host := registry
	if registry != "" && !strings.Contains(registry, ".") {
		host = registry + ".dkr.ecr." + region + ".amazonaws.com"
	}
	imageURI := ""
	if host != "" && repo != "" && digest != "" {
		imageURI = host + "/" + repo + "@" + digest
	}
	keys := findingKeys(host, repo, digest, ecr.ImageTags)
	hits := runidx.Match(idx, keys)
	pkgs := []itypes.VulnerablePackage{{}}
	if vuln != nil && len(vuln.VulnerablePackages) > 0 {
		pkgs = vuln.VulnerablePackages
	}
	var rows []model.Row
	for _, p := range pkgs {
		fixed := aws.ToString(p.FixedInVersion)
		rows = append(rows, model.Row{Tier: tier, Severity: string(f.Severity), CVSS: cvss, ExploitAvailable: string(f.ExploitAvailable), FixAvailable: string(f.FixAvailable), CVE: vulnID(vuln), Title: aws.ToString(f.Title), AccountID: aws.ToString(f.AwsAccountId), Region: region, Repository: repo, ImageTags: ecr.ImageTags, ImageDigest: digest, ImageURI: imageURI, Package: aws.ToString(p.Name), InstalledVersion: aws.ToString(p.Version), FixedVersion: fixed, PackageManager: string(p.PackageManager), FirstObservedAt: tstr(f.FirstObservedAt), UpdatedAt: tstr(f.UpdatedAt), FindingARN: aws.ToString(f.FindingArn), InspectorStatus: string(f.Status), RunningOrDeployed: len(hits) > 0, RuntimeLocations: hits})
	}
	return rows
}

func findingKeys(host, repo, digest string, tags []string) []string {
	m := map[string]struct{}{}
	if digest != "" {
		if !strings.HasPrefix(digest, "sha256:") {
			digest = "sha256:" + digest
		}
		m[digest] = struct{}{}
		if repo != "" {
			m[repo+"@"+digest] = struct{}{}
		}
		if host != "" && repo != "" {
			m[host+"/"+repo+"@"+digest] = struct{}{}
		}
	}
	for _, tag := range tags {
		if repo != "" {
			m[repo+":"+tag] = struct{}{}
		}
		if host != "" && repo != "" {
			m[host+"/"+repo+":"+tag] = struct{}{}
		}
	}
	if repo != "" {
		m[repo] = struct{}{}
	}
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
func vulnID(v *itypes.PackageVulnerabilityDetails) string {
	if v == nil {
		return ""
	}
	return aws.ToString(v.VulnerabilityId)
}
func tstr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
func chunks[T any](in []T, n int) [][]T {
	var out [][]T
	for len(in) > 0 {
		if len(in) < n {
			n = len(in)
		}
		out = append(out, in[:n])
		in = in[n:]
	}
	return out
}
func last(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
func RegionsDefault() []string { return []string{"eu-central-1", "eu-west-1", "us-east-1"} }
func ErrNoRegions() error      { return fmt.Errorf("no AWS regions provided") }
