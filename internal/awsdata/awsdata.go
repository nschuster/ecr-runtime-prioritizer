package awsdata

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

type Scanner struct {
	cfg     aws.Config
	profile string
}

func New(ctx context.Context, profile string) (*Scanner, error) {
	opts := []func(*awscfg.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(profile))
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &Scanner{cfg: cfg, profile: profile}, nil
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

type EKSClusterInfo struct {
	EndpointHost string
}

func (s *Scanner) EKSClusterInfo(ctx context.Context, region, name string) (EKSClusterInfo, error) {
	c := eks.NewFromConfig(s.cfg, func(o *eks.Options) { o.Region = region })
	out, err := c.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(name)})
	if err != nil {
		return EKSClusterInfo{}, err
	}
	endpoint := ""
	if out.Cluster != nil {
		endpoint = aws.ToString(out.Cluster.Endpoint)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return EKSClusterInfo{EndpointHost: strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")}, nil
	}
	return EKSClusterInfo{EndpointHost: u.Host}, nil
}

func (s *Scanner) prepareClusterAccess(ctx context.Context, cfg model.Config, region, cluster, contextName, endpointHost string, ordinal int) (func(), runidx.KubeAccess) {
	access := runidx.KubeAccess{Context: contextName, Kubeconfig: cfg.Kubeconfig, Region: region, Cluster: cluster}
	if cfg.ClusterTunnels == nil {
		cfg.ClusterTunnels = map[string]model.ClusterTunnel{}
	}
	key := region + "/" + cluster
	tunnel, ok := lookupTunnel(cfg.ClusterTunnels, key, contextName, cluster)
	if !ok && cfg.PromptForJumpHosts && stdinInteractive() {
		if jump := promptJumpHost(region, cluster); jump != "" {
			tunnel = model.ClusterTunnel{JumpHostID: jump}
			cfg.ClusterTunnels[key] = tunnel
			ok = true
		}
	}
	if !ok || strings.TrimSpace(tunnel.JumpHostID) == "" {
		return nil, access
	}
	if tunnel.RemoteHost == "" {
		tunnel.RemoteHost = endpointHost
	}
	if tunnel.RemoteHost == "" {
		log.Warn("no EKS endpoint host for tunnel; collecting with normal kube context", "cluster", cluster)
		return nil, access
	}
	if tunnel.LocalPort <= 0 {
		tunnel.LocalPort = 18443 + ordinal
	}
	cfg.ClusterTunnels[key] = tunnel
	params := fmt.Sprintf(`{"host":["%s"],"portNumber":["443"],"localPortNumber":["%d"]}`, tunnel.RemoteHost, tunnel.LocalPort)
	cmd := exec.CommandContext(ctx, "aws", "ssm", "start-session", "--target", tunnel.JumpHostID, "--document-name", "AWS-StartPortForwardingSessionToRemoteHost", "--parameters", params)
	if s.profile != "" {
		cmd.Env = append(os.Environ(), "AWS_PROFILE="+s.profile, "AWS_REGION="+region)
	} else {
		cmd.Env = append(os.Environ(), "AWS_REGION="+region)
	}
	log.Info("starting EKS SSM tunnel", "region", region, "cluster", cluster, "jump_host", tunnel.JumpHostID, "local_port", tunnel.LocalPort, "remote_host", tunnel.RemoteHost)
	if err := cmd.Start(); err != nil {
		log.Warn("cannot start EKS SSM tunnel; collecting with normal kube context", "cluster", cluster, "err", err)
		return nil, access
	}
	wait := cfg.KubeTunnelWait
	if wait <= 0 {
		wait = 3
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		log.Warn("EKS SSM tunnel exited before collection; collecting with normal kube context", "cluster", cluster, "err", err)
		return nil, access
	case <-time.After(time.Duration(wait) * time.Second):
	}
	access.Server = fmt.Sprintf("https://127.0.0.1:%d", tunnel.LocalPort)
	access.TLSServerName = tunnel.RemoteHost
	return func() {
		if cmd.Process != nil {
			log.Info("stopping EKS SSM tunnel", "cluster", cluster)
			_ = cmd.Process.Kill()
		}
	}, access
}

func (s *Scanner) CollectEKS(ctx context.Context, cfg model.Config) []runidx.ImageRef {
	var refs []runidx.ImageRef
	if cfg.ClusterTunnels == nil {
		cfg.ClusterTunnels = map[string]model.ClusterTunnel{}
	}
	if len(cfg.KubeContexts) > 0 {
		access := make([]runidx.KubeAccess, 0, len(cfg.KubeContexts))
		var stops []func()
		defer func() {
			for _, stop := range stops {
				stop()
			}
		}()
		for i, kc := range cfg.KubeContexts {
			region, cluster := runidx.ParseKubeContext(kc)
			tunnel, _ := lookupTunnel(cfg.ClusterTunnels, kc, region+"/"+cluster, cluster)
			stop, acc := s.prepareClusterAccess(ctx, cfg, region, cluster, kc, tunnel.RemoteHost, i)
			if stop != nil {
				stops = append(stops, stop)
			}
			access = append(access, acc)
		}
		got, _ := runidx.CollectEKSWithAccess(ctx, access)
		return got
	}
	for _, region := range cfg.Regions {
		clusters, err := s.EKSClusters(ctx, region)
		if err != nil {
			log.Warn("cannot list EKS clusters", "region", region, "err", err)
			continue
		}
		for i, cluster := range clusters {
			contextName := region + "/" + cluster
			info, err := s.EKSClusterInfo(ctx, region, cluster)
			if err != nil {
				log.Warn("cannot describe EKS cluster", "region", region, "cluster", cluster, "err", err)
			}
			if !cfg.NoKubeconfig {
				log.Info("updating kubeconfig", "region", region, "cluster", cluster, "kubeconfig", cfg.Kubeconfig)
				args := updateKubeconfigArgs(region, cluster, contextName, cfg.Kubeconfig, s.profile)
				if cfg.Kubeconfig != "" {
					if err := os.MkdirAll(filepath.Dir(cfg.Kubeconfig), 0o755); err != nil {
						log.Warn("cannot create kubeconfig directory", "path", cfg.Kubeconfig, "err", err)
						continue
					}
				}
				cmd := exec.CommandContext(ctx, "aws", args...)
				if b, err := cmd.CombinedOutput(); err != nil {
					log.Warn("update-kubeconfig failed", "cluster", cluster, "err", err, "output", string(b))
					continue
				}
			}
			stop, access := s.prepareClusterAccess(ctx, cfg, region, cluster, contextName, info.EndpointHost, i)
			if stop != nil {
				defer stop()
			}
			got, _ := runidx.CollectEKSWithAccess(ctx, []runidx.KubeAccess{access})
			refs = append(refs, got...)
		}
	}
	if cfg.SaveKubeTunnelConfig && len(cfg.ClusterTunnels) > 0 {
		if err := saveTunnelConfig(cfg.KubeTunnelConfig, cfg.ClusterTunnels); err != nil {
			log.Warn("cannot save kube tunnel config", "path", cfg.KubeTunnelConfig, "err", err)
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

func lookupTunnel(tunnels map[string]model.ClusterTunnel, keys ...string) (model.ClusterTunnel, bool) {
	for _, key := range keys {
		if t, ok := tunnels[key]; ok {
			return t, true
		}
	}
	return model.ClusterTunnel{}, false
}

func stdinInteractive() bool {
	st, err := os.Stdin.Stat()
	return err == nil && (st.Mode()&os.ModeCharDevice) != 0
}

func promptJumpHost(region, cluster string) string {
	fmt.Fprintf(os.Stderr, "SSM jump host instance ID for EKS cluster %s/%s (blank = no tunnel): ", region, cluster)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func saveTunnelConfig(path string, tunnels map[string]model.ClusterTunnel) error {
	if path == "" {
		return nil
	}
	payload := struct {
		Clusters map[string]model.ClusterTunnel `json:"clusters"`
	}{Clusters: tunnels}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func updateKubeconfigArgs(region, cluster, contextName, kubeconfig, profile string) []string {
	args := []string{"eks", "update-kubeconfig", "--region", region, "--name", cluster, "--alias", contextName}
	if kubeconfig != "" {
		args = append(args, "--kubeconfig", kubeconfig)
	}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args
}

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
