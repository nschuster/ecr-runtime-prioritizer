package model

import (
	"sort"
	"strings"
)

type Config struct {
	Profile              string
	Regions              []string
	IncludeMedium        bool
	EKS                  bool
	ECS                  bool
	KubeContexts         []string
	NoKubeconfig         bool
	KubeTunnelCommand    string
	KubeTunnelWait       int
	KubeTunnelConfig     string
	PromptForJumpHosts   bool
	SaveKubeTunnelConfig bool
	ClusterTunnels       map[string]ClusterTunnel
	Format               string
	OutPrefix            string
	TUI                  bool
	Demo                 bool
	Limit                int
}

type ClusterTunnel struct {
	JumpHostID string `json:"jump_host_id"`
	RemoteHost string `json:"remote_host,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	Context    string `json:"context,omitempty"`
}

type RuntimeHit struct {
	Platform  string `json:"platform"`
	Region    string `json:"region"`
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Container string `json:"container,omitempty"`
	Image     string `json:"image,omitempty"`
	ImageID   string `json:"image_id,omitempty"`
	Status    string `json:"status,omitempty"`
}

func (h RuntimeHit) Compact() string {
	if h.Platform == "EKS" {
		return h.Platform + ":" + h.Region + ":" + h.Cluster + ":" + h.Namespace + "/" + h.Workload + " pod=" + h.Pod + " container=" + h.Container
	}
	return h.Platform + ":" + h.Region + ":" + h.Cluster + ":" + h.Workload + " status=" + h.Status
}

type Row struct {
	Tier              string       `json:"tier"`
	Severity          string       `json:"severity"`
	CVSS              float64      `json:"cvss"`
	EPSS              *float64     `json:"epss,omitempty"`
	ExploitAvailable  string       `json:"exploit_available"`
	FixAvailable      string       `json:"fix_available"`
	CVE               string       `json:"cve"`
	Title             string       `json:"title"`
	AccountID         string       `json:"account_id"`
	Region            string       `json:"region"`
	Repository        string       `json:"repository"`
	ImageTags         []string     `json:"image_tags"`
	ImageDigest       string       `json:"image_digest"`
	ImageURI          string       `json:"image_uri"`
	Package           string       `json:"package"`
	InstalledVersion  string       `json:"installed_version"`
	FixedVersion      string       `json:"fixed_version"`
	PackageManager    string       `json:"package_manager"`
	FirstObservedAt   string       `json:"first_observed_at"`
	UpdatedAt         string       `json:"updated_at"`
	FindingARN        string       `json:"finding_arn"`
	InspectorStatus   string       `json:"inspector_status"`
	RunningOrDeployed bool         `json:"running_or_deployed"`
	RuntimeLocations  []RuntimeHit `json:"runtime_locations"`
}

func DeduplicateRows(rows []Row) []Row {
	if len(rows) < 2 {
		out := append([]Row(nil), rows...)
		for i := range out {
			out[i].RuntimeLocations = dedupeRuntimeLocations(out[i].RuntimeLocations)
			out[i].RunningOrDeployed = out[i].RunningOrDeployed || len(out[i].RuntimeLocations) > 0
		}
		return out
	}
	byKey := map[string]int{}
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		row.RuntimeLocations = dedupeRuntimeLocations(row.RuntimeLocations)
		row.RunningOrDeployed = row.RunningOrDeployed || len(row.RuntimeLocations) > 0
		key := row.DedupeKey()
		if idx, ok := byKey[key]; ok {
			out[idx] = mergeRows(out[idx], row)
			continue
		}
		byKey[key] = len(out)
		out = append(out, row)
	}
	return out
}

func (r Row) DedupeKey() string {
	imageKey := strings.ToLower(strings.TrimSpace(r.ImageDigest))
	if imageKey == "" {
		tags := uniqueStrings(append([]string{}, r.ImageTags...))
		sort.Strings(tags)
		imageKey = strings.ToLower(strings.Join(tags, ","))
	}
	parts := []string{
		strings.ToLower(strings.TrimSpace(r.AccountID)),
		strings.ToLower(strings.TrimSpace(r.Region)),
		strings.ToLower(strings.TrimSpace(r.Repository)),
		imageKey,
		strings.ToUpper(strings.TrimSpace(r.CVE)),
		strings.ToLower(strings.TrimSpace(r.PackageManager)),
		strings.ToLower(strings.TrimSpace(r.Package)),
		strings.TrimSpace(r.InstalledVersion),
		strings.TrimSpace(r.FixedVersion),
	}
	return strings.Join(parts, "\x00")
}

func mergeRows(a, b Row) Row {
	best := a
	if rowPriorityLess(b, a) {
		best = b
	}
	best.RuntimeLocations = dedupeRuntimeLocations(append(append([]RuntimeHit{}, a.RuntimeLocations...), b.RuntimeLocations...))
	best.RunningOrDeployed = a.RunningOrDeployed || b.RunningOrDeployed || len(best.RuntimeLocations) > 0
	best.FindingARN = joinUnique(a.FindingARN, b.FindingARN)
	best.ImageTags = uniqueStrings(append(append([]string{}, a.ImageTags...), b.ImageTags...))
	return best
}

func dedupeRuntimeLocations(hits []RuntimeHit) []RuntimeHit {
	seen := map[string]struct{}{}
	out := make([]RuntimeHit, 0, len(hits))
	for _, h := range hits {
		key := strings.Join([]string{h.Platform, h.Region, h.Cluster, h.Namespace, h.Workload, h.Pod, h.Container, h.Image, h.ImageID, h.Status}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	return out
}

func joinUnique(a, b string) string {
	return strings.Join(uniqueStrings(splitJoined(a, b)), ",")
}

func splitJoined(values ...string) []string {
	var out []string
	for _, v := range values {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func rowPriorityLess(a, b Row) bool {
	severity := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
	tier := map[string]int{"Tier 1": 1, "Tier 2": 2}
	keysA := []any{tier[a.Tier], !a.RunningOrDeployed, severity[a.Severity], -a.CVSS}
	keysB := []any{tier[b.Tier], !b.RunningOrDeployed, severity[b.Severity], -b.CVSS}
	for k := range keysA {
		switch av := keysA[k].(type) {
		case int:
			bv := keysB[k].(int)
			if av != bv {
				return av < bv
			}
		case bool:
			bv := keysB[k].(bool)
			if av != bv {
				return !av && bv
			}
		case float64:
			bv := keysB[k].(float64)
			if av != bv {
				return av < bv
			}
		}
	}
	return false
}

func SortRows(rows []Row) {
	severity := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
	tier := map[string]int{"Tier 1": 1, "Tier 2": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		keysA := []any{tier[a.Tier], !a.RunningOrDeployed, severity[a.Severity], -a.CVSS, a.Repository, a.CVE}
		keysB := []any{tier[b.Tier], !b.RunningOrDeployed, severity[b.Severity], -b.CVSS, b.Repository, b.CVE}
		for k := range keysA {
			switch av := keysA[k].(type) {
			case int:
				bv := keysB[k].(int)
				if av != bv {
					return av < bv
				}
			case bool:
				bv := keysB[k].(bool)
				if av != bv {
					return !av && bv
				}
			case float64:
				bv := keysB[k].(float64)
				if av != bv {
					return av < bv
				}
			case string:
				bv := keysB[k].(string)
				if av != bv {
					return av < bv
				}
			}
		}
		return false
	})
}

func Summary(rows []Row) (tier1, tier2, runtime int) {
	for _, r := range rows {
		if r.Tier == "Tier 1" {
			tier1++
		} else if r.Tier == "Tier 2" {
			tier2++
		}
		if r.RunningOrDeployed {
			runtime++
		}
	}
	return
}
