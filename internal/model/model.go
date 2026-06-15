package model

import "sort"

type Config struct {
	Profile       string
	Regions       []string
	IncludeMedium bool
	EKS           bool
	ECS           bool
	KubeContexts  []string
	NoKubeconfig  bool
	Format        string
	OutPrefix     string
	TUI           bool
	Demo          bool
	Limit         int
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
