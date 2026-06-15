package model

import "testing"

func TestDeduplicateRowsMergesSameCVEImagePackageFinding(t *testing.T) {
	rows := []Row{
		{Tier: "Tier 2", Severity: "HIGH", CVSS: 7.5, CVE: "CVE-1", Region: "eu-central-1", Repository: "api", ImageDigest: "sha256:aaa", Package: "openssl", InstalledVersion: "1.0", FixedVersion: "1.1", FindingARN: "arn:1", RuntimeLocations: []RuntimeHit{{Platform: "EKS", Cluster: "prod", Namespace: "a", Workload: "Deployment/api", Pod: "api-1", Container: "api"}}},
		{Tier: "Tier 1", Severity: "CRITICAL", CVSS: 9.8, CVE: "CVE-1", Region: "eu-central-1", Repository: "api", ImageDigest: "sha256:aaa", Package: "openssl", InstalledVersion: "1.0", FixedVersion: "1.1", FindingARN: "arn:1", RunningOrDeployed: true, RuntimeLocations: []RuntimeHit{{Platform: "EKS", Cluster: "prod", Namespace: "a", Workload: "Deployment/api", Pod: "api-2", Container: "api"}}},
		{Tier: "Tier 1", Severity: "CRITICAL", CVSS: 9.8, CVE: "CVE-2", Region: "eu-central-1", Repository: "api", ImageDigest: "sha256:aaa", Package: "openssl", InstalledVersion: "1.0", FixedVersion: "1.1", FindingARN: "arn:2"},
	}

	got := DeduplicateRows(rows)
	if len(got) != 2 {
		t.Fatalf("expected 2 rows after dedupe, got %d: %#v", len(got), got)
	}
	merged := got[0]
	if merged.Tier != "Tier 1" || merged.Severity != "CRITICAL" || merged.CVSS != 9.8 || !merged.RunningOrDeployed {
		t.Fatalf("expected duplicate merge to preserve highest priority fields, got %#v", merged)
	}
	if len(merged.RuntimeLocations) != 2 {
		t.Fatalf("expected runtime locations to merge, got %#v", merged.RuntimeLocations)
	}
}

func TestDeduplicateRowsCollapsesDuplicateRuntimeLocations(t *testing.T) {
	hit := RuntimeHit{Platform: "EKS", Region: "eu-central-1", Cluster: "prod", Namespace: "payments", Workload: "Deployment/api", Pod: "api-1", Container: "api"}
	rows := []Row{{CVE: "CVE-1", Repository: "api", ImageDigest: "sha256:aaa", Package: "openssl", InstalledVersion: "1.0", FixedVersion: "1.1", RuntimeLocations: []RuntimeHit{hit, hit}}}

	got := DeduplicateRows(rows)
	if len(got) != 1 || len(got[0].RuntimeLocations) != 1 {
		t.Fatalf("expected duplicate runtime locations to collapse, got %#v", got)
	}
}
