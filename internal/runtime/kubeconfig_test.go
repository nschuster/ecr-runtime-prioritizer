package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectKubectlPassesDedicatedKubeconfig(t *testing.T) {
	tmp := t.TempDir()
	argsFile := filepath.Join(tmp, "args.txt")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "` + argsFile + `"
case "$*" in
  *"get pods"*) echo '{"items":[]}' ;;
  *"get jobs"*) echo '{"items":[]}' ;;
  *"get cronjobs"*) echo '{"items":[]}' ;;
  *) exit 1 ;;
esac
`
	kubectl := filepath.Join(tmp, "kubectl")
	if err := os.WriteFile(kubectl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	kubeconfig := filepath.Join(tmp, "app-kubeconfig")
	_, err := collectKubectl(context.Background(), KubeAccess{Context: "eu-central-1/prod", Region: "eu-central-1", Cluster: "prod", Kubeconfig: kubeconfig})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.Contains(line, "--kubeconfig "+kubeconfig) {
			t.Fatalf("kubectl args did not include dedicated kubeconfig %q in line %q", kubeconfig, line)
		}
	}
}

func TestParseKubeContextRegionCluster(t *testing.T) {
	region, cluster := ParseKubeContext("eu-central-1/prod-eks")
	if region != "eu-central-1" || cluster != "prod-eks" {
		t.Fatalf("unexpected parsed context: region=%q cluster=%q", region, cluster)
	}
	region, cluster = ParseKubeContext("us-gov-west-1/prod-eks")
	if region != "us-gov-west-1" || cluster != "prod-eks" {
		t.Fatalf("unexpected parsed GovCloud context: region=%q cluster=%q", region, cluster)
	}
	region, cluster = ParseKubeContext("prod-eks")
	if region != "unknown" || cluster != "prod-eks" {
		t.Fatalf("unexpected parsed bare context: region=%q cluster=%q", region, cluster)
	}
}
