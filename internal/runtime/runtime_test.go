package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectKubectlIncludesPodsJobsAndCronJobs(t *testing.T) {
	tmp := t.TempDir()
	script := `#!/bin/sh
case "$*" in
  *"get pods"*) cat <<'JSON'
{"items":[{"metadata":{"name":"runner-pod","namespace":"ci","ownerReferences":[{"kind":"Job","name":"runner-job"}]},"spec":{"containers":[{"name":"build","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/runner:pod"}],"initContainers":[{"name":"init","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/init:pod"}]},"status":{"containerStatuses":[{"name":"build","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/runner:pod","imageID":"docker-pullable://123456789012.dkr.ecr.eu-central-1.amazonaws.com/runner@sha256:pod"}],"initContainerStatuses":[{"name":"init","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/init:pod","imageID":"docker-pullable://123456789012.dkr.ecr.eu-central-1.amazonaws.com/init@sha256:init"}]}}]}
JSON
    ;;
  *"get jobs"*) cat <<'JSON'
{"items":[{"metadata":{"name":"gitlab-runner-job","namespace":"ci"},"spec":{"template":{"spec":{"containers":[{"name":"helper","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/gitlab-helper:job"}],"initContainers":[]}}},"status":{"active":1}}]}
JSON
    ;;
  *"get cronjobs"*) cat <<'JSON'
{"items":[{"metadata":{"name":"nightly-runner","namespace":"ci"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"nightly","image":"123456789012.dkr.ecr.eu-central-1.amazonaws.com/gitlab-helper:cron"}],"initContainers":[]}}}}}}]}
JSON
    ;;
  *) exit 1 ;;
esac
`
	kubectl := filepath.Join(tmp, "kubectl")
	if err := os.WriteFile(kubectl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+oldPath)

	refs, err := collectKubectl(context.Background(), KubeAccess{Context: "eu-central-1/prod", Region: "eu-central-1", Cluster: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"Job/runner-job|running":                  false,
		"Job/gitlab-runner-job|job-active":        false,
		"CronJob/nightly-runner|cronjob-template": false,
	}
	for _, ref := range refs {
		key := ref.Hit.Workload + "|" + ref.Hit.Status
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Fatalf("missing runtime image source %s in %#v", key, refs)
		}
	}
}
