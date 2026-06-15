package runtime

import (
	"context"
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/nschuster/ecr-runtime-prioritizer/internal/model"
)

type ImageRef struct {
	Hit model.RuntimeHit
}

type Index map[string][]model.RuntimeHit

type KubeAccess struct {
	Context       string
	Kubeconfig    string
	Region        string
	Cluster       string
	Server        string
	TLSServerName string
}

func BuildIndex(refs []ImageRef) Index {
	idx := Index{}
	for _, ref := range refs {
		for _, k := range ImageKeys(ref.Hit.Image, ref.Hit.ImageID) {
			idx[k] = append(idx[k], ref.Hit)
		}
	}
	return idx
}

func ImageKeys(image, imageID string) []string {
	set := map[string]struct{}{}
	for _, raw := range []string{image, imageID} {
		if raw == "" {
			continue
		}
		ref := strings.TrimPrefix(strings.TrimPrefix(raw, "docker-pullable://"), "containerd://")
		set[ref] = struct{}{}
		if strings.Contains(ref, "@sha256:") {
			parts := strings.SplitN(ref, "@sha256:", 2)
			set["sha256:"+parts[1]] = struct{}{}
			set[parts[0]] = struct{}{}
		}
		if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
			set[ref[:i]] = struct{}{}
		}
		if p := strings.SplitN(ref, "/", 2); len(p) == 2 && (strings.Contains(p[0], ".") || strings.Contains(p[0], ":")) {
			set[p[1]] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func Match(idx Index, keys []string) []model.RuntimeHit {
	seen := map[string]struct{}{}
	var hits []model.RuntimeHit
	for _, key := range keys {
		for _, hit := range idx[key] {
			id := hit.Platform + hit.Region + hit.Cluster + hit.Namespace + hit.Workload + hit.Pod + hit.Container + hit.Image + hit.Status
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			hits = append(hits, hit)
		}
	}
	return hits
}

func CollectEKSWithAccess(ctx context.Context, clusters []KubeAccess) ([]ImageRef, error) {
	var refs []ImageRef
	if len(clusters) == 0 {
		log.Warn("no kube contexts supplied; EKS discovery requires AWS SDK path in scanner, skipping direct context collection")
		return refs, nil
	}
	for _, access := range clusters {
		if access.Context == "" {
			continue
		}
		if access.Region == "" {
			access.Region, _ = ParseKubeContext(access.Context)
		}
		if access.Cluster == "" {
			_, access.Cluster = ParseKubeContext(access.Context)
		}
		log.Info("collecting EKS images", "context", access.Context, "cluster", access.Cluster)
		got, err := collectKubectl(ctx, access)
		if err != nil {
			log.Warn("kubectl collection failed", "context", access.Context, "err", err)
			continue
		}
		refs = append(refs, got...)
	}
	return refs, nil
}

func collectKubectl(ctx context.Context, access KubeAccess) ([]ImageRef, error) {
	refs, err := collectPods(ctx, access)
	if err != nil {
		return nil, err
	}
	jobs, err := collectJobs(ctx, access)
	if err != nil {
		log.Warn("kubectl jobs collection failed", "context", access.Context, "err", err)
	} else {
		refs = append(refs, jobs...)
	}
	cronJobs, err := collectCronJobs(ctx, access)
	if err != nil {
		log.Warn("kubectl cronjobs collection failed", "context", access.Context, "err", err)
	} else {
		refs = append(refs, cronJobs...)
	}
	return refs, nil
}

func kubectlJSON(ctx context.Context, access KubeAccess, args ...string) ([]byte, error) {
	base := []string{}
	if access.Kubeconfig != "" {
		base = append(base, "--kubeconfig", access.Kubeconfig)
	}
	base = append(base, "--context", access.Context)
	if access.Server != "" {
		base = append(base, "--server", access.Server)
	}
	if access.TLSServerName != "" {
		base = append(base, "--tls-server-name", access.TLSServerName)
	}
	base = append(base, args...)
	cmd := exec.CommandContext(ctx, "kubectl", base...)
	return cmd.CombinedOutput()
}

func collectPods(ctx context.Context, access KubeAccess) ([]ImageRef, error) {
	b, err := kubectlJSON(ctx, access, "get", "pods", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var pods struct {
		Items []pod `json:"items"`
	}
	if err := json.Unmarshal(b, &pods); err != nil {
		return nil, err
	}
	var refs []ImageRef
	for _, p := range pods.Items {
		images := map[string]string{}
		for _, c := range p.Spec.Containers {
			images[c.Name] = c.Image
		}
		for _, c := range p.Spec.InitContainers {
			images[c.Name] = c.Image
		}
		for _, st := range append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses...) {
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: access.Region, Cluster: access.Cluster, Namespace: p.Metadata.Namespace, Workload: workload(p), Pod: p.Metadata.Name, Container: st.Name, Image: first(st.Image, images[st.Name]), ImageID: st.ImageID, Status: "running"}})
			delete(images, st.Name)
		}
		for name, img := range images {
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: access.Region, Cluster: access.Cluster, Namespace: p.Metadata.Namespace, Workload: workload(p), Pod: p.Metadata.Name, Container: name, Image: img, Status: "configured"}})
		}
	}
	return refs, nil
}

func collectJobs(ctx context.Context, access KubeAccess) ([]ImageRef, error) {
	b, err := kubectlJSON(ctx, access, "get", "jobs", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []job `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	var refs []ImageRef
	for _, j := range list.Items {
		status := "job"
		if j.Status.Active > 0 {
			status = "job-active"
		} else if j.Status.Succeeded > 0 {
			status = "job-succeeded"
		} else if j.Status.Failed > 0 {
			status = "job-failed"
		}
		for _, c := range append(j.Spec.Template.Spec.InitContainers, j.Spec.Template.Spec.Containers...) {
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: access.Region, Cluster: access.Cluster, Namespace: j.Metadata.Namespace, Workload: "Job/" + j.Metadata.Name, Container: c.Name, Image: c.Image, Status: status}})
		}
	}
	return refs, nil
}

func collectCronJobs(ctx context.Context, access KubeAccess) ([]ImageRef, error) {
	b, err := kubectlJSON(ctx, access, "get", "cronjobs", "--all-namespaces", "-o", "json")
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []cronJob `json:"items"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	var refs []ImageRef
	for _, cj := range list.Items {
		for _, c := range append(cj.Spec.JobTemplate.Spec.Template.Spec.InitContainers, cj.Spec.JobTemplate.Spec.Template.Spec.Containers...) {
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: access.Region, Cluster: access.Cluster, Namespace: cj.Metadata.Namespace, Workload: "CronJob/" + cj.Metadata.Name, Container: c.Name, Image: c.Image, Status: "cronjob-template"}})
		}
	}
	return refs, nil
}

type containerSpec struct{ Name, Image string }

type pod struct {
	Metadata struct {
		Name, Namespace string
		Labels          map[string]string             `json:"labels"`
		OwnerReferences []struct{ Kind, Name string } `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Containers     []containerSpec `json:"containers"`
		InitContainers []containerSpec `json:"initContainers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses     []struct{ Name, Image, ImageID string } `json:"containerStatuses"`
		InitContainerStatuses []struct{ Name, Image, ImageID string } `json:"initContainerStatuses"`
	} `json:"status"`
}

type podTemplateSpec struct {
	Spec struct {
		Containers     []containerSpec `json:"containers"`
		InitContainers []containerSpec `json:"initContainers"`
	} `json:"spec"`
}

type job struct {
	Metadata struct{ Name, Namespace string }        `json:"metadata"`
	Spec     struct{ Template podTemplateSpec }      `json:"spec"`
	Status   struct{ Active, Succeeded, Failed int } `json:"status"`
}

type cronJob struct {
	Metadata struct{ Name, Namespace string } `json:"metadata"`
	Spec     struct {
		JobTemplate struct {
			Spec struct{ Template podTemplateSpec } `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

func workload(p pod) string {
	if len(p.Metadata.OwnerReferences) > 0 {
		return p.Metadata.OwnerReferences[0].Kind + "/" + p.Metadata.OwnerReferences[0].Name
	}
	for _, k := range []string{"app.kubernetes.io/name", "app", "k8s-app"} {
		if v := p.Metadata.Labels[k]; v != "" {
			return v
		}
	}
	return "unknown"
}
func ParseKubeContext(s string) (region, cluster string) {
	cluster = s
	if strings.Contains(s, "/") {
		cluster = s[strings.LastIndex(s, "/")+1:]
	}
	region = inferRegion(s)
	return region, cluster
}

func inferRegion(s string) string {
	re := regexp.MustCompile(`(?:^|[^a-z0-9-])([a-z]{2}(?:-[a-z]+)+-\d)(?:$|[^a-z0-9-])`)
	parts := re.FindStringSubmatch(s)
	if len(parts) > 1 {
		return parts[1]
	}
	return "unknown"
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
