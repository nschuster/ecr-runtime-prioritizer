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
			id := hit.Platform + hit.Region + hit.Cluster + hit.Namespace + hit.Workload + hit.Pod + hit.Container
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			hits = append(hits, hit)
		}
	}
	return hits
}

func CollectEKS(ctx context.Context, regions, contexts []string, updateKubeconfig bool) ([]ImageRef, error) {
	var refs []ImageRef
	if len(contexts) == 0 {
		log.Warn("no kube contexts supplied; EKS discovery requires AWS SDK path in scanner, skipping direct context collection")
		return refs, nil
	}
	for _, kc := range contexts {
		region := inferRegion(kc)
		cluster := kc
		if strings.Contains(kc, "/") {
			cluster = kc[strings.LastIndex(kc, "/")+1:]
		}
		log.Info("collecting EKS pod images", "context", kc)
		got, err := collectKubectl(ctx, kc, region, cluster)
		if err != nil {
			log.Warn("kubectl collection failed", "context", kc, "err", err)
			continue
		}
		refs = append(refs, got...)
	}
	return refs, nil
}

func collectKubectl(ctx context.Context, kubeContext, region, cluster string) ([]ImageRef, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "get", "pods", "--all-namespaces", "-o", "json")
	b, err := cmd.CombinedOutput()
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
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: region, Cluster: cluster, Namespace: p.Metadata.Namespace, Workload: workload(p), Pod: p.Metadata.Name, Container: st.Name, Image: first(st.Image, images[st.Name]), ImageID: st.ImageID, Status: "running"}})
			delete(images, st.Name)
		}
		for name, img := range images {
			refs = append(refs, ImageRef{Hit: model.RuntimeHit{Platform: "EKS", Region: region, Cluster: cluster, Namespace: p.Metadata.Namespace, Workload: workload(p), Pod: p.Metadata.Name, Container: name, Image: img, Status: "configured"}})
		}
	}
	return refs, nil
}

type pod struct {
	Metadata struct {
		Name, Namespace string
		Labels          map[string]string             `json:"labels"`
		OwnerReferences []struct{ Kind, Name string } `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Containers, InitContainers []struct{ Name, Image string } `json:"containers"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses, InitContainerStatuses []struct{ Name, Image, ImageID string } `json:"containerStatuses"`
	} `json:"status"`
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
func inferRegion(s string) string {
	re := regexp.MustCompile(`[a-z]{2}-[a-z]+-\d`)
	if m := re.FindString(s); m != "" {
		return m
	}
	return "unknown"
}
func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
