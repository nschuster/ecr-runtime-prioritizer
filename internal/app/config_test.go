package app

import (
	"path/filepath"
	"testing"
)

func TestDefaultKubeconfigPathIsAppSpecific(t *testing.T) {
	configHome := filepath.Join(t.TempDir(), "xdg")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	got := DefaultKubeconfigPath()
	want := filepath.Join(configHome, "ecr-prioritizer", "kubeconfig")
	if got != want {
		t.Fatalf("expected app-specific kubeconfig path %q, got %q", want, got)
	}
	if filepath.Base(got) != "kubeconfig" {
		t.Fatalf("expected kubeconfig filename, got %q", got)
	}
	if filepath.Base(filepath.Dir(got)) != "ecr-prioritizer" {
		t.Fatalf("expected app-specific config dir, got %q", got)
	}
	if got == filepath.Join("~", ".kube", "config") || filepath.Base(filepath.Dir(got)) == ".kube" {
		t.Fatalf("default kubeconfig path must not target default kube config: %q", got)
	}
}
