package awsdata

import "testing"

func TestUpdateKubeconfigArgsIncludeDedicatedKubeconfig(t *testing.T) {
	args := updateKubeconfigArgs("eu-central-1", "prod-eks", "eu-central-1/prod-eks", "/tmp/ecr-prioritizer-kubeconfig", "prod")
	joined := ""
	for _, arg := range args {
		joined += arg + " "
	}
	for _, want := range []string{"eks", "update-kubeconfig", "--region", "eu-central-1", "--name", "prod-eks", "--alias", "eu-central-1/prod-eks", "--kubeconfig", "/tmp/ecr-prioritizer-kubeconfig", "--profile", "prod"} {
		if !containsArg(args, want) {
			t.Fatalf("args missing %q in %q", want, joined)
		}
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
