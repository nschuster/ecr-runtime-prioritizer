# ECR Runtime Prioritizer

A Charm Bubble Tea TUI and automation-friendly Go CLI that turns Amazon Inspector ECR findings into a remediation queue ranked by exploitability, fixability, severity, and whether the vulnerable image is actually deployed.

![VHS demo](assets/ecr-prioritizer-demo.gif)

## What it does

`ecr-prioritizer` answers the practical remediation question:

> Which high/critical ECR vulnerabilities should we fix first, and are the affected images running in EKS/ECS?

It combines:

- **Amazon Inspector2 ECR findings** for CVE/package/fix metadata.
- **EKS runtime inventory** from `kubectl get pods`, `kubectl get jobs`, and `kubectl get cronjobs` across all namespaces, so GitLab runner Jobs/CronJobs are included even when they are short-lived.
- **ECS running/pending task inventory** from the ECS API.
- **Charm TUI/output** using Bubble Tea, Bubbles table/viewport/text input components, Lip Gloss, Fang, Glamour/Glow-style Markdown rendering, and Charm log messages.

## Interactive TUI

By default, table output launches an interactive Bubble Tea TUI after the scanner logs every finding discovered. The startup logs make the scan auditable; the TUI then gives you a navigable remediation queue.

```bash
./bin/ecr-prioritizer --demo
```

TUI controls:

| Key | Action |
|---|---|
| `↑`/`↓` or `k`/`j` | Move through findings |
| `Enter`/`→` | Open the selected finding detail page |
| `Esc`/`←` | Return from details/modal |
| `r` | Open the report-generation modal |
| `Space` | Toggle report file types in the report modal |
| `q` | Quit from the main table/details views |

The report modal floats in the foreground in the middle of the TUI, lets you set a filename prefix, and select `csv`/`json`/`md`. Pressing the generate button writes the files and closes the modal automatically. The overview table preserves the original severity/tier/runtime color cues, and the active selection highlight spans the full row across every column. Use `--tui=false` for the old plain terminal table, or choose `--format json|csv|md` for scriptable output.

## Prioritization model

| Tier | Rule |
|---|---|
| **Tier 1** | `exploitAvailable = YES` and `fixAvailable = YES` |
| **Tier 2** | `fixAvailable = YES`, no known exploit available |

The scanner filters to `ACTIVE` ECR image findings with `fixAvailable = YES` and `CRITICAL`/`HIGH` severity by default.

Inspector can return multiple package entries for one finding, and different pages/regions can also contain records that collapse to the same practical remediation item. The tool therefore deduplicates by account, region, repository, image digest — or image tags when a digest is unavailable — CVE, package manager, package, installed version, and fixed version, while merging runtime locations and preserving the highest-priority tier/severity/CVSS fields.

Sorting order:

1. Tier 1 before Tier 2
2. Runtime matched images before images only present in ECR
3. Critical before High
4. Highest CVSS first
5. Repository/CVE for stable output

## Install

```bash
git clone https://github.com/nschuster/ecr-runtime-prioritizer.git
cd ecr-runtime-prioritizer
go build -o ./bin/ecr-prioritizer ./cmd/ecr-prioritizer
```

> The module currently uses Go 1.24.2 metadata because the newer Charm Bubble Tea/Bubbles/Fang stack pulls recent terminal packages. Go toolchain auto-download handles this in tested environments.

## Quick demo without AWS

```bash
./bin/ecr-prioritizer --demo
```

Write all report formats:

```bash
./bin/ecr-prioritizer --demo --out-prefix demo-report
```

Creates:

```text
demo-report.csv
demo-report.json
demo-report.md
```

## Real AWS usage

### Inspector findings only

If your AWS credentials are already available locally, you do **not** need to pass an AWS profile. The tool uses the normal AWS SDK credential chain: environment variables, `AWS_PROFILE`, SSO/session credentials, shared config files, EC2/ECS roles, etc.

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1,eu-west-1
```

Use `--profile` only when you want to force a named shared config profile:

```bash
./bin/ecr-prioritizer \
  --profile prod \
  --regions eu-central-1,eu-west-1
```

### Inspector + EKS runtime check

```bash
./bin/ecr-prioritizer \
  --profile prod \
  --regions eu-central-1,eu-west-1 \
  --eks \
  --out-prefix prod-ecr-vulns
```

By default, EKS mode discovers clusters with the EKS API and runs:

```bash
aws eks update-kubeconfig --region <region> --name <cluster> --alias <region>/<cluster>
kubectl --context <region>/<cluster> get pods --all-namespaces -o json
kubectl --context <region>/<cluster> get jobs --all-namespaces -o json
kubectl --context <region>/<cluster> get cronjobs --all-namespaces -o json
```

Pods catch currently running containers. Jobs and CronJobs catch CI/build workloads such as GitLab runners even if the runner pod has already completed or is only represented by a Job template.

When `--profile` is omitted, both the AWS SDK calls and `aws eks update-kubeconfig` use your local default credential chain. When `--profile prod` is supplied, the generated `aws eks update-kubeconfig` call also receives `--profile prod`.

### Use existing kube contexts

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1 \
  --eks \
  --kube-contexts prod-eks,staging-eks
```

### Private Kubernetes API endpoints through per-cluster SSM jump hosts

If each EKS cluster/VPC has its own SSM-managed jump host, the scanner can now open the tunnel itself per cluster. On discovered EKS clusters it:

1. calls `eks:DescribeCluster` to get the real private API endpoint hostname,
2. updates kubeconfig as usual so IAM auth/CA data exists,
3. starts `aws ssm start-session --document-name AWS-StartPortForwardingSessionToRemoteHost` against the configured jump host,
4. runs `kubectl` through `https://127.0.0.1:<local_port>` with `--tls-server-name <real-eks-endpoint-host>`,
5. kills the tunnel after that cluster was inventoried.

Run interactively and let the tool ask for missing jump host IDs:

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1,eu-west-1 \
  --eks \
  --save-kube-tunnel-config
```

The default config path is shown in `--help` and is usually:

```text
~/.config/ecr-prioritizer/config.json
```

Example config:

```json
{
  "clusters": {
    "eu-central-1/prod-eks": {
      "jump_host_id": "i-0123456789abcdef0",
      "local_port": 18443
    },
    "eu-west-1/staging-eks": {
      "jump_host_id": "i-0fedcba9876543210",
      "local_port": 18444
    }
  }
}
```

You can also point to a team-maintained config file:

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1,eu-west-1 \
  --eks \
  --kube-tunnel-config ./ecr-prioritizer.config.json \
  --prompt-jump-hosts=false
```

The older global `--kube-tunnel-command` option still exists for non-SSM or custom network setups. It starts one command before all EKS collection and kills it when the scan exits:

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1 \
  --eks \
  --kube-contexts prod-eks \
  --no-update-kubeconfig \
  --kube-tunnel-command 'ssh -N -L 127.0.0.1:8443:PRIVATE_EKS_ENDPOINT:443 bastion.example.com' \
  --kube-tunnel-wait 5
```

For AWS-native environments, the built-in per-cluster SSM tunnel mode is usually better than a global command. If you use a custom tunnel, the important point is that `kubectl --context <ctx> get pods/jobs/cronjobs --all-namespaces -o json` must work while the tunnel is up.

### Inspector + EKS + ECS

```bash
./bin/ecr-prioritizer \
  --profile prod \
  --regions eu-central-1,eu-west-1 \
  --eks \
  --ecs \
  --out-prefix prod-ecr-vulns
```

## Output formats

Plain terminal table without the interactive TUI:

```bash
./bin/ecr-prioritizer --demo --format table --tui=false
```

Markdown rendered in the terminal with a Glow/Glamour-style renderer:

```bash
./bin/ecr-prioritizer --demo --format md
```

CSV:

```bash
./bin/ecr-prioritizer --demo --format csv
```

JSON:

```bash
./bin/ecr-prioritizer --demo --format json
```

## Required permissions

Inspector:

```text
inspector2:ListFindings
```

EKS discovery/runtime enrichment:

```text
eks:ListClusters
eks:DescribeCluster
```

Kubernetes RBAC:

```text
pods/list across namespaces
jobs/list across namespaces
cronjobs/list across namespaces
```

Private EKS tunnel mode also needs:

```text
eks:DescribeCluster
ssm:StartSession on the per-cluster jump host instances
```

ECS enrichment:

```text
ecs:ListClusters
ecs:ListTasks
ecs:DescribeTasks
```

## Notes and limitations

- Inspector findings are regional. Pass every region where ECR scanning/Inspector is enabled.
- Runtime matching is best-effort and checks full image URI, repository/tag, repository/digest, and digest keys.
- EKS runtime enrichment depends on local `aws` and `kubectl` CLIs. In EKS mode it checks Pods plus Jobs/CronJobs, so GitLab runner job images are treated as in-use/configured even when no runner pod is currently running.
- ECS runtime enrichment currently considers running and pending tasks.
- For large estates, write CSV/JSON/Markdown with `--out-prefix` and feed the CSV into ticketing or BI tooling.

## Development

```bash
go mod tidy
gofmt -w .
go build ./...
go run ./cmd/ecr-prioritizer --demo --tui=false --out-prefix demo-report
```

## Regenerate the VHS demo

Install VHS if needed:

```bash
go install github.com/charmbracelet/vhs@latest
```

Render:

```bash
go build -o ./bin/ecr-prioritizer ./cmd/ecr-prioritizer
VHS_NO_SANDBOX=1 vhs demo.tape
```

The generated GIF is written to:

```text
assets/ecr-prioritizer-demo.gif
```
