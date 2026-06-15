# ECR Runtime Prioritizer

A Charm Bubble Tea TUI and automation-friendly Go CLI that turns Amazon Inspector ECR findings into a remediation queue ranked by exploitability, fixability, severity, and whether the vulnerable image is actually deployed.

![VHS demo](assets/ecr-prioritizer-demo.gif)

## What it does

`ecr-prioritizer` answers the practical remediation question:

> Which high/critical ECR vulnerabilities should we fix first, and are the affected images running in EKS/ECS?

It combines:

- **Amazon Inspector2 ECR findings** for CVE/package/fix metadata.
- **EKS pod inventory** from `kubectl get pods --all-namespaces -o json`.
- **ECS running/pending task inventory** from the ECS API.
- **Charm TUI/output** using Bubble Tea, Bubbles table/viewport/text input/file picker components, Lip Gloss, Fang, Glamour/Glow-style Markdown rendering, and Charm log messages.

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
| `p` | Open the directory file picker from the report modal |
| `Space` | Toggle report file types in the report modal |
| `q` | Quit from the main table/details views |

The report modal lets you set a filename prefix, select `csv`/`json`/`md`, and choose an output directory with the Bubbles file picker. Use `--tui=false` for the old plain terminal table, or choose `--format json|csv|md` for scriptable output.

## Prioritization model

| Tier | Rule |
|---|---|
| **Tier 1** | `exploitAvailable = YES` and `fixAvailable = YES` |
| **Tier 2** | `fixAvailable = YES`, no known exploit available |

The scanner filters to `ACTIVE` ECR image findings with `fixAvailable = YES` and `CRITICAL`/`HIGH` severity by default.

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
```

When `--profile` is omitted, both the AWS SDK calls and `aws eks update-kubeconfig` use your local default credential chain. When `--profile prod` is supplied, the generated `aws eks update-kubeconfig` call also receives `--profile prod`.

### Use existing kube contexts

```bash
./bin/ecr-prioritizer \
  --regions eu-central-1 \
  --eks \
  --kube-contexts prod-eks,staging-eks
```

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
- EKS runtime enrichment depends on local `aws` and `kubectl` CLIs.
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
