# OpenShift Governance Tool

Live cluster auditor and discovery tool for OpenShift and Kubernetes. Two modes:

- **Discovery** -- catalog every resource in the cluster and produce a full inventory report (nodes, deployments, pods, services, routes, storage, RBAC, SCCs)
- **Audit** -- run 50+ governance checks across security, resources, network, storage, compute, and compliance with severity ratings and remediation guidance

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Login to your cluster
oc login https://your-cluster:6443 --token=<token>

# Run full audit
python governance.py

# Generate HTML report
python governance.py --output report.html
```

## Usage

### Discovery Mode

```bash
# Full cluster inventory as HTML
python governance.py --discover

# Discovery for a single namespace
python governance.py --discover -n my-app-namespace

# Discovery as Markdown
python governance.py --discover --output inventory.md

# Discovery as JSON (for pipelines, CMDB import, migration tooling)
python governance.py --discover --json-output cluster_inventory.json

# HTML + JSON together
python governance.py --discover --output inventory.html --json-output inventory.json
```

Discovery reports include: nodes (capacity, versions, taints, conditions), namespaces (labels, status), deployments (replicas, strategy), pods (phase, containers, images, restarts), services (type, ports, selectors), routes (host, TLS, target), PVs/PVCs (status, class, capacity), storage classes, network policies, RBAC bindings, and SCCs.

### Audit Mode

```bash
# Run all audits (default)
python governance.py

# Run specific categories only
python governance.py --audit security,network,compliance

# Audit a single namespace
python governance.py -n my-app-namespace

# Export findings as JSON
python governance.py --json-output findings.json

# Verbose mode (print every finding inline)
python governance.py -v

# Combine options
python governance.py -n production --audit security,storage --output report.html -v
```

## Audit Categories

### Security
- Privileged containers
- Pods running as root (UID 0) or without `runAsNonRoot`
- hostNetwork, hostPID, hostIPC usage
- Default service account with auto-mounted tokens
- cluster-admin role bindings
- Secrets exceeding rotation age threshold
- Missing required namespace labels
- OpenShift SCC permissiveness

### Resources
- Containers without resource requests or limits
- CPU/memory request-to-limit ratio sprawl
- ResourceQuota utilization above threshold
- Idle deployments (scaled to 0)
- Namespaces without LimitRange

### Network
- Namespaces without NetworkPolicy (default-allow)
- OpenShift routes without TLS termination
- LoadBalancer services (external exposure)
- Sensitive ports (DB, cache, etcd) exposed via NodePort/LoadBalancer

### Storage
- Unbound or Lost PVCs
- PVs with ReclaimPolicy: Delete
- PVCs without explicit StorageClass
- Released or Failed PVs

### Compute
- Node conditions: DiskPressure, MemoryPressure, PIDPressure, NotReady
- Cordoned (unschedulable) nodes
- Node CPU/memory request saturation
- Kubelet version skew across nodes

### Compliance
- Missing liveness and readiness probes
- Images using `:latest` or untagged
- imagePullPolicy not set to Always for latest tags
- Containers with excessive restart counts
- Multi-replica deployments without PodDisruptionBudget
- Single-replica deployments (no HA)

## Configuration

All thresholds and policies are in `config.yaml`:

```yaml
# Which audits to run
audits:
  security: true
  resources: true
  network: true
  storage: true
  compute: true
  compliance: true

# Example thresholds
security:
  flag_privileged: true
  secret_max_age_days: 90
  required_namespace_labels: [owner, environment]
  excluded_namespaces: [openshift-*, kube-*]

resources:
  require_requests: true
  require_limits: true
  quota_usage_warn_percent: 80

compute:
  node_cpu_warn_percent: 80
  node_memory_warn_percent: 85

compliance:
  require_liveness_probes: true
  flag_latest_tag: true
  max_restart_count: 5
```

## Output

| Format | Command | Description |
|--------|---------|-------------|
| Terminal | `python governance.py` | Inline summary with counts per category |
| Terminal verbose | `python governance.py -v` | Every finding printed with severity |
| HTML | `--output report.html` | Styled dashboard with inventory, severity cards, and findings tables |
| Markdown | `--output report.md` | Portable markdown report |
| JSON | `--json-output findings.json` | Machine-readable for pipelines and dashboards |

## Project Structure

```
openshift-governance/
├── governance.py          # CLI entry point
├── cluster.py             # Cluster connection and OpenShift detection
├── discovery.py           # Full resource inventory collection
├── report.py              # Audit report generation (HTML, Markdown, JSON)
├── discovery_report.py    # Discovery report generation (HTML, Markdown, JSON)
├── config.yaml            # Configurable thresholds and policies
├── requirements.txt
└── audits/
    ├── base.py            # Base audit class
    ├── security.py
    ├── resources.py
    ├── network.py
    ├── storage.py
    ├── compute.py
    └── compliance.py
```

## Requirements

- Python 3.8+
- `oc` or `kubectl` CLI authenticated to the target cluster
- Cluster read access (view ClusterRole is sufficient for most checks)
