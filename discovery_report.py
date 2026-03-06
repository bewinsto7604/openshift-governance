#!/usr/bin/env python3
"""
Discovery Report Generator

Produces detailed cluster inventory reports (HTML, Markdown, JSON)
without running any audits. Used for cataloging, pre-migration
snapshots, and infrastructure visibility.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from jinja2 import Template


def _safe_labels(obj):
    """Extract labels dict from a k8s object or raw dict."""
    if hasattr(obj, "metadata"):
        return dict(obj.metadata.labels or {})
    if isinstance(obj, dict):
        return dict(obj.get("metadata", {}).get("labels", {}) or {})
    return {}


def _safe_annotations_count(obj):
    if hasattr(obj, "metadata"):
        return len(obj.metadata.annotations or {})
    return 0


def serialize_nodes(nodes) -> List[Dict]:
    items = []
    for n in nodes:
        info = n.status.node_info if n.status else None
        allocatable = n.status.allocatable or {} if n.status else {}
        capacity = n.status.capacity or {} if n.status else {}
        conditions = {}
        for c in (n.status.conditions or []) if n.status else []:
            conditions[c.type] = c.status

        items.append({
            "name": n.metadata.name,
            "labels": _safe_labels(n),
            "taints": [{"key": t.key, "effect": t.effect, "value": t.value} for t in (n.spec.taints or [])],
            "unschedulable": bool(n.spec.unschedulable),
            "os": info.os_image if info else "unknown",
            "arch": info.architecture if info else "unknown",
            "kubelet_version": info.kubelet_version if info else "unknown",
            "container_runtime": info.container_runtime_version if info else "unknown",
            "capacity": dict(capacity),
            "allocatable": dict(allocatable),
            "conditions": conditions,
            "created": n.metadata.creation_timestamp.isoformat() if n.metadata.creation_timestamp else "",
        })
    return items


def serialize_namespaces(ns_objects) -> List[Dict]:
    items = []
    for ns in ns_objects:
        items.append({
            "name": ns.metadata.name,
            "labels": _safe_labels(ns),
            "status": ns.status.phase if ns.status else "unknown",
            "created": ns.metadata.creation_timestamp.isoformat() if ns.metadata.creation_timestamp else "",
        })
    return items


def serialize_pods(pods) -> List[Dict]:
    items = []
    for p in pods:
        containers = []
        for c in (p.spec.containers or []):
            res = c.resources
            containers.append({
                "name": c.name,
                "image": c.image,
                "requests": dict(res.requests) if res and res.requests else {},
                "limits": dict(res.limits) if res and res.limits else {},
                "liveness_probe": c.liveness_probe is not None,
                "readiness_probe": c.readiness_probe is not None,
            })

        restart_count = 0
        for cs in (p.status.container_statuses or []) if p.status else []:
            restart_count += cs.restart_count

        items.append({
            "name": p.metadata.name,
            "namespace": p.metadata.namespace,
            "phase": p.status.phase if p.status else "unknown",
            "node": p.spec.node_name or "",
            "service_account": p.spec.service_account_name or "default",
            "containers": containers,
            "restart_count": restart_count,
            "created": p.metadata.creation_timestamp.isoformat() if p.metadata.creation_timestamp else "",
        })
    return items


def serialize_deployments(deployments) -> List[Dict]:
    items = []
    for d in deployments:
        items.append({
            "name": d.metadata.name,
            "namespace": d.metadata.namespace,
            "replicas_desired": d.spec.replicas,
            "replicas_ready": d.status.ready_replicas if d.status else 0,
            "replicas_available": d.status.available_replicas if d.status else 0,
            "strategy": d.spec.strategy.type if d.spec.strategy else "unknown",
            "labels": _safe_labels(d),
            "created": d.metadata.creation_timestamp.isoformat() if d.metadata.creation_timestamp else "",
        })
    return items


def serialize_services(services) -> List[Dict]:
    items = []
    for s in services:
        ports = []
        for p in (s.spec.ports or []):
            ports.append({
                "name": p.name or "",
                "port": p.port,
                "target_port": str(p.target_port) if p.target_port else "",
                "protocol": p.protocol or "TCP",
            })
        items.append({
            "name": s.metadata.name,
            "namespace": s.metadata.namespace,
            "type": s.spec.type,
            "cluster_ip": s.spec.cluster_ip or "",
            "ports": ports,
            "selector": dict(s.spec.selector or {}),
        })
    return items


def serialize_routes(routes) -> List[Dict]:
    items = []
    for r in routes:
        spec = r.get("spec", {})
        tls = spec.get("tls")
        items.append({
            "name": r.get("metadata", {}).get("name", ""),
            "namespace": r.get("metadata", {}).get("namespace", ""),
            "host": spec.get("host", ""),
            "path": spec.get("path", "/"),
            "tls_termination": tls.get("termination", "") if tls else "none",
            "target_service": spec.get("to", {}).get("name", ""),
            "target_port": str(spec.get("port", {}).get("targetPort", "")),
        })
    return items


def serialize_pvcs(pvcs) -> List[Dict]:
    items = []
    for p in pvcs:
        items.append({
            "name": p.metadata.name,
            "namespace": p.metadata.namespace,
            "status": p.status.phase if p.status else "unknown",
            "storage_class": p.spec.storage_class_name or "",
            "capacity": dict(p.status.capacity) if p.status and p.status.capacity else {},
            "access_modes": list(p.spec.access_modes or []),
            "volume": p.spec.volume_name or "",
        })
    return items


def serialize_pvs(pvs) -> List[Dict]:
    items = []
    for p in pvs:
        claim = p.spec.claim_ref
        items.append({
            "name": p.metadata.name,
            "status": p.status.phase if p.status else "unknown",
            "capacity": dict(p.spec.capacity or {}),
            "access_modes": list(p.spec.access_modes or []),
            "reclaim_policy": p.spec.persistent_volume_reclaim_policy or "",
            "storage_class": p.spec.storage_class_name or "",
            "bound_to": f"{claim.namespace}/{claim.name}" if claim else "unbound",
        })
    return items


def serialize_storage_classes(scs) -> List[Dict]:
    items = []
    for sc in scs:
        items.append({
            "name": sc.metadata.name,
            "provisioner": sc.provisioner,
            "reclaim_policy": sc.reclaim_policy or "",
            "volume_binding_mode": sc.volume_binding_mode or "",
            "allow_expansion": bool(sc.allow_volume_expansion),
        })
    return items


def serialize_network_policies(nps) -> List[Dict]:
    items = []
    for np in nps:
        items.append({
            "name": np.metadata.name,
            "namespace": np.metadata.namespace,
            "pod_selector": dict(np.spec.pod_selector.match_labels or {}) if np.spec.pod_selector else {},
            "ingress_rules": len(np.spec.ingress or []) if np.spec.ingress else 0,
            "egress_rules": len(np.spec.egress or []) if np.spec.egress else 0,
            "policy_types": list(np.spec.policy_types or []),
        })
    return items


def serialize_rbac(cluster_roles, cluster_role_bindings) -> Dict:
    roles = []
    for cr in cluster_roles:
        rules_count = len(cr.rules or [])
        roles.append({
            "name": cr.metadata.name,
            "rules_count": rules_count,
        })

    bindings = []
    for crb in cluster_role_bindings:
        subjects = []
        for s in (crb.subjects or []):
            subjects.append({
                "kind": s.kind,
                "name": s.name,
                "namespace": s.namespace or "",
            })
        bindings.append({
            "name": crb.metadata.name,
            "role": crb.role_ref.name if crb.role_ref else "",
            "subjects": subjects,
        })

    return {"cluster_roles_count": len(roles), "bindings": bindings}


def serialize_sccs(sccs) -> List[Dict]:
    items = []
    for scc in sccs:
        items.append({
            "name": scc.get("metadata", {}).get("name", ""),
            "allow_privileged": scc.get("allowPrivilegedContainer", False),
            "run_as_user": scc.get("runAsUser", {}).get("type", ""),
            "se_linux_context": scc.get("seLinuxContext", {}).get("type", ""),
            "volumes": scc.get("volumes", []),
        })
    return items


def build_discovery_data(cluster_info, inventory) -> Dict:
    """Build a fully serialized discovery dataset from raw inventory."""
    return {
        "cluster": cluster_info,
        "collected_at": inventory.get("collected_at", ""),
        "counts": inventory["counts"],
        "nodes": serialize_nodes(inventory["nodes"]),
        "namespaces": serialize_namespaces(inventory["namespace_objects"]),
        "pods": serialize_pods(inventory["pods"]),
        "deployments": serialize_deployments(inventory["deployments"]),
        "services": serialize_services(inventory["services"]),
        "routes": serialize_routes(inventory.get("routes", [])),
        "pvcs": serialize_pvcs(inventory["pvcs"]),
        "pvs": serialize_pvs(inventory["pvs"]),
        "storage_classes": serialize_storage_classes(inventory["storage_classes"]),
        "network_policies": serialize_network_policies(inventory["network_policies"]),
        "rbac": serialize_rbac(inventory["cluster_roles"], inventory["cluster_role_bindings"]),
        "sccs": serialize_sccs(inventory.get("sccs", [])),
    }


# ---------------------------------------------------------------------------
# HTML discovery report
# ---------------------------------------------------------------------------

DISCOVERY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OpenShift Cluster Discovery</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #3b82f6; padding-bottom: 10px; }
  h2 { color: #16213e; margin-top: 30px; cursor: pointer; }
  h2:hover { color: #3b82f6; }
  .meta { color: #666; font-size: 14px; margin-bottom: 30px; }
  .inventory { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin: 20px 0; }
  .inv-item { background: white; border-radius: 8px; padding: 18px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .inv-item .count { font-size: 32px; font-weight: bold; color: #1a1a2e; }
  .inv-item .type { font-size: 11px; text-transform: uppercase; color: #666; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  th { background: #1a1a2e; color: white; padding: 10px 12px; text-align: left; font-size: 12px; }
  td { padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 12px; }
  tr:hover { background: #f0f7ff; }
  .tag { display: inline-block; background: #e8f0fe; color: #1a73e8; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin: 1px; }
  .tag-warn { background: #fef3cd; color: #856404; }
  .tag-ok { background: #d4edda; color: #155724; }
  .tag-bad { background: #f8d7da; color: #721c24; }
  .section { margin: 25px 0; }
  .ns-group { margin: 10px 0; padding: 10px; background: white; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
  .ns-name { font-weight: bold; font-size: 14px; color: #1a1a2e; }
</style>
</head>
<body>
<h1>OpenShift Cluster Discovery Report</h1>
<div class="meta">
  <strong>Cluster:</strong> {{ data.cluster.server }} |
  <strong>Version:</strong> {{ data.cluster.version }} |
  <strong>Collected:</strong> {{ data.collected_at[:19] }} UTC
</div>

<h2>Resource Inventory</h2>
<div class="inventory">
{% for type, count in data.counts.items() %}
  <div class="inv-item"><div class="count">{{ count }}</div><div class="type">{{ type }}</div></div>
{% endfor %}
</div>

<!-- NODES -->
<div class="section">
<h2>Nodes ({{ data.nodes | length }})</h2>
<table>
<tr><th>Name</th><th>Version</th><th>OS</th><th>Arch</th><th>Runtime</th><th>CPU (alloc)</th><th>Memory (alloc)</th><th>Conditions</th><th>Taints</th></tr>
{% for n in data.nodes %}
<tr>
  <td>{{ n.name }}</td>
  <td>{{ n.kubelet_version }}</td>
  <td>{{ n.os }}</td>
  <td>{{ n.arch }}</td>
  <td>{{ n.container_runtime }}</td>
  <td>{{ n.allocatable.get('cpu', '') }}</td>
  <td>{{ n.allocatable.get('memory', '') }}</td>
  <td>{% for k,v in n.conditions.items() %}<span class="tag {{ 'tag-ok' if (k=='Ready' and v=='True') or (k!='Ready' and v!='True') else 'tag-bad' }}">{{ k }}={{ v }}</span>{% endfor %}</td>
  <td>{% for t in n.taints %}<span class="tag tag-warn">{{ t.key }}:{{ t.effect }}</span>{% endfor %}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- NAMESPACES -->
<div class="section">
<h2>Namespaces ({{ data.namespaces | length }})</h2>
<table>
<tr><th>Name</th><th>Status</th><th>Labels</th><th>Created</th></tr>
{% for ns in data.namespaces %}
<tr>
  <td>{{ ns.name }}</td>
  <td><span class="tag tag-ok">{{ ns.status }}</span></td>
  <td>{% for k,v in ns.labels.items() %}<span class="tag">{{ k }}={{ v }}</span>{% endfor %}</td>
  <td>{{ ns.created[:10] }}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- DEPLOYMENTS -->
<div class="section">
<h2>Deployments ({{ data.deployments | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Replicas</th><th>Ready</th><th>Strategy</th><th>Created</th></tr>
{% for d in data.deployments %}
<tr>
  <td>{{ d.namespace }}</td>
  <td>{{ d.name }}</td>
  <td>{{ d.replicas_desired }}</td>
  <td><span class="tag {{ 'tag-ok' if d.replicas_ready == d.replicas_desired else 'tag-bad' }}">{{ d.replicas_ready or 0 }}</span></td>
  <td>{{ d.strategy }}</td>
  <td>{{ d.created[:10] }}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- PODS -->
<div class="section">
<h2>Pods ({{ data.pods | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Phase</th><th>Node</th><th>Containers</th><th>Restarts</th><th>SA</th></tr>
{% for p in data.pods %}
<tr>
  <td>{{ p.namespace }}</td>
  <td>{{ p.name }}</td>
  <td><span class="tag {{ 'tag-ok' if p.phase=='Running' else 'tag-warn' if p.phase=='Pending' else 'tag-bad' if p.phase=='Failed' else '' }}">{{ p.phase }}</span></td>
  <td>{{ p.node }}</td>
  <td>{% for c in p.containers %}<span class="tag">{{ c.name }}: {{ c.image.split('/')[-1][:40] }}</span>{% endfor %}</td>
  <td>{{ p.restart_count }}</td>
  <td>{{ p.service_account }}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- SERVICES -->
<div class="section">
<h2>Services ({{ data.services | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Type</th><th>ClusterIP</th><th>Ports</th><th>Selector</th></tr>
{% for s in data.services %}
<tr>
  <td>{{ s.namespace }}</td>
  <td>{{ s.name }}</td>
  <td><span class="tag {{ 'tag-warn' if s.type=='LoadBalancer' else '' }}">{{ s.type }}</span></td>
  <td>{{ s.cluster_ip }}</td>
  <td>{% for p in s.ports %}<span class="tag">{{ p.port }}:{{ p.target_port }}/{{ p.protocol }}</span>{% endfor %}</td>
  <td>{% for k,v in s.selector.items() %}<span class="tag">{{ k }}={{ v }}</span>{% endfor %}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- ROUTES -->
{% if data.routes %}
<div class="section">
<h2>Routes ({{ data.routes | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Host</th><th>Path</th><th>TLS</th><th>Target Service</th><th>Port</th></tr>
{% for r in data.routes %}
<tr>
  <td>{{ r.namespace }}</td>
  <td>{{ r.name }}</td>
  <td>{{ r.host }}</td>
  <td>{{ r.path }}</td>
  <td><span class="tag {{ 'tag-ok' if r.tls_termination != 'none' else 'tag-bad' }}">{{ r.tls_termination }}</span></td>
  <td>{{ r.target_service }}</td>
  <td>{{ r.target_port }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endif %}

<!-- STORAGE -->
<div class="section">
<h2>Storage Classes ({{ data.storage_classes | length }})</h2>
<table>
<tr><th>Name</th><th>Provisioner</th><th>Reclaim Policy</th><th>Binding Mode</th><th>Expansion</th></tr>
{% for sc in data.storage_classes %}
<tr>
  <td>{{ sc.name }}</td>
  <td>{{ sc.provisioner }}</td>
  <td>{{ sc.reclaim_policy }}</td>
  <td>{{ sc.volume_binding_mode }}</td>
  <td><span class="tag {{ 'tag-ok' if sc.allow_expansion else 'tag-warn' }}">{{ 'yes' if sc.allow_expansion else 'no' }}</span></td>
</tr>
{% endfor %}
</table>

<h2>Persistent Volumes ({{ data.pvs | length }})</h2>
<table>
<tr><th>Name</th><th>Status</th><th>Capacity</th><th>Access Modes</th><th>Reclaim</th><th>Class</th><th>Bound To</th></tr>
{% for p in data.pvs %}
<tr>
  <td>{{ p.name }}</td>
  <td><span class="tag {{ 'tag-ok' if p.status=='Bound' else 'tag-warn' }}">{{ p.status }}</span></td>
  <td>{{ p.capacity.get('storage', '') }}</td>
  <td>{{ p.access_modes | join(', ') }}</td>
  <td>{{ p.reclaim_policy }}</td>
  <td>{{ p.storage_class }}</td>
  <td>{{ p.bound_to }}</td>
</tr>
{% endfor %}
</table>

<h2>Persistent Volume Claims ({{ data.pvcs | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Status</th><th>Class</th><th>Capacity</th><th>Access Modes</th><th>Volume</th></tr>
{% for p in data.pvcs %}
<tr>
  <td>{{ p.namespace }}</td>
  <td>{{ p.name }}</td>
  <td><span class="tag {{ 'tag-ok' if p.status=='Bound' else 'tag-bad' }}">{{ p.status }}</span></td>
  <td>{{ p.storage_class }}</td>
  <td>{{ p.capacity.get('storage', '') }}</td>
  <td>{{ p.access_modes | join(', ') }}</td>
  <td>{{ p.volume }}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- NETWORK POLICIES -->
<div class="section">
<h2>Network Policies ({{ data.network_policies | length }})</h2>
<table>
<tr><th>Namespace</th><th>Name</th><th>Pod Selector</th><th>Ingress Rules</th><th>Egress Rules</th><th>Types</th></tr>
{% for np in data.network_policies %}
<tr>
  <td>{{ np.namespace }}</td>
  <td>{{ np.name }}</td>
  <td>{% for k,v in np.pod_selector.items() %}<span class="tag">{{ k }}={{ v }}</span>{% endfor %}</td>
  <td>{{ np.ingress_rules }}</td>
  <td>{{ np.egress_rules }}</td>
  <td>{{ np.policy_types | join(', ') }}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- RBAC -->
<div class="section">
<h2>RBAC: Cluster Role Bindings ({{ data.rbac.bindings | length }})</h2>
<table>
<tr><th>Binding Name</th><th>Role</th><th>Subjects</th></tr>
{% for b in data.rbac.bindings %}
<tr>
  <td>{{ b.name }}</td>
  <td><span class="tag {{ 'tag-bad' if b.role=='cluster-admin' else '' }}">{{ b.role }}</span></td>
  <td>{% for s in b.subjects %}<span class="tag">{{ s.kind }}: {{ s.namespace + '/' if s.namespace else '' }}{{ s.name }}</span>{% endfor %}</td>
</tr>
{% endfor %}
</table>
</div>

<!-- SCCs -->
{% if data.sccs %}
<div class="section">
<h2>Security Context Constraints ({{ data.sccs | length }})</h2>
<table>
<tr><th>Name</th><th>Privileged</th><th>RunAsUser</th><th>SELinux</th><th>Volumes</th></tr>
{% for s in data.sccs %}
<tr>
  <td>{{ s.name }}</td>
  <td><span class="tag {{ 'tag-bad' if s.allow_privileged else 'tag-ok' }}">{{ s.allow_privileged }}</span></td>
  <td><span class="tag {{ 'tag-bad' if s.run_as_user=='RunAsAny' else 'tag-ok' }}">{{ s.run_as_user }}</span></td>
  <td>{{ s.se_linux_context }}</td>
  <td>{{ s.volumes | join(', ') }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endif %}

<div class="meta" style="margin-top:40px; text-align:center;">
  OpenShift Governance Tool -- Discovery Report | {{ data.collected_at[:19] }} UTC
</div>
</body>
</html>"""


class DiscoveryReportGenerator:
    """Generates discovery-only reports."""

    def __init__(self, cluster_info, inventory):
        self.data = build_discovery_data(cluster_info, inventory)

    def generate(self, output_path: str):
        path = Path(output_path)
        if path.suffix == ".html":
            self._generate_html(path)
        elif path.suffix == ".json":
            self.export_json(output_path)
        else:
            self._generate_markdown(path)

    def _generate_html(self, path: Path):
        template = Template(DISCOVERY_HTML)
        html = template.render(data=self.data)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _generate_markdown(self, path: Path):
        d = self.data
        lines = [
            "# OpenShift Cluster Discovery Report",
            "",
            f"**Cluster:** {d['cluster'].get('server', 'unknown')}",
            f"**Version:** {d['cluster'].get('version', 'unknown')}",
            f"**Collected:** {d['collected_at'][:19]} UTC",
            "",
            "## Resource Counts",
            "",
            "| Resource | Count |",
            "|----------|-------|",
        ]
        for rtype, count in d["counts"].items():
            lines.append(f"| {rtype} | {count} |")

        # Nodes
        lines.extend(["", f"## Nodes ({len(d['nodes'])})", "",
                       "| Name | Version | OS | CPU | Memory | Ready |",
                       "|------|---------|-----|-----|--------|-------|"])
        for n in d["nodes"]:
            ready = n["conditions"].get("Ready", "?")
            lines.append(f"| {n['name']} | {n['kubelet_version']} | {n['os'][:30]} | {n['allocatable'].get('cpu','')} | {n['allocatable'].get('memory','')} | {ready} |")

        # Deployments
        lines.extend(["", f"## Deployments ({len(d['deployments'])})", "",
                       "| Namespace | Name | Desired | Ready | Strategy |",
                       "|-----------|------|---------|-------|----------|"])
        for dep in d["deployments"]:
            lines.append(f"| {dep['namespace']} | {dep['name']} | {dep['replicas_desired']} | {dep['replicas_ready'] or 0} | {dep['strategy']} |")

        # Services
        lines.extend(["", f"## Services ({len(d['services'])})", "",
                       "| Namespace | Name | Type | Ports |",
                       "|-----------|------|------|-------|"])
        for s in d["services"]:
            ports = ", ".join(f"{p['port']}:{p['target_port']}" for p in s["ports"])
            lines.append(f"| {s['namespace']} | {s['name']} | {s['type']} | {ports} |")

        # Routes
        if d["routes"]:
            lines.extend(["", f"## Routes ({len(d['routes'])})", "",
                           "| Namespace | Name | Host | TLS | Target |",
                           "|-----------|------|------|-----|--------|"])
            for r in d["routes"]:
                lines.append(f"| {r['namespace']} | {r['name']} | {r['host']} | {r['tls_termination']} | {r['target_service']} |")

        # Storage
        lines.extend(["", f"## PVCs ({len(d['pvcs'])})", "",
                       "| Namespace | Name | Status | Class | Capacity |",
                       "|-----------|------|--------|-------|----------|"])
        for p in d["pvcs"]:
            lines.append(f"| {p['namespace']} | {p['name']} | {p['status']} | {p['storage_class']} | {p['capacity'].get('storage','')} |")

        lines.append("")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def export_json(self, output_path: str):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)
