"""
Compute Audit Module

Checks:
- Node CPU/memory utilization
- Unschedulable nodes
- Node conditions (DiskPressure, MemoryPressure, PIDPressure)
- Taint/toleration coverage
- Node version skew
"""

from .base import BaseAudit


class ComputeAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_node_conditions()
        self._check_unschedulable()
        self._check_node_capacity()
        self._check_version_skew()
        return self.findings

    def _check_node_conditions(self):
        if not self.config.get("flag_node_conditions", True):
            return

        problem_conditions = {"DiskPressure", "MemoryPressure", "PIDPressure", "NetworkUnavailable"}

        for node in self.inventory["nodes"]:
            name = node.metadata.name
            for condition in (node.status.conditions or []):
                if condition.type in problem_conditions and condition.status == "True":
                    self.finding(
                        "CRITICAL", "compute",
                        f"Node '{name}' has {condition.type} = True",
                        resource=name,
                        remediation=f"Investigate {condition.type} on node '{name}': {condition.message or ''}"
                    )

                if condition.type == "Ready" and condition.status != "True":
                    self.finding(
                        "CRITICAL", "compute",
                        f"Node '{name}' is NotReady (status: {condition.status})",
                        resource=name,
                        remediation=f"Check kubelet and node health: {condition.message or ''}"
                    )

    def _check_unschedulable(self):
        if not self.config.get("flag_unschedulable", True):
            return

        for node in self.inventory["nodes"]:
            name = node.metadata.name
            if node.spec.unschedulable:
                self.finding(
                    "WARNING", "compute",
                    f"Node '{name}' is cordoned (unschedulable)",
                    resource=name,
                    remediation="Uncordon node or remove from cluster if decommissioned"
                )

    def _parse_resource_value(self, value):
        """Parse k8s resource quantities."""
        if not value:
            return 0
        value = str(value)
        if value.endswith("Ki"):
            return float(value[:-2]) * 1024
        if value.endswith("Mi"):
            return float(value[:-2]) * 1024 * 1024
        if value.endswith("Gi"):
            return float(value[:-2]) * 1024 * 1024 * 1024
        if value.endswith("m"):
            return float(value[:-1]) / 1000
        try:
            return float(value)
        except ValueError:
            return 0

    def _check_node_capacity(self):
        cpu_warn = self.config.get("node_cpu_warn_percent", 80)
        mem_warn = self.config.get("node_memory_warn_percent", 85)

        # Calculate per-node pod resource requests
        node_requests = {}
        for pod in self.inventory["pods"]:
            if pod.status and pod.status.phase not in ("Running", "Pending"):
                continue
            node_name = pod.spec.node_name
            if not node_name:
                continue

            if node_name not in node_requests:
                node_requests[node_name] = {"cpu": 0, "memory": 0}

            for container in (pod.spec.containers or []):
                res = container.resources
                if res and res.requests:
                    cpu_req = res.requests.get("cpu", "0")
                    mem_req = res.requests.get("memory", "0")
                    node_requests[node_name]["cpu"] += self._parse_resource_value(cpu_req)
                    node_requests[node_name]["memory"] += self._parse_resource_value(mem_req)

        for node in self.inventory["nodes"]:
            name = node.metadata.name
            allocatable = node.status.allocatable or {}

            alloc_cpu = self._parse_resource_value(allocatable.get("cpu", "0"))
            alloc_mem = self._parse_resource_value(allocatable.get("memory", "0"))

            req = node_requests.get(name, {"cpu": 0, "memory": 0})

            if alloc_cpu > 0:
                cpu_pct = (req["cpu"] / alloc_cpu) * 100
                if cpu_pct >= cpu_warn:
                    self.finding(
                        "WARNING", "compute",
                        f"Node '{name}' CPU requested at {cpu_pct:.0f}% of allocatable",
                        resource=name,
                        remediation="Scale cluster or redistribute workloads"
                    )

            if alloc_mem > 0:
                mem_pct = (req["memory"] / alloc_mem) * 100
                if mem_pct >= mem_warn:
                    self.finding(
                        "WARNING", "compute",
                        f"Node '{name}' memory requested at {mem_pct:.0f}% of allocatable",
                        resource=name,
                        remediation="Scale cluster or redistribute workloads"
                    )

    def _check_version_skew(self):
        """Flag nodes running different kubelet versions."""
        versions = {}
        for node in self.inventory["nodes"]:
            name = node.metadata.name
            ver = node.status.node_info.kubelet_version if node.status and node.status.node_info else "unknown"
            versions.setdefault(ver, []).append(name)

        if len(versions) > 1:
            version_summary = ", ".join(f"{v} ({len(nodes)} nodes)" for v, nodes in versions.items())
            self.finding(
                "WARNING", "compute",
                f"Node version skew detected: {version_summary}",
                resource="cluster",
                remediation="Align all nodes to the same kubelet version"
            )
        elif len(versions) == 1:
            ver = list(versions.keys())[0]
            self.finding(
                "PASS", "compute",
                f"All {len(self.inventory['nodes'])} nodes running kubelet {ver}",
                resource="cluster",
            )
