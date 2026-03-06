"""
Resource Audit Module

Checks:
- Pods without resource requests/limits
- CPU/memory request-to-limit ratios
- ResourceQuota utilization
- Idle deployments (0 replicas)
- Missing LimitRanges
"""

from datetime import datetime, timezone
from .base import BaseAudit


class ResourceAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_resource_requests_limits()
        self._check_request_limit_ratios()
        self._check_quota_usage()
        self._check_idle_deployments()
        self._check_limit_ranges()
        return self.findings

    def _check_resource_requests_limits(self):
        require_requests = self.config.get("require_requests", True)
        require_limits = self.config.get("require_limits", True)

        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            # Skip completed pods
            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            for container in (pod.spec.containers or []):
                res = container.resources
                cname = container.name

                if require_requests:
                    if not res or not res.requests:
                        self.finding(
                            "WARNING", "resources",
                            f"Container '{cname}' in pod '{name}' has no resource requests",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Add resources.requests.cpu and resources.requests.memory"
                        )

                if require_limits:
                    if not res or not res.limits:
                        self.finding(
                            "WARNING", "resources",
                            f"Container '{cname}' in pod '{name}' has no resource limits",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Add resources.limits.cpu and resources.limits.memory"
                        )

    def _parse_resource(self, value):
        """Parse k8s resource string to numeric (millicores or bytes)."""
        if value is None:
            return 0
        value = str(value)
        if value.endswith("m"):
            return float(value[:-1])
        if value.endswith("Mi"):
            return float(value[:-2]) * 1024 * 1024
        if value.endswith("Gi"):
            return float(value[:-2]) * 1024 * 1024 * 1024
        if value.endswith("Ki"):
            return float(value[:-2]) * 1024
        try:
            return float(value) * 1000  # cores to millicores
        except ValueError:
            return 0

    def _check_request_limit_ratios(self):
        cpu_warn = self.config.get("cpu_ratio_warn", 5.0)
        mem_warn = self.config.get("memory_ratio_warn", 3.0)

        for pod in self.inventory["pods"]:
            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            ns = pod.metadata.namespace
            name = pod.metadata.name

            for container in (pod.spec.containers or []):
                res = container.resources
                if not res or not res.requests or not res.limits:
                    continue

                # CPU ratio
                cpu_req = self._parse_resource(res.requests.get("cpu"))
                cpu_lim = self._parse_resource(res.limits.get("cpu"))
                if cpu_req > 0 and cpu_lim > 0:
                    ratio = cpu_lim / cpu_req
                    if ratio > cpu_warn:
                        self.finding(
                            "WARNING", "resources",
                            f"Container '{container.name}' in '{name}': CPU limit/request ratio {ratio:.1f}x (threshold: {cpu_warn}x)",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Reduce gap between CPU request and limit"
                        )

                # Memory ratio
                mem_req = self._parse_resource(res.requests.get("memory"))
                mem_lim = self._parse_resource(res.limits.get("memory"))
                if mem_req > 0 and mem_lim > 0:
                    ratio = mem_lim / mem_req
                    if ratio > mem_warn:
                        self.finding(
                            "WARNING", "resources",
                            f"Container '{container.name}' in '{name}': memory limit/request ratio {ratio:.1f}x (threshold: {mem_warn}x)",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Reduce gap between memory request and limit"
                        )

    def _check_quota_usage(self):
        warn_pct = self.config.get("quota_usage_warn_percent", 80)

        for rq in self.inventory["resource_quotas"]:
            ns = rq.metadata.namespace
            name = rq.metadata.name
            status = rq.status

            if not status or not status.hard or not status.used:
                continue

            for resource_name, hard_val in status.hard.items():
                used_val = status.used.get(resource_name, "0")
                hard_num = self._parse_resource(hard_val)
                used_num = self._parse_resource(used_val)

                if hard_num > 0:
                    pct = (used_num / hard_num) * 100
                    if pct >= warn_pct:
                        self.finding(
                            "WARNING", "resources",
                            f"ResourceQuota '{name}' in '{ns}': {resource_name} at {pct:.0f}% ({used_val}/{hard_val})",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation=f"Increase quota or reduce usage for {resource_name}"
                        )

    def _check_idle_deployments(self):
        idle_days = self.config.get("idle_deployment_days", 7)
        now = datetime.now(timezone.utc)

        for dep in self.inventory["deployments"]:
            ns = dep.metadata.namespace
            name = dep.metadata.name

            if dep.spec.replicas == 0:
                created = dep.metadata.creation_timestamp
                if created:
                    age = (now - created).days
                    if age > idle_days:
                        self.finding(
                            "INFO", "resources",
                            f"Deployment '{name}' scaled to 0 for {age} days",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Remove idle deployments or scale up if needed"
                        )

    def _check_limit_ranges(self):
        ns_with_lr = set()
        for lr in self.inventory["limit_ranges"]:
            ns_with_lr.add(lr.metadata.namespace)

        for ns in self.inventory["namespaces"]:
            if ns not in ns_with_lr:
                self.finding(
                    "INFO", "resources",
                    f"Namespace '{ns}' has no LimitRange",
                    resource=ns,
                    namespace=ns,
                    remediation="Add a LimitRange to set default resource requests/limits"
                )
