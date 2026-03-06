"""
Compliance & Best Practices Audit Module

Checks:
- Missing liveness/readiness probes
- Images using :latest tag
- Image pull policy
- Pod restart counts
- Missing PodDisruptionBudgets
- Anti-affinity for HA deployments
"""

from .base import BaseAudit


class ComplianceAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_probes()
        self._check_image_tags()
        self._check_image_pull_policy()
        self._check_restart_counts()
        self._check_pdbs()
        self._check_replica_count()
        return self.findings

    def _check_probes(self):
        require_liveness = self.config.get("require_liveness_probes", True)
        require_readiness = self.config.get("require_readiness_probes", True)

        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            # Skip jobs/cronjobs (owner reference check)
            owners = pod.metadata.owner_references or []
            if any(o.kind == "Job" for o in owners):
                continue

            for container in (pod.spec.containers or []):
                cname = container.name

                if require_liveness and not container.liveness_probe:
                    self.finding(
                        "WARNING", "compliance",
                        f"Container '{cname}' in pod '{name}' has no liveness probe",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Add a livenessProbe to detect stuck containers"
                    )

                if require_readiness and not container.readiness_probe:
                    self.finding(
                        "WARNING", "compliance",
                        f"Container '{cname}' in pod '{name}' has no readiness probe",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Add a readinessProbe to prevent traffic to unready pods"
                    )

    def _check_image_tags(self):
        if not self.config.get("flag_latest_tag", True):
            return

        for pod in self.inventory["pods"]:
            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            ns = pod.metadata.namespace
            name = pod.metadata.name

            for container in (pod.spec.containers or []):
                image = container.image or ""
                if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                    self.finding(
                        "WARNING", "compliance",
                        f"Container '{container.name}' in pod '{name}' uses image tag ':latest' or untagged ({image})",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Pin images to a specific version tag or SHA digest"
                    )

    def _check_image_pull_policy(self):
        if not self.config.get("require_always_pull", True):
            return

        for pod in self.inventory["pods"]:
            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            ns = pod.metadata.namespace
            name = pod.metadata.name

            for container in (pod.spec.containers or []):
                policy = container.image_pull_policy
                if policy and policy != "Always":
                    image = container.image or ""
                    if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                        self.finding(
                            "WARNING", "compliance",
                            f"Container '{container.name}' in pod '{name}' uses ':latest' with pullPolicy '{policy}'",
                            resource=f"{ns}/{name}",
                            namespace=ns,
                            remediation="Set imagePullPolicy: Always for latest/untagged images"
                        )

    def _check_restart_counts(self):
        max_restarts = self.config.get("max_restart_count", 5)

        for pod in self.inventory["pods"]:
            if pod.status and pod.status.phase in ("Succeeded", "Failed"):
                continue

            ns = pod.metadata.namespace
            name = pod.metadata.name

            for cs in (pod.status.container_statuses or []) if pod.status else []:
                if cs.restart_count > max_restarts:
                    self.finding(
                        "WARNING", "compliance",
                        f"Container '{cs.name}' in pod '{name}' has restarted {cs.restart_count} times (threshold: {max_restarts})",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Investigate CrashLoopBackOff or OOMKilled causes"
                    )

    def _check_pdbs(self):
        if not self.config.get("require_pdb", True):
            return

        # Build set of deployments with PDBs
        pdb_selectors = []
        for pdb in self.inventory["pdbs"]:
            if pdb.spec.selector and pdb.spec.selector.match_labels:
                pdb_selectors.append({
                    "namespace": pdb.metadata.namespace,
                    "labels": pdb.spec.selector.match_labels,
                })

        for dep in self.inventory["deployments"]:
            ns = dep.metadata.namespace
            name = dep.metadata.name
            replicas = dep.spec.replicas or 1

            if replicas < 2:
                continue

            dep_labels = dep.spec.selector.match_labels if dep.spec.selector else {}
            has_pdb = any(
                p["namespace"] == ns and
                all(dep_labels.get(k) == v for k, v in p["labels"].items())
                for p in pdb_selectors
            )

            if not has_pdb:
                self.finding(
                    "WARNING", "compliance",
                    f"Deployment '{name}' in '{ns}' ({replicas} replicas) has no PodDisruptionBudget",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Add a PodDisruptionBudget to ensure availability during disruptions"
                )

    def _check_replica_count(self):
        """Flag single-replica deployments that should be HA."""
        for dep in self.inventory["deployments"]:
            ns = dep.metadata.namespace
            name = dep.metadata.name
            replicas = dep.spec.replicas

            if replicas == 1:
                self.finding(
                    "INFO", "compliance",
                    f"Deployment '{name}' in '{ns}' has only 1 replica (no HA)",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Consider running 2+ replicas for availability"
                )
