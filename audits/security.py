"""
Security Audit Module

Checks:
- Pods running as root
- Privileged containers
- Default service account token mounts
- RBAC over-permissive bindings (cluster-admin)
- Secret age / rotation
- Namespace label requirements
- Host network / host PID usage
- SCC assignments (OpenShift)
"""

from datetime import datetime, timezone
from .base import BaseAudit


class SecurityAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_privileged_pods()
        self._check_root_pods()
        self._check_host_access()
        self._check_default_sa_tokens()
        self._check_cluster_admin_bindings()
        self._check_secret_age()
        self._check_namespace_labels()
        self._check_sccs()
        return self.findings

    def _check_privileged_pods(self):
        if not self.config.get("flag_privileged", True):
            return

        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            for container in (pod.spec.containers or []):
                sc = container.security_context
                if sc and sc.privileged:
                    self.finding(
                        "CRITICAL", "security",
                        f"Privileged container '{container.name}' in pod '{name}'",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Remove privileged: true from container securityContext"
                    )

    def _check_root_pods(self):
        if not self.config.get("flag_root_pods", True):
            return

        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            # Check pod-level security context
            pod_sc = pod.spec.security_context
            pod_run_as_non_root = pod_sc and pod_sc.run_as_non_root

            for container in (pod.spec.containers or []):
                sc = container.security_context
                container_run_as_non_root = sc and sc.run_as_non_root
                run_as_user = (sc and sc.run_as_user) or (pod_sc and pod_sc.run_as_user)

                if run_as_user == 0:
                    self.finding(
                        "CRITICAL", "security",
                        f"Container '{container.name}' runs as UID 0 (root) in pod '{name}'",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Set runAsUser to a non-zero UID"
                    )
                elif not pod_run_as_non_root and not container_run_as_non_root:
                    self.finding(
                        "WARNING", "security",
                        f"Container '{container.name}' in pod '{name}' does not enforce runAsNonRoot",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Set runAsNonRoot: true in securityContext"
                    )

    def _check_host_access(self):
        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name

            if pod.spec.host_network:
                self.finding(
                    "CRITICAL", "security",
                    f"Pod '{name}' uses hostNetwork",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Remove hostNetwork: true unless absolutely required"
                )

            if pod.spec.host_pid:
                self.finding(
                    "CRITICAL", "security",
                    f"Pod '{name}' uses hostPID",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Remove hostPID: true"
                )

            if pod.spec.host_ipc:
                self.finding(
                    "WARNING", "security",
                    f"Pod '{name}' uses hostIPC",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Remove hostIPC: true"
                )

    def _check_default_sa_tokens(self):
        if not self.config.get("flag_default_sa_tokens", True):
            return

        for pod in self.inventory["pods"]:
            ns = pod.metadata.namespace
            name = pod.metadata.name
            sa = pod.spec.service_account_name or "default"

            if sa == "default":
                auto_mount = pod.spec.automount_service_account_token
                if auto_mount is None or auto_mount:
                    self.finding(
                        "WARNING", "security",
                        f"Pod '{name}' uses default SA with auto-mounted token",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation="Set automountServiceAccountToken: false or use a dedicated SA"
                    )

    def _check_cluster_admin_bindings(self):
        for crb in self.inventory["cluster_role_bindings"]:
            role_ref = crb.role_ref
            if role_ref and role_ref.name == "cluster-admin":
                for subject in (crb.subjects or []):
                    if subject.kind == "ServiceAccount":
                        self.finding(
                            "CRITICAL", "security",
                            f"ServiceAccount '{subject.namespace}/{subject.name}' has cluster-admin via '{crb.metadata.name}'",
                            resource=crb.metadata.name,
                            remediation="Use least-privilege roles instead of cluster-admin"
                        )
                    elif subject.kind == "User":
                        self.finding(
                            "WARNING", "security",
                            f"User '{subject.name}' has cluster-admin via '{crb.metadata.name}'",
                            resource=crb.metadata.name,
                            remediation="Review if cluster-admin is necessary for this user"
                        )

    def _check_secret_age(self):
        max_days = self.config.get("secret_max_age_days", 90)
        now = datetime.now(timezone.utc)

        for secret in self.inventory["secrets"]:
            if secret.type in ("kubernetes.io/service-account-token",
                               "kubernetes.io/dockercfg",
                               "kubernetes.io/dockerconfigjson"):
                continue

            created = secret.metadata.creation_timestamp
            if created:
                age_days = (now - created).days
                if age_days > max_days:
                    ns = secret.metadata.namespace
                    name = secret.metadata.name
                    self.finding(
                        "WARNING", "security",
                        f"Secret '{name}' is {age_days} days old (threshold: {max_days})",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation=f"Rotate secrets older than {max_days} days"
                    )

    def _check_namespace_labels(self):
        required = self.config.get("required_namespace_labels", [])
        if not required:
            return

        for ns_obj in self.inventory["namespace_objects"]:
            labels = ns_obj.metadata.labels or {}
            name = ns_obj.metadata.name
            for req in required:
                if req not in labels:
                    self.finding(
                        "WARNING", "security",
                        f"Namespace '{name}' missing required label '{req}'",
                        resource=name,
                        namespace=name,
                        remediation=f"Add label '{req}' to namespace"
                    )

    def _check_sccs(self):
        """Check OpenShift Security Context Constraints."""
        for scc in self.inventory.get("sccs", []):
            name = scc.get("metadata", {}).get("name", "unknown")
            if scc.get("allowPrivilegedContainer", False):
                self.finding(
                    "INFO", "security",
                    f"SCC '{name}' allows privileged containers",
                    resource=name,
                    remediation="Restrict SCC or limit which SAs can use it"
                )
            if scc.get("runAsUser", {}).get("type") == "RunAsAny":
                self.finding(
                    "INFO", "security",
                    f"SCC '{name}' allows RunAsAny (any UID including root)",
                    resource=name,
                    remediation="Use MustRunAsRange or MustRunAsNonRoot"
                )
