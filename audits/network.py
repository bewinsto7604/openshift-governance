"""
Network Audit Module

Checks:
- Namespaces without NetworkPolicy
- Routes without TLS termination
- LoadBalancer services
- Services exposing sensitive ports
"""

from .base import BaseAudit


SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 9200, 2379, 8443}


class NetworkAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_network_policies()
        self._check_tls_routes()
        self._check_loadbalancer_services()
        self._check_sensitive_ports()
        return self.findings

    def _check_network_policies(self):
        if not self.config.get("require_network_policy", True):
            return

        ns_with_np = set()
        for np in self.inventory["network_policies"]:
            ns_with_np.add(np.metadata.namespace)

        for ns in self.inventory["namespaces"]:
            if ns not in ns_with_np:
                self.finding(
                    "WARNING", "network",
                    f"Namespace '{ns}' has no NetworkPolicy (all traffic allowed)",
                    resource=ns,
                    namespace=ns,
                    remediation="Add a default-deny NetworkPolicy and whitelist required traffic"
                )
            else:
                self.finding(
                    "PASS", "network",
                    f"Namespace '{ns}' has NetworkPolicy defined",
                    resource=ns,
                    namespace=ns,
                )

    def _check_tls_routes(self):
        if not self.config.get("require_tls_routes", True):
            return

        for route in self.inventory.get("routes", []):
            name = route.get("metadata", {}).get("name", "unknown")
            ns = route.get("metadata", {}).get("namespace", "unknown")
            tls = route.get("spec", {}).get("tls")

            if not tls:
                self.finding(
                    "WARNING", "network",
                    f"Route '{name}' in '{ns}' has no TLS termination",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Add TLS termination (edge, passthrough, or reencrypt)"
                )
            else:
                self.finding(
                    "PASS", "network",
                    f"Route '{name}' in '{ns}' has TLS ({tls.get('termination', 'configured')})",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                )

    def _check_loadbalancer_services(self):
        if not self.config.get("flag_loadbalancer_services", True):
            return

        for svc in self.inventory["services"]:
            if svc.spec.type == "LoadBalancer":
                ns = svc.metadata.namespace
                name = svc.metadata.name
                self.finding(
                    "INFO", "network",
                    f"Service '{name}' in '{ns}' is type LoadBalancer (external exposure)",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Verify this service should be externally accessible"
                )

    def _check_sensitive_ports(self):
        for svc in self.inventory["services"]:
            ns = svc.metadata.namespace
            name = svc.metadata.name

            for port in (svc.spec.ports or []):
                target = port.target_port if port.target_port else port.port
                try:
                    port_num = int(target)
                except (ValueError, TypeError):
                    continue

                if port_num in SENSITIVE_PORTS and svc.spec.type in ("LoadBalancer", "NodePort"):
                    self.finding(
                        "CRITICAL", "network",
                        f"Service '{name}' in '{ns}' exposes sensitive port {port_num} via {svc.spec.type}",
                        resource=f"{ns}/{name}",
                        namespace=ns,
                        remediation=f"Use ClusterIP for port {port_num} or restrict access via NetworkPolicy"
                    )
