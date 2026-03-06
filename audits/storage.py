"""
Storage Audit Module

Checks:
- Unbound PVCs
- PVs with ReclaimPolicy Delete
- PVCs without storage class
- Overprovisioned storage
"""

from .base import BaseAudit


class StorageAudit(BaseAudit):

    def run(self):
        self.findings = []
        self._check_unbound_pvcs()
        self._check_reclaim_policy()
        self._check_storage_class_usage()
        self._check_pv_utilization()
        return self.findings

    def _check_unbound_pvcs(self):
        if not self.config.get("flag_unbound_pvcs", True):
            return

        for pvc in self.inventory["pvcs"]:
            ns = pvc.metadata.namespace
            name = pvc.metadata.name
            phase = pvc.status.phase if pvc.status else "Unknown"

            if phase == "Pending":
                self.finding(
                    "WARNING", "storage",
                    f"PVC '{name}' in '{ns}' is Pending (unbound)",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Check if a matching PV exists or if StorageClass can provision one"
                )
            elif phase == "Lost":
                self.finding(
                    "CRITICAL", "storage",
                    f"PVC '{name}' in '{ns}' is in Lost state",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Investigate the backing PV -- data may be at risk"
                )
            elif phase == "Bound":
                self.finding(
                    "PASS", "storage",
                    f"PVC '{name}' in '{ns}' is Bound",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                )

    def _check_reclaim_policy(self):
        if not self.config.get("flag_delete_reclaim", True):
            return

        for pv in self.inventory["pvs"]:
            name = pv.metadata.name
            policy = pv.spec.persistent_volume_reclaim_policy

            if policy == "Delete":
                # Check if used by a production namespace
                claim = pv.spec.claim_ref
                ns = claim.namespace if claim else "unbound"
                self.finding(
                    "WARNING", "storage",
                    f"PV '{name}' (bound to '{ns}') has ReclaimPolicy: Delete",
                    resource=name,
                    namespace=ns,
                    remediation="Set ReclaimPolicy to Retain for production data"
                )

    def _check_storage_class_usage(self):
        sc_names = {sc.metadata.name for sc in self.inventory["storage_classes"]}

        for pvc in self.inventory["pvcs"]:
            ns = pvc.metadata.namespace
            name = pvc.metadata.name
            sc = pvc.spec.storage_class_name

            if not sc:
                self.finding(
                    "INFO", "storage",
                    f"PVC '{name}' in '{ns}' has no explicit StorageClass",
                    resource=f"{ns}/{name}",
                    namespace=ns,
                    remediation="Specify a StorageClass to ensure consistent provisioning"
                )

    def _check_pv_utilization(self):
        """Flag PVs that are Released but not reused."""
        for pv in self.inventory["pvs"]:
            name = pv.metadata.name
            phase = pv.status.phase if pv.status else "Unknown"

            if phase == "Released":
                self.finding(
                    "INFO", "storage",
                    f"PV '{name}' is Released (not bound, not available)",
                    resource=name,
                    remediation="Delete or reclaim the PV to free storage"
                )
            elif phase == "Failed":
                self.finding(
                    "CRITICAL", "storage",
                    f"PV '{name}' is in Failed state",
                    resource=name,
                    remediation="Investigate PV failure -- automatic reclaim may have failed"
                )
