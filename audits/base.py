"""Base audit class."""

from typing import List, Dict, Any


class BaseAudit:
    """Base class for all audit modules."""

    def __init__(self, conn, inventory: dict, config: dict):
        self.conn = conn
        self.inventory = inventory
        self.config = config
        self.findings: List[Dict[str, Any]] = []

    def finding(self, severity: str, category: str, message: str,
                resource: str = "", namespace: str = "", remediation: str = ""):
        """Record an audit finding."""
        self.findings.append({
            "severity": severity,
            "category": category,
            "message": message,
            "resource": resource,
            "namespace": namespace,
            "remediation": remediation,
        })

    def run(self) -> List[Dict[str, Any]]:
        """Run the audit. Subclasses must implement this."""
        raise NotImplementedError
