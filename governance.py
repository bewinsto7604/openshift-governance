#!/usr/bin/env python3
"""
OpenShift Governance Tool

Connects to a live OpenShift cluster and audits configuration across
security, resources, network, storage, compute, and compliance.

Usage:
    python governance.py --config config.yaml
    python governance.py --config config.yaml --audit security,network
    python governance.py --config config.yaml --output report.html
"""

import click
import yaml
import sys
from pathlib import Path
from datetime import datetime

from cluster import ClusterConnection
from discovery import ClusterDiscovery
from audits.security import SecurityAudit
from audits.resources import ResourceAudit
from audits.network import NetworkAudit
from audits.storage import StorageAudit
from audits.compute import ComputeAudit
from audits.compliance import ComplianceAudit
from report import ReportGenerator


AUDIT_CLASSES = {
    "security": SecurityAudit,
    "resources": ResourceAudit,
    "network": NetworkAudit,
    "storage": StorageAudit,
    "compute": ComputeAudit,
    "compliance": ComplianceAudit,
}


@click.command()
@click.option("--config", "-c", default="config.yaml", help="Path to config file")
@click.option("--audit", "-a", default=None, help="Comma-separated audit categories to run (default: all enabled)")
@click.option("--output", "-o", default=None, help="Output report file (.html or .md)")
@click.option("--namespace", "-n", default=None, help="Audit a specific namespace only")
@click.option("--json-output", "-j", default=None, help="Export findings as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def main(config, audit, output, namespace, json_output, verbose):
    """OpenShift Governance & Compliance Auditor"""

    # Load config
    config_path = Path(config)
    if not config_path.exists():
        click.echo(f"Config file not found: {config}")
        sys.exit(1)

    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    click.echo("=" * 70)
    click.echo("  OPENSHIFT GOVERNANCE AUDIT")
    click.echo(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    click.echo("=" * 70)

    # Connect to cluster
    click.echo("\nConnecting to cluster...")
    conn = ClusterConnection(context=cfg.get("cluster", {}).get("context"))
    if not conn.connect():
        click.echo("ERROR: Could not connect to OpenShift cluster.")
        click.echo("Ensure you are logged in (oc login) or kubeconfig is set.")
        sys.exit(1)

    cluster_info = conn.get_cluster_info()
    click.echo(f"  Cluster: {cluster_info['server']}")
    click.echo(f"  Version: {cluster_info.get('version', 'unknown')}")
    click.echo(f"  User:    {cluster_info.get('user', 'unknown')}")

    # Discovery phase
    click.echo("\nDiscovering cluster resources...")
    discovery = ClusterDiscovery(conn, cfg, target_namespace=namespace)
    inventory = discovery.collect()

    click.echo(f"  Namespaces:    {inventory['counts']['namespaces']}")
    click.echo(f"  Pods:          {inventory['counts']['pods']}")
    click.echo(f"  Deployments:   {inventory['counts']['deployments']}")
    click.echo(f"  Services:      {inventory['counts']['services']}")
    click.echo(f"  Routes:        {inventory['counts']['routes']}")
    click.echo(f"  PVCs:          {inventory['counts']['pvcs']}")
    click.echo(f"  Nodes:         {inventory['counts']['nodes']}")

    # Determine which audits to run
    if audit:
        audit_names = [a.strip() for a in audit.split(",")]
    else:
        audit_names = [
            name for name, enabled in cfg.get("audits", {}).items()
            if enabled
        ]

    # Run audits
    all_findings = []
    summaries = {}

    for name in audit_names:
        if name not in AUDIT_CLASSES:
            click.echo(f"  WARNING: Unknown audit category '{name}', skipping")
            continue

        click.echo(f"\n{'─' * 70}")
        click.echo(f"  AUDIT: {name.upper()}")
        click.echo(f"{'─' * 70}")

        audit_cfg = cfg.get(name, {})
        audit_instance = AUDIT_CLASSES[name](conn, inventory, audit_cfg)
        findings = audit_instance.run()

        critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
        warning = sum(1 for f in findings if f["severity"] == "WARNING")
        info = sum(1 for f in findings if f["severity"] == "INFO")
        passed = sum(1 for f in findings if f["severity"] == "PASS")

        summaries[name] = {
            "total": len(findings),
            "critical": critical,
            "warning": warning,
            "info": info,
            "passed": passed,
        }

        if verbose:
            for f in findings:
                icon = {"CRITICAL": "X", "WARNING": "!", "INFO": "-", "PASS": "+"}
                click.echo(f"  [{icon.get(f['severity'], '?')}] {f['severity']}: {f['message']}")
        else:
            click.echo(f"  Critical: {critical}  Warning: {warning}  Info: {info}  Pass: {passed}")

        all_findings.extend(findings)

    # Summary
    total_critical = sum(s["critical"] for s in summaries.values())
    total_warning = sum(s["warning"] for s in summaries.values())
    total_findings = len(all_findings)

    click.echo(f"\n{'=' * 70}")
    click.echo("  AUDIT SUMMARY")
    click.echo(f"{'=' * 70}")
    click.echo(f"  Total findings:  {total_findings}")
    click.echo(f"  Critical:        {total_critical}")
    click.echo(f"  Warning:         {total_warning}")
    click.echo(f"  Overall status:  {'FAIL' if total_critical > 0 else 'WARN' if total_warning > 0 else 'PASS'}")

    # Generate report
    if output or json_output:
        report = ReportGenerator(
            cluster_info=cluster_info,
            inventory=inventory,
            findings=all_findings,
            summaries=summaries,
            config=cfg,
        )

        if output:
            report.generate(output)
            click.echo(f"\n  Report saved: {output}")

        if json_output:
            report.export_json(json_output)
            click.echo(f"  JSON export:  {json_output}")

    click.echo("")


if __name__ == "__main__":
    main()
