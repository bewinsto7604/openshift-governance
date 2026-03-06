#!/usr/bin/env python3
"""
Report Generator

Generates HTML and Markdown governance reports with findings,
summaries, and remediation guidance.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from jinja2 import Template


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OpenShift Governance Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #f5f5f5; color: #333; }
  h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
  h2 { color: #16213e; margin-top: 30px; }
  .meta { color: #666; font-size: 14px; margin-bottom: 30px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
  .summary-card { background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  .summary-card .number { font-size: 36px; font-weight: bold; }
  .summary-card .label { font-size: 12px; text-transform: uppercase; color: #666; }
  .critical .number { color: #e94560; }
  .warning .number { color: #f59e0b; }
  .info .number { color: #3b82f6; }
  .pass .number { color: #10b981; }
  .status-pass { background: #10b981; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
  .status-fail { background: #e94560; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
  .status-warn { background: #f59e0b; color: white; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
  th { background: #1a1a2e; color: white; padding: 12px 15px; text-align: left; font-size: 13px; }
  td { padding: 10px 15px; border-bottom: 1px solid #eee; font-size: 13px; }
  tr:hover { background: #f0f7ff; }
  .sev-CRITICAL { color: #e94560; font-weight: bold; }
  .sev-WARNING { color: #f59e0b; font-weight: bold; }
  .sev-INFO { color: #3b82f6; }
  .sev-PASS { color: #10b981; }
  .inventory { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 15px 0; }
  .inv-item { background: white; border-radius: 6px; padding: 12px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .inv-item .count { font-size: 24px; font-weight: bold; color: #1a1a2e; }
  .inv-item .type { font-size: 11px; color: #666; text-transform: uppercase; }
  .category-section { margin: 25px 0; }
  .remediation { font-size: 12px; color: #666; font-style: italic; }
</style>
</head>
<body>
<h1>OpenShift Governance Report</h1>
<div class="meta">
  <strong>Cluster:</strong> {{ cluster_info.server }} |
  <strong>Version:</strong> {{ cluster_info.version }} |
  <strong>Generated:</strong> {{ generated_at }} |
  <strong>Status:</strong> <span class="{{ overall_status_class }}">{{ overall_status }}</span>
</div>

<h2>Cluster Inventory</h2>
<div class="inventory">
{% for type, count in inventory.counts.items() %}
  <div class="inv-item"><div class="count">{{ count }}</div><div class="type">{{ type }}</div></div>
{% endfor %}
</div>

<h2>Audit Summary</h2>
<div class="summary-grid">
  <div class="summary-card critical"><div class="number">{{ total_critical }}</div><div class="label">Critical</div></div>
  <div class="summary-card warning"><div class="number">{{ total_warning }}</div><div class="label">Warning</div></div>
  <div class="summary-card info"><div class="number">{{ total_info }}</div><div class="label">Info</div></div>
  <div class="summary-card pass"><div class="number">{{ total_pass }}</div><div class="label">Pass</div></div>
</div>

{% for category, findings in findings_by_category.items() %}
<div class="category-section">
<h2>{{ category | upper }}</h2>
<table>
<tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Remediation</th></tr>
{% for f in findings %}
<tr>
  <td class="sev-{{ f.severity }}">{{ f.severity }}</td>
  <td>{{ f.resource }}</td>
  <td>{{ f.message }}</td>
  <td class="remediation">{{ f.remediation }}</td>
</tr>
{% endfor %}
</table>
</div>
{% endfor %}

<div class="meta" style="margin-top:40px; text-align:center;">
  OpenShift Governance Tool | {{ generated_at }}
</div>
</body>
</html>"""


class ReportGenerator:
    """Generates governance audit reports."""

    def __init__(self, cluster_info, inventory, findings, summaries, config):
        self.cluster_info = cluster_info
        self.inventory = inventory
        self.findings = findings
        self.summaries = summaries
        self.config = config
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_path: str):
        """Generate report (HTML or Markdown based on extension)."""
        path = Path(output_path)
        if path.suffix == ".html":
            self._generate_html(path)
        else:
            self._generate_markdown(path)

    def _generate_html(self, path: Path):
        total_critical = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        total_warning = sum(1 for f in self.findings if f["severity"] == "WARNING")
        total_info = sum(1 for f in self.findings if f["severity"] == "INFO")
        total_pass = sum(1 for f in self.findings if f["severity"] == "PASS")

        overall = "FAIL" if total_critical > 0 else "WARN" if total_warning > 0 else "PASS"
        status_class = f"status-{overall.lower()}"

        # Group findings by category
        by_category = {}
        for f in self.findings:
            cat = f["category"]
            by_category.setdefault(cat, []).append(f)

        # Sort each category: CRITICAL first, then WARNING, INFO, PASS
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2, "PASS": 3}
        for cat in by_category:
            by_category[cat].sort(key=lambda x: severity_order.get(x["severity"], 9))

        template = Template(HTML_TEMPLATE)
        html = template.render(
            cluster_info=self.cluster_info,
            inventory=self.inventory,
            findings_by_category=by_category,
            total_critical=total_critical,
            total_warning=total_warning,
            total_info=total_info,
            total_pass=total_pass,
            overall_status=overall,
            overall_status_class=status_class,
            generated_at=self.generated_at,
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _generate_markdown(self, path: Path):
        lines = [
            "# OpenShift Governance Report",
            "",
            f"**Cluster:** {self.cluster_info.get('server', 'unknown')}",
            f"**Version:** {self.cluster_info.get('version', 'unknown')}",
            f"**Generated:** {self.generated_at}",
            "",
            "## Inventory",
            "",
            "| Resource | Count |",
            "|----------|-------|",
        ]

        for rtype, count in self.inventory["counts"].items():
            lines.append(f"| {rtype} | {count} |")

        lines.extend(["", "## Findings", ""])

        # Group by category
        by_category = {}
        for f in self.findings:
            by_category.setdefault(f["category"], []).append(f)

        for cat, findings in by_category.items():
            lines.append(f"### {cat.upper()}")
            lines.append("")
            lines.append("| Severity | Resource | Finding | Remediation |")
            lines.append("|----------|----------|---------|-------------|")
            for f in findings:
                lines.append(f"| {f['severity']} | {f['resource']} | {f['message']} | {f['remediation']} |")
            lines.append("")

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def export_json(self, output_path: str):
        """Export findings as JSON."""
        data = {
            "cluster": self.cluster_info,
            "generated_at": self.generated_at,
            "inventory_counts": self.inventory["counts"],
            "summaries": self.summaries,
            "total_findings": len(self.findings),
            "findings": self.findings,
        }

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
