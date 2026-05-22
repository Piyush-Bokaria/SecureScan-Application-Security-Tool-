"""
report_generator.py — Generates structured remediation reports.

Supports three output formats:
  - Console: Rich-formatted colorized terminal output.
  - JSON: Machine-readable structured report.
  - HTML: Professional styled report from a Jinja2 template.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from securescanner.scanner import ScanResult
from securescanner.owasp_mapper import OWASPMapper, OWASP_TOP_10


# Path to the HTML report template
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.

    Usage:
        generator = ReportGenerator(scan_result, owasp_summary)
        generator.generate_console()
        generator.generate_json("report.json")
        generator.generate_html("report.html")
    """

    SEVERITY_COLORS = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    SEVERITY_ICONS = {
        "HIGH": "🔴",
        "MEDIUM": "🟡",
        "LOW": "🔵",
    }

    def __init__(self, scan_result: ScanResult, owasp_summary: dict):
        """
        Args:
            scan_result: The complete scan result from SecurityScanner.
            owasp_summary: OWASP category summary from OWASPMapper.
        """
        self.result = scan_result
        self.owasp_summary = owasp_summary
        self.console = Console()

    # ── Console Report ────────────────────────────────────────────────

    def generate_console(self) -> None:
        """Print a rich-formatted report to the terminal."""
        self._print_header()
        self._print_summary_table()
        self._print_owasp_breakdown()
        self._print_findings_detail()
        self._print_footer()

    def _print_header(self) -> None:
        header_text = Text()
        header_text.append("🛡️  SecureScan ", style="bold cyan")
        header_text.append("Security Report\n", style="bold white")
        header_text.append(f"Target: ", style="dim")
        header_text.append(f"{self.result.metadata.target}\n", style="white")
        header_text.append(f"Scanned: ", style="dim")
        header_text.append(f"{self.result.metadata.timestamp}\n", style="white")
        header_text.append(f"Duration: ", style="dim")
        header_text.append(f"{self.result.metadata.duration_seconds}s", style="white")

        self.console.print(Panel(header_text, border_style="cyan", box=box.DOUBLE))

    def _print_summary_table(self) -> None:
        table = Table(
            title="📊 Scan Summary",
            box=box.ROUNDED,
            border_style="cyan",
            title_style="bold cyan",
        )
        table.add_column("Metric", style="bold white", min_width=25)
        table.add_column("Value", justify="center", min_width=15)

        sev = self.result.severity_counts
        table.add_row("Total Findings", str(self.result.total_findings))
        table.add_row("Files Scanned", str(self.result.metadata.total_files_scanned))
        table.add_row(
            "🔴 High Severity",
            Text(str(sev["HIGH"]), style="bold red"),
        )
        table.add_row(
            "🟡 Medium Severity",
            Text(str(sev["MEDIUM"]), style="bold yellow"),
        )
        table.add_row(
            "🔵 Low Severity",
            Text(str(sev["LOW"]), style="bold blue"),
        )

        status = "✅ PASS" if not self.result.has_high_severity else "❌ FAIL"
        status_style = "bold green" if not self.result.has_high_severity else "bold red"
        table.add_row("Status", Text(status, style=status_style))

        self.console.print(table)
        self.console.print()

    def _print_owasp_breakdown(self) -> None:
        if not self.owasp_summary:
            return

        table = Table(
            title="🏛️  OWASP Top 10:2021 Breakdown",
            box=box.ROUNDED,
            border_style="magenta",
            title_style="bold magenta",
        )
        table.add_column("OWASP ID", style="bold white", min_width=12)
        table.add_column("Category", min_width=30)
        table.add_column("Count", justify="center", min_width=8)
        table.add_column("High", justify="center", style="red", min_width=6)
        table.add_column("Medium", justify="center", style="yellow", min_width=8)
        table.add_column("Low", justify="center", style="blue", min_width=6)

        for owasp_id, data in self.owasp_summary.items():
            sev = data["severity_breakdown"]
            table.add_row(
                owasp_id,
                data["name"],
                str(data["count"]),
                str(sev["HIGH"]),
                str(sev["MEDIUM"]),
                str(sev["LOW"]),
            )

        self.console.print(table)
        self.console.print()

    def _print_findings_detail(self) -> None:
        if not self.result.findings:
            self.console.print(
                Panel(
                    "✅ No security issues found!",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )
            return

        self.console.print(
            Text("📋 Detailed Findings", style="bold white underline")
        )
        self.console.print()

        for idx, finding in enumerate(self.result.findings, 1):
            sev_color = self.SEVERITY_COLORS.get(finding.severity, "white")
            sev_icon = self.SEVERITY_ICONS.get(finding.severity, "⚪")

            # Finding header
            title = (
                f"{sev_icon} [{idx}] {finding.test_id}: {finding.test_name}"
            )

            content = Text()
            content.append(f"File: ", style="dim")
            content.append(f"{finding.filename}:{finding.line_number}\n", style="white")
            content.append(f"Severity: ", style="dim")
            content.append(f"{finding.severity}", style=f"bold {sev_color}")
            content.append(f"  Confidence: ", style="dim")
            content.append(f"{finding.confidence}\n", style="white")
            content.append(f"CWE: ", style="dim")
            content.append(f"CWE-{finding.cwe_id}\n", style="white")
            content.append(f"OWASP: ", style="dim")
            content.append(
                f"{finding.owasp_id} — {finding.owasp_category}\n", style="magenta"
            )
            content.append(f"\nIssue: ", style="dim")
            content.append(f"{finding.issue_text}\n", style="white")

            if finding.code_snippet:
                content.append(f"\nCode:\n", style="dim")
                content.append(f"{finding.code_snippet}\n", style="cyan")

            content.append(f"\n💡 Remediation: ", style="bold green")
            content.append(f"{finding.remediation}", style="green")

            self.console.print(
                Panel(content, title=title, border_style=sev_color, box=box.ROUNDED)
            )
            self.console.print()

    def _print_footer(self) -> None:
        footer = Text()
        footer.append("─" * 60 + "\n", style="dim")
        footer.append("Generated by ", style="dim")
        footer.append("SecureScan v1.0.0", style="bold cyan")
        footer.append(" • ", style="dim")
        footer.append("OWASP Top 10:2021 Mapping", style="dim magenta")
        self.console.print(footer)

    # ── JSON Report ───────────────────────────────────────────────────

    def generate_json(self, output_path: Optional[str] = None) -> str:
        """
        Generate a JSON report.

        Args:
            output_path: If provided, write JSON to this file path.

        Returns:
            The JSON string.
        """
        report = {
            "report": {
                "tool": "SecureScan",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
            },
            "scan": self.result.to_dict(),
            "owasp_summary": self.owasp_summary,
        }

        json_str = json.dumps(report, indent=2, default=str)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    # ── HTML Report ───────────────────────────────────────────────────

    def generate_html(self, output_path: Optional[str] = None) -> str:
        """
        Generate an HTML report using the Jinja2 template.

        Args:
            output_path: If provided, write HTML to this file path.

        Returns:
            The HTML string.
        """
        try:
            from jinja2 import Environment, FileSystemLoader
        except ImportError:
            raise RuntimeError(
                "Jinja2 is required for HTML reports. Install it: pip install jinja2"
            )

        template_dir = _TEMPLATES_DIR
        if not template_dir.exists():
            raise FileNotFoundError(f"Templates directory not found: {template_dir}")

        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=True,
        )
        template = env.get_template("report.html")

        html = template.render(
            result=self.result,
            findings=self.result.findings,
            owasp_summary=self.owasp_summary,
            owasp_top_10=OWASP_TOP_10,
            severity_counts=self.result.severity_counts,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html
