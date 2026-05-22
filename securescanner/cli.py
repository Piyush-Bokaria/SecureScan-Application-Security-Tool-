"""
cli.py — Command-line interface for SecureScan.

Provides the main entry point for running security scans from the terminal.
Supports multiple output formats and configurable severity/confidence thresholds.
"""

import argparse
import io
import os
import sys

from rich.console import Console

from securescanner import __version__
from securescanner.scanner import SecurityScanner
from securescanner.owasp_mapper import OWASPMapper
from securescanner.report_generator import ReportGenerator


# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )
    except Exception:
        pass


def create_parser() -> argparse.ArgumentParser:
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="securescanner",
        description=(
            "🛡️  SecureScan — SAST Security Scanner with OWASP Top 10 Mapping\n\n"
            "Scans Python source code for security vulnerabilities using Bandit,\n"
            "maps findings to OWASP Top 10:2021 categories, and generates\n"
            "structured remediation reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  securescanner ./myproject\n"
            "  securescanner ./myproject --format json --output report.json\n"
            "  securescanner ./myproject --format html --output report.html\n"
            "  securescanner ./myproject --severity MEDIUM --confidence HIGH\n"
        ),
    )

    parser.add_argument(
        "target",
        help="Path to the Python file or directory to scan",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json", "html"],
        default="console",
        dest="output_format",
        help="Output format (default: console)",
    )

    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write report to a file (default: stdout for console/json)",
    )

    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Minimum severity threshold (default: LOW)",
    )

    parser.add_argument(
        "--confidence",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Minimum confidence threshold (default: LOW)",
    )

    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        default=False,
        help="Exit with code 1 if any HIGH severity issues are found",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"SecureScan v{__version__}",
    )

    return parser


def main(argv=None) -> int:
    """
    Main entry point for the SecureScan CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code (0 for success, 1 for findings that exceed threshold).
    """
    parser = create_parser()
    args = parser.parse_args(argv)
    console = Console()

    try:
        # ── 1. Scan ──────────────────────────────────────────────────
        scanner = SecurityScanner(
            severity_threshold=args.severity,
            confidence_threshold=args.confidence,
        )

        console.print(f"[bold cyan]Scanning:[/bold cyan] {args.target} ...\n")
        result = scanner.scan(args.target)

        # ── 2. Map to OWASP ──────────────────────────────────────────
        mapper = OWASPMapper()
        mapper.enrich_findings(result.findings)
        owasp_summary = mapper.get_owasp_summary(result.findings)
        result.summary = {"owasp_categories_found": len(owasp_summary)}

        # ── 3. Generate Report ────────────────────────────────────────
        reporter = ReportGenerator(result, owasp_summary)

        if args.output_format == "console":
            reporter.generate_console()
            if args.output:
                reporter.generate_json(args.output.replace(".txt", ".json"))

        elif args.output_format == "json":
            json_str = reporter.generate_json(args.output)
            if not args.output:
                console.print(json_str)

        elif args.output_format == "html":
            html_str = reporter.generate_html(args.output)
            if not args.output:
                console.print(html_str)
            else:
                console.print(f"[green]HTML report written to:[/green] {args.output}")

        # ── 4. Summary ───────────────────────────────────────────────
        console.print(
            f"\n[bold green]Scan complete:[/bold green] "
            f"{result.total_findings} finding(s) across "
            f"{len(owasp_summary)} OWASP category(ies)"
        )

        if args.output:
            console.print(f"[dim]Report saved to:[/dim] {args.output}")

        # ── 5. Exit code ──────────────────────────────────────────────
        if args.fail_on_high and result.has_high_severity:
            high_count = result.severity_counts["HIGH"]
            console.print(
                f"\n[bold red]FAILED:[/bold red] {high_count} HIGH severity issue(s) found."
            )
            return 1

        return 0

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        return 2
    except RuntimeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        return 2
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {e}", style="red")
        return 2


# Allow running as: python -m securescanner
if __name__ == "__main__":
    sys.exit(main())
