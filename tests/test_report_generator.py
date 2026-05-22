"""
test_report_generator.py — Unit tests for the ReportGenerator module.
"""

import json
import os
import tempfile
import pytest
from pathlib import Path

from securescanner.scanner import SecurityScanner, ScanResult, ScanMetadata, Finding
from securescanner.owasp_mapper import OWASPMapper
from securescanner.report_generator import ReportGenerator


# Path to sample vulnerable code
SAMPLE_DIR = Path(__file__).parent / "sample_vulnerable"
SAMPLE_FILE = SAMPLE_DIR / "vulnerable_app.py"


@pytest.fixture
def scan_with_findings():
    """Run a real scan against the vulnerable sample and enrich with OWASP data."""
    scanner = SecurityScanner()
    result = scanner.scan(str(SAMPLE_FILE))

    mapper = OWASPMapper()
    mapper.enrich_findings(result.findings)
    owasp_summary = mapper.get_owasp_summary(result.findings)

    return result, owasp_summary


@pytest.fixture
def empty_scan():
    """Create a scan result with no findings."""
    metadata = ScanMetadata(
        target="/empty/project",
        timestamp="2025-01-01T00:00:00Z",
        duration_seconds=0.1,
        python_version="3.11.0",
    )
    result = ScanResult(metadata=metadata, findings=[], summary={})
    return result, {}


class TestReportGeneratorJSON:
    """Tests for JSON report generation."""

    def test_json_output_is_valid_json(self, scan_with_findings):
        """JSON report should be valid, parseable JSON."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        json_str = generator.generate_json()
        parsed = json.loads(json_str)

        assert "report" in parsed
        assert "scan" in parsed
        assert "owasp_summary" in parsed

    def test_json_contains_findings(self, scan_with_findings):
        """JSON report should contain the scan findings."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        parsed = json.loads(generator.generate_json())
        findings = parsed["scan"]["findings"]

        assert len(findings) > 0
        assert findings[0]["test_id"], "Finding must have test_id"
        assert findings[0]["owasp_id"], "Finding must have owasp_id"

    def test_json_contains_summary(self, scan_with_findings):
        """JSON report should contain summary with severity counts."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        parsed = json.loads(generator.generate_json())
        summary = parsed["scan"]["summary"]

        assert "total_findings" in summary
        assert "severity_counts" in summary
        assert summary["total_findings"] > 0

    def test_json_write_to_file(self, scan_with_findings, tmp_path):
        """JSON report should be writable to a file."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        output_path = str(tmp_path / "report.json")
        generator.generate_json(output_path)

        assert os.path.exists(output_path)
        with open(output_path, "r") as f:
            parsed = json.load(f)
        assert parsed["report"]["tool"] == "SecureScan"

    def test_json_empty_scan(self, empty_scan):
        """JSON report for empty scan should have zero findings."""
        result, owasp_summary = empty_scan
        generator = ReportGenerator(result, owasp_summary)

        parsed = json.loads(generator.generate_json())
        assert parsed["scan"]["summary"]["total_findings"] == 0
        assert len(parsed["scan"]["findings"]) == 0


class TestReportGeneratorHTML:
    """Tests for HTML report generation."""

    def test_html_output_is_valid_html(self, scan_with_findings):
        """HTML report should contain proper HTML structure."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        html = generator.generate_html()

        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "SecureScan" in html

    def test_html_contains_findings(self, scan_with_findings):
        """HTML report should include finding details."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        html = generator.generate_html()

        # Should contain at least one test ID
        assert any(f.test_id in html for f in result.findings)
        # Should contain OWASP references
        assert "OWASP" in html

    def test_html_contains_owasp_breakdown(self, scan_with_findings):
        """HTML report should include OWASP Top 10 breakdown table."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        html = generator.generate_html()

        for owasp_id in owasp_summary.keys():
            assert owasp_id in html, f"OWASP ID {owasp_id} missing from HTML"

    def test_html_write_to_file(self, scan_with_findings, tmp_path):
        """HTML report should be writable to a file."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        output_path = str(tmp_path / "report.html")
        generator.generate_html(output_path)

        assert os.path.exists(output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert "SecureScan" in content

    def test_html_empty_scan(self, empty_scan):
        """HTML report for empty scan should show 'no issues' message."""
        result, owasp_summary = empty_scan
        generator = ReportGenerator(result, owasp_summary)

        html = generator.generate_html()
        assert "No security issues found" in html


class TestReportGeneratorConsole:
    """Tests for console report generation."""

    def test_console_report_runs_without_error(self, scan_with_findings):
        """Console report should execute without raising exceptions."""
        result, owasp_summary = scan_with_findings
        generator = ReportGenerator(result, owasp_summary)

        # Should not raise
        generator.generate_console()

    def test_console_empty_scan_runs(self, empty_scan):
        """Console report for empty scan should execute without error."""
        result, owasp_summary = empty_scan
        generator = ReportGenerator(result, owasp_summary)

        generator.generate_console()
