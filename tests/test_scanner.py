"""
test_scanner.py — Unit tests for the SecurityScanner module.
"""

import os
import pytest
from pathlib import Path

from securescanner.scanner import SecurityScanner, ScanResult, Finding


# Path to the sample vulnerable code
SAMPLE_DIR = Path(__file__).parent / "sample_vulnerable"
SAMPLE_FILE = SAMPLE_DIR / "vulnerable_app.py"


class TestSecurityScanner:
    """Tests for SecurityScanner."""

    def test_scan_vulnerable_file_finds_issues(self):
        """Scanning the vulnerable sample should return multiple findings."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_FILE))

        assert isinstance(result, ScanResult)
        assert result.total_findings > 0, "Expected findings in vulnerable code"
        assert len(result.findings) > 0

    def test_scan_returns_finding_objects(self):
        """Each finding should be a properly structured Finding object."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_FILE))

        for finding in result.findings:
            assert isinstance(finding, Finding)
            assert finding.test_id, "Finding must have a test_id"
            assert finding.severity in ("LOW", "MEDIUM", "HIGH", "UNDEFINED")
            assert finding.confidence in ("LOW", "MEDIUM", "HIGH", "UNDEFINED")
            assert finding.filename, "Finding must have a filename"
            assert finding.line_number > 0, "Finding must have a line number"
            assert finding.issue_text, "Finding must have issue_text"

    def test_scan_returns_cwe_data(self):
        """Findings should include CWE identifiers."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_FILE))

        cwe_findings = [f for f in result.findings if f.cwe_id > 0]
        assert len(cwe_findings) > 0, "Expected at least some findings with CWE IDs"

    def test_severity_filter_high(self):
        """Filtering by HIGH severity should return fewer findings."""
        scanner_all = SecurityScanner(severity_threshold="LOW")
        scanner_high = SecurityScanner(severity_threshold="HIGH")

        result_all = scanner_all.scan(str(SAMPLE_FILE))
        result_high = scanner_high.scan(str(SAMPLE_FILE))

        assert result_high.total_findings <= result_all.total_findings

        for finding in result_high.findings:
            assert finding.severity == "HIGH"

    def test_confidence_filter_high(self):
        """Filtering by HIGH confidence should return fewer findings."""
        scanner_all = SecurityScanner(confidence_threshold="LOW")
        scanner_high = SecurityScanner(confidence_threshold="HIGH")

        result_all = scanner_all.scan(str(SAMPLE_FILE))
        result_high = scanner_high.scan(str(SAMPLE_FILE))

        assert result_high.total_findings <= result_all.total_findings

        for finding in result_high.findings:
            assert finding.confidence == "HIGH"

    def test_scan_nonexistent_path_raises_error(self):
        """Scanning a path that doesn't exist should raise FileNotFoundError."""
        scanner = SecurityScanner()
        with pytest.raises(FileNotFoundError):
            scanner.scan("/nonexistent/path/does/not/exist.py")

    def test_scan_directory(self):
        """Scanning a directory should work like scanning individual files."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_DIR))

        assert isinstance(result, ScanResult)
        assert result.total_findings > 0

    def test_scan_metadata(self):
        """Scan result should contain valid metadata."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_FILE))

        assert result.metadata.target, "Metadata must have target path"
        assert result.metadata.timestamp, "Metadata must have timestamp"
        assert result.metadata.duration_seconds >= 0
        assert result.metadata.python_version, "Metadata must have Python version"

    def test_severity_counts(self):
        """Severity counts should sum to total findings."""
        scanner = SecurityScanner()
        result = scanner.scan(str(SAMPLE_FILE))

        counts = result.severity_counts
        total = counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
        assert total == result.total_findings

    def test_finding_to_dict(self):
        """Finding.to_dict() should return a complete dictionary."""
        finding = Finding(
            test_id="B101",
            test_name="assert_used",
            severity="LOW",
            confidence="HIGH",
            cwe_id=703,
            cwe_url="https://cwe.mitre.org/data/definitions/703.html",
            filename="test.py",
            line_number=10,
            line_range=[10],
            code_snippet="assert x > 0",
            issue_text="Use of assert detected.",
        )

        d = finding.to_dict()
        assert d["test_id"] == "B101"
        assert d["severity"] == "LOW"
        assert d["cwe_id"] == 703
