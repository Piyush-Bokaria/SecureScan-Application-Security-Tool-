"""
scanner.py — Core Bandit scanning engine for SecureScan.

Invokes Bandit programmatically via subprocess to scan Python source code,
parses the JSON output into structured Finding objects, and returns a
ScanResult containing all findings and scan metadata.
"""

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class Finding:
    """Represents a single security finding from Bandit."""

    test_id: str
    test_name: str
    severity: str
    confidence: str
    cwe_id: int
    cwe_url: str
    filename: str
    line_number: int
    line_range: list
    code_snippet: str
    issue_text: str
    owasp_category: str = ""
    owasp_id: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        """Convert finding to a dictionary."""
        return asdict(self)


@dataclass
class ScanMetadata:
    """Metadata about the scan execution."""

    target: str
    timestamp: str
    duration_seconds: float
    python_version: str
    bandit_version: str = "unknown"
    total_files_scanned: int = 0
    total_files_skipped: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result including findings and metadata."""

    metadata: ScanMetadata
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def has_high_severity(self) -> bool:
        return any(f.severity == "HIGH" for f in self.findings)

    @property
    def severity_counts(self) -> dict:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    @property
    def confidence_counts(self) -> dict:
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            if f.confidence in counts:
                counts[f.confidence] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "metadata": self.metadata.to_dict(),
            "summary": {
                "total_findings": self.total_findings,
                "severity_counts": self.severity_counts,
                "confidence_counts": self.confidence_counts,
                **self.summary,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class SecurityScanner:
    """
    Core scanning engine that wraps Bandit for SAST analysis.

    Usage:
        scanner = SecurityScanner(severity_threshold="LOW", confidence_threshold="LOW")
        result = scanner.scan("/path/to/project")
    """

    SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

    def __init__(
        self,
        severity_threshold: str = "LOW",
        confidence_threshold: str = "LOW",
    ):
        self.severity_threshold = severity_threshold.upper()
        self.confidence_threshold = confidence_threshold.upper()

    def scan(self, target: str) -> ScanResult:
        """
        Scan a file or directory for security vulnerabilities using Bandit.

        Args:
            target: Path to a Python file or directory to scan.

        Returns:
            ScanResult containing all findings and scan metadata.

        Raises:
            FileNotFoundError: If the target path does not exist.
            RuntimeError: If Bandit fails to execute.
        """
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Run Bandit via subprocess to get JSON output
        bandit_output = self._run_bandit(str(target_path))
        duration = time.time() - start_time

        # Parse findings from Bandit JSON output
        findings = self._parse_findings(bandit_output)

        # Apply severity/confidence filters
        findings = self._filter_findings(findings)

        # Build metadata
        metrics = bandit_output.get("metrics", {})
        total_stats = metrics.get("_totals", {})

        metadata = ScanMetadata(
            target=str(target_path),
            timestamp=timestamp,
            duration_seconds=round(duration, 2),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            total_files_scanned=total_stats.get("loc", 0),
            total_files_skipped=0,
        )

        # Try to extract file count from metrics
        file_count = len([k for k in metrics.keys() if k != "_totals"])
        metadata.total_files_scanned = file_count

        return ScanResult(metadata=metadata, findings=findings)

    def _run_bandit(self, target: str) -> dict:
        """
        Execute Bandit and return the parsed JSON output.

        Args:
            target: Path to scan.

        Returns:
            Parsed JSON dict from Bandit output.
        """
        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            target,
            "-f",
            "json",
            "--exit-zero",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Bandit scan timed out after 300 seconds.")
        except FileNotFoundError:
            raise RuntimeError(
                "Bandit is not installed. Install it with: pip install bandit"
            )

        # Bandit outputs JSON to stdout even on findings (exit code 1)
        output = result.stdout.strip()
        if not output:
            # If no stdout, check stderr for errors
            if result.stderr:
                raise RuntimeError(f"Bandit error: {result.stderr.strip()}")
            return {"results": [], "metrics": {}}

        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Bandit JSON output: {e}")

    def _parse_findings(self, bandit_output: dict) -> list:
        """
        Parse Bandit JSON results into Finding objects.

        Args:
            bandit_output: Parsed Bandit JSON dict.

        Returns:
            List of Finding objects.
        """
        findings = []
        results = bandit_output.get("results", [])

        for result in results:
            # Extract CWE information
            issue_cwe = result.get("issue_cwe", {})
            cwe_id = issue_cwe.get("id", 0) if issue_cwe else 0
            cwe_url = issue_cwe.get("link", "") if issue_cwe else ""

            finding = Finding(
                test_id=result.get("test_id", ""),
                test_name=result.get("test_name", ""),
                severity=result.get("issue_severity", "UNDEFINED"),
                confidence=result.get("issue_confidence", "UNDEFINED"),
                cwe_id=cwe_id,
                cwe_url=cwe_url,
                filename=result.get("filename", ""),
                line_number=result.get("line_number", 0),
                line_range=result.get("line_range", []),
                code_snippet=result.get("code", "").strip(),
                issue_text=result.get("issue_text", ""),
            )
            findings.append(finding)

        return findings

    def _filter_findings(self, findings: list) -> list:
        """
        Filter findings based on severity and confidence thresholds.

        Args:
            findings: List of Finding objects.

        Returns:
            Filtered list of Finding objects.
        """
        sev_min = self.SEVERITY_LEVELS.get(self.severity_threshold, 1)
        conf_min = self.SEVERITY_LEVELS.get(self.confidence_threshold, 1)

        return [
            f
            for f in findings
            if self.SEVERITY_LEVELS.get(f.severity, 0) >= sev_min
            and self.SEVERITY_LEVELS.get(f.confidence, 0) >= conf_min
        ]
