"""
owasp_mapper.py — Maps Bandit CWE findings to OWASP Top 10:2021 categories.

Loads the static CWE → OWASP mapping from the bundled JSON file and enriches
each Finding with its OWASP category, ID, and remediation guidance.
"""

import json
from collections import Counter
from pathlib import Path
from typing import Optional


# Path to the bundled CWE → OWASP mapping data
_MAPPINGS_DIR = Path(__file__).parent / "mappings"
_CWE_OWASP_FILE = _MAPPINGS_DIR / "cwe_to_owasp.json"


# OWASP Top 10:2021 category metadata for summary/reporting
OWASP_TOP_10 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "description": "Failures in enforcing access restrictions, allowing unauthorized users to act outside their intended permissions.",
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography that lead to exposure of sensitive data or system compromise.",
    },
    "A03:2021": {
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized, leading to hostile data being used in commands or queries.",
    },
    "A04:2021": {
        "name": "Insecure Design",
        "description": "Missing or ineffective security controls and design patterns that fail to protect against known attack vectors.",
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "description": "Insecure default configurations, open cloud storage, misconfigured HTTP headers, or verbose error messages.",
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities, or failing to keep libraries, frameworks, and dependencies up to date.",
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "description": "Weaknesses in authentication mechanisms including hardcoded credentials, weak passwords, and missing MFA.",
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations, including insecure deserialization.",
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and alerting that prevents detection of active breaches.",
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Application fetches a remote resource without validating the user-supplied URL, enabling SSRF attacks.",
    },
}


class OWASPMapper:
    """
    Maps Bandit findings (via CWE IDs) to OWASP Top 10:2021 categories.

    Usage:
        mapper = OWASPMapper()
        enriched_findings = mapper.enrich_findings(findings)
        summary = mapper.get_owasp_summary(enriched_findings)
    """

    def __init__(self, mapping_file: Optional[str] = None):
        """
        Initialize the mapper with CWE → OWASP mapping data.

        Args:
            mapping_file: Optional path to a custom mapping JSON file.
                         Defaults to the bundled cwe_to_owasp.json.
        """
        mapping_path = Path(mapping_file) if mapping_file else _CWE_OWASP_FILE

        if not mapping_path.exists():
            raise FileNotFoundError(
                f"CWE-to-OWASP mapping file not found: {mapping_path}"
            )

        with open(mapping_path, "r", encoding="utf-8") as f:
            self._mapping = json.load(f)

    def map_cwe(self, cwe_id: int) -> dict:
        """
        Look up the OWASP Top 10 category for a given CWE ID.

        Args:
            cwe_id: The CWE identifier (integer).

        Returns:
            Dict with keys: owasp_id, owasp_category, remediation.
            Returns 'Uncategorized' values if no mapping exists.
        """
        key = str(cwe_id)
        if key in self._mapping:
            return self._mapping[key]

        return {
            "owasp_id": "N/A",
            "owasp_category": "Uncategorized",
            "remediation": (
                "This finding could not be mapped to an OWASP Top 10 category. "
                "Review the CWE description for specific remediation guidance."
            ),
        }

    def enrich_findings(self, findings: list) -> list:
        """
        Enrich a list of Finding objects with OWASP mapping data.

        Mutates each Finding in-place by setting owasp_category, owasp_id,
        and remediation fields.

        Args:
            findings: List of Finding objects from the scanner.

        Returns:
            The same list of Finding objects (mutated with OWASP data).
        """
        for finding in findings:
            mapping = self.map_cwe(finding.cwe_id)
            finding.owasp_id = mapping["owasp_id"]
            finding.owasp_category = mapping["owasp_category"]
            finding.remediation = mapping["remediation"]

        return findings

    def get_owasp_summary(self, findings: list) -> dict:
        """
        Generate a summary of findings grouped by OWASP Top 10 category.

        Args:
            findings: List of enriched Finding objects.

        Returns:
            Dict mapping OWASP IDs to summary dicts with:
              - name: OWASP category name
              - description: Category description
              - count: Number of findings
              - severity_breakdown: {HIGH: n, MEDIUM: n, LOW: n}
              - findings: List of finding indices
        """
        summary = {}

        for idx, finding in enumerate(findings):
            owasp_id = finding.owasp_id

            if owasp_id not in summary:
                # Get category metadata
                category_info = OWASP_TOP_10.get(
                    owasp_id,
                    {"name": finding.owasp_category, "description": ""},
                )
                summary[owasp_id] = {
                    "name": category_info["name"],
                    "description": category_info["description"],
                    "count": 0,
                    "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    "finding_indices": [],
                }

            summary[owasp_id]["count"] += 1
            if finding.severity in summary[owasp_id]["severity_breakdown"]:
                summary[owasp_id]["severity_breakdown"][finding.severity] += 1
            summary[owasp_id]["finding_indices"].append(idx)

        # Sort by count descending
        sorted_summary = dict(
            sorted(summary.items(), key=lambda x: x[1]["count"], reverse=True)
        )

        return sorted_summary
