"""
test_owasp_mapper.py — Unit tests for the OWASPMapper module.
"""

import pytest

from securescanner.owasp_mapper import OWASPMapper, OWASP_TOP_10
from securescanner.scanner import Finding


class TestOWASPMapper:
    """Tests for OWASPMapper."""

    @pytest.fixture
    def mapper(self):
        """Create a mapper instance."""
        return OWASPMapper()

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        return [
            Finding(
                test_id="B602",
                test_name="subprocess_popen_with_shell_equals_true",
                severity="HIGH",
                confidence="HIGH",
                cwe_id=78,
                cwe_url="https://cwe.mitre.org/data/definitions/78.html",
                filename="app.py",
                line_number=10,
                line_range=[10],
                code_snippet="subprocess.call(cmd, shell=True)",
                issue_text="subprocess call with shell=True",
            ),
            Finding(
                test_id="B303",
                test_name="md5",
                severity="MEDIUM",
                confidence="HIGH",
                cwe_id=328,
                cwe_url="https://cwe.mitre.org/data/definitions/328.html",
                filename="crypto.py",
                line_number=20,
                line_range=[20],
                code_snippet="hashlib.md5(data)",
                issue_text="Use of insecure MD5 hash function.",
            ),
            Finding(
                test_id="B105",
                test_name="hardcoded_password_string",
                severity="LOW",
                confidence="MEDIUM",
                cwe_id=259,
                cwe_url="https://cwe.mitre.org/data/definitions/259.html",
                filename="config.py",
                line_number=5,
                line_range=[5],
                code_snippet='password = "secret"',
                issue_text="Possible hardcoded password.",
            ),
        ]

    def test_map_known_cwe_injection(self, mapper):
        """CWE-78 should map to A03:2021 Injection."""
        result = mapper.map_cwe(78)
        assert result["owasp_id"] == "A03:2021"
        assert result["owasp_category"] == "Injection"
        assert result["remediation"], "Remediation should not be empty"

    def test_map_known_cwe_crypto(self, mapper):
        """CWE-328 should map to A02:2021 Cryptographic Failures."""
        result = mapper.map_cwe(328)
        assert result["owasp_id"] == "A02:2021"
        assert result["owasp_category"] == "Cryptographic Failures"

    def test_map_known_cwe_auth(self, mapper):
        """CWE-259 should map to A07:2021 Identification and Authentication Failures."""
        result = mapper.map_cwe(259)
        assert result["owasp_id"] == "A07:2021"
        assert "Authentication" in result["owasp_category"]

    def test_map_known_cwe_deserialization(self, mapper):
        """CWE-502 should map to A08:2021 Software and Data Integrity Failures."""
        result = mapper.map_cwe(502)
        assert result["owasp_id"] == "A08:2021"

    def test_map_known_cwe_misconfiguration(self, mapper):
        """CWE-703 should map to A05:2021 Security Misconfiguration."""
        result = mapper.map_cwe(703)
        assert result["owasp_id"] == "A05:2021"

    def test_map_unknown_cwe_returns_uncategorized(self, mapper):
        """An unmapped CWE should return Uncategorized gracefully."""
        result = mapper.map_cwe(99999)
        assert result["owasp_id"] == "N/A"
        assert result["owasp_category"] == "Uncategorized"
        assert result["remediation"], "Should have fallback remediation text"

    def test_enrich_findings(self, mapper, sample_findings):
        """enrich_findings should populate OWASP fields on all findings."""
        enriched = mapper.enrich_findings(sample_findings)

        assert len(enriched) == 3

        # Injection finding
        assert enriched[0].owasp_id == "A03:2021"
        assert enriched[0].owasp_category == "Injection"
        assert enriched[0].remediation, "Remediation should be populated"

        # Crypto finding
        assert enriched[1].owasp_id == "A02:2021"
        assert enriched[1].owasp_category == "Cryptographic Failures"

        # Auth finding
        assert enriched[2].owasp_id == "A07:2021"

    def test_get_owasp_summary(self, mapper, sample_findings):
        """OWASP summary should correctly count and group findings."""
        mapper.enrich_findings(sample_findings)
        summary = mapper.get_owasp_summary(sample_findings)

        # Should have 3 categories (Injection, Crypto, Auth)
        assert len(summary) == 3

        # Check Injection category
        assert "A03:2021" in summary
        assert summary["A03:2021"]["count"] == 1
        assert summary["A03:2021"]["severity_breakdown"]["HIGH"] == 1

        # Check Crypto category
        assert "A02:2021" in summary
        assert summary["A02:2021"]["count"] == 1
        assert summary["A02:2021"]["severity_breakdown"]["MEDIUM"] == 1

    def test_owasp_top_10_metadata_complete(self):
        """OWASP_TOP_10 dict should have all 10 categories."""
        assert len(OWASP_TOP_10) == 10

        expected_ids = [f"A{str(i).zfill(2)}:2021" for i in range(1, 11)]
        for owasp_id in expected_ids:
            assert owasp_id in OWASP_TOP_10, f"Missing {owasp_id}"
            assert "name" in OWASP_TOP_10[owasp_id]
            assert "description" in OWASP_TOP_10[owasp_id]

    def test_enrich_findings_mutates_in_place(self, mapper, sample_findings):
        """enrich_findings should modify findings in place and return the same list."""
        result = mapper.enrich_findings(sample_findings)
        assert result is sample_findings  # Same reference
        assert sample_findings[0].owasp_id == "A03:2021"
