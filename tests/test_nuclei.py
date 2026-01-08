"""
Tests for nuclei vulnerability scanner integration.

Tests the nuclei_scan and nuclei_templates tools.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sploitgpt.tools.nuclei import (
    SEVERITY_LEVELS,
    TEMPLATE_TAGS,
    _format_findings_text,
    _parse_nuclei_jsonl,
    _sanitize_for_filename,
    nuclei_scan,
    nuclei_templates,
)


class TestSanitizeForFilename:
    """Tests for filename sanitization."""

    def test_sanitize_simple_hostname(self):
        """Test sanitizing a simple hostname."""
        result = _sanitize_for_filename("example.com")
        assert result == "example.com"

    def test_sanitize_url(self):
        """Test sanitizing a URL (after protocol removal)."""
        result = _sanitize_for_filename("example.com/path?query=1")
        assert result == "example.com_path_query_1"

    def test_sanitize_ip_address(self):
        """Test sanitizing an IP address."""
        result = _sanitize_for_filename("10.0.0.1")
        assert result == "10.0.0.1"

    def test_sanitize_ip_with_port(self):
        """Test sanitizing an IP with port."""
        result = _sanitize_for_filename("10.0.0.1:8080")
        assert result == "10.0.0.1:8080"

    def test_sanitize_empty_string(self):
        """Test sanitizing empty string returns 'target'."""
        result = _sanitize_for_filename("")
        assert result == "target"

    def test_sanitize_special_chars_only(self):
        """Test sanitizing string with only special chars."""
        result = _sanitize_for_filename("///")
        assert result == "target"


class TestParseNucleiJsonl:
    """Tests for nuclei JSONL output parsing."""

    def test_parse_valid_jsonl(self):
        """Test parsing valid JSONL output."""
        output = """{"template-id":"test-1","info":{"name":"Test Finding"}}
{"template-id":"test-2","info":{"name":"Another Finding"}}"""
        findings = _parse_nuclei_jsonl(output)
        assert len(findings) == 2
        assert findings[0]["template-id"] == "test-1"
        assert findings[1]["template-id"] == "test-2"

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        findings = _parse_nuclei_jsonl("")
        assert findings == []

    def test_parse_mixed_output(self):
        """Test parsing output with non-JSON lines."""
        output = """Some status line
{"template-id":"test-1","info":{"name":"Test"}}
Another status
{"template-id":"test-2","info":{"name":"Test2"}}"""
        findings = _parse_nuclei_jsonl(output)
        assert len(findings) == 2

    def test_parse_malformed_json(self):
        """Test that malformed JSON is skipped."""
        output = """{"template-id":"test-1"}
{invalid json}
{"template-id":"test-2"}"""
        findings = _parse_nuclei_jsonl(output)
        assert len(findings) == 2


class TestFormatFindingsText:
    """Tests for formatting findings as text."""

    def test_format_no_findings(self):
        """Test formatting empty findings."""
        result = _format_findings_text([])
        assert result == "No vulnerabilities found."

    def test_format_single_finding(self):
        """Test formatting a single finding."""
        findings = [
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Log4j RCE",
                    "severity": "critical",
                    "reference": ["CVE-2021-44228"],
                },
                "matched-at": "https://example.com/api",
            }
        ]
        result = _format_findings_text(findings)
        assert "Found 1 findings" in result
        assert "CRITICAL" in result
        assert "Log4j RCE" in result
        assert "CVE-2021-44228" in result

    def test_format_multiple_severities(self):
        """Test formatting findings with different severities."""
        findings = [
            {"info": {"name": "Info Finding", "severity": "info"}},
            {"info": {"name": "Low Finding", "severity": "low"}},
            {"info": {"name": "Medium Finding", "severity": "medium"}},
            {"info": {"name": "High Finding", "severity": "high"}},
            {"info": {"name": "Critical Finding", "severity": "critical"}},
        ]
        result = _format_findings_text(findings)
        assert "Found 5 findings" in result
        # Critical/high should appear first due to reversed order
        assert result.index("CRITICAL") < result.index("INFO")

    def test_format_truncates_large_lists(self):
        """Test that large lists are truncated per severity."""
        findings = [{"info": {"name": f"Finding {i}", "severity": "high"}} for i in range(15)]
        result = _format_findings_text(findings)
        assert "and 5 more high findings" in result


class TestNucleiScan:
    """Tests for nuclei_scan tool."""

    @pytest.mark.asyncio
    async def test_scan_empty_target(self):
        """Test scan with empty target."""
        result = await nuclei_scan(target="")
        assert "Error: target is required" in result

    @pytest.mark.asyncio
    async def test_scan_invalid_target(self):
        """Test scan with invalid target format."""
        result = await nuclei_scan(target="   ")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_scan_nuclei_not_installed(self, tmp_path, monkeypatch):
        """Test scan when nuclei is not installed."""
        mock_settings = MagicMock()
        mock_settings.loot_dir = tmp_path / "loot"
        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        # Mock subprocess to raise FileNotFoundError
        async def mock_create_subprocess(*args, **kwargs):
            raise FileNotFoundError("nuclei not found")

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        result = await nuclei_scan(target="https://example.com")
        assert "Error: nuclei is not installed" in result
        assert "go install" in result

    @pytest.mark.asyncio
    async def test_scan_success(self, tmp_path, monkeypatch):
        """Test successful scan with findings."""
        mock_settings = MagicMock()
        mock_settings.loot_dir = tmp_path / "loot"
        mock_settings.loot_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        # Mock subprocess
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"Scan complete", b""))

        async def mock_create_subprocess(*args, **kwargs):
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        # Create fake output file
        output_file = mock_settings.loot_dir / "nuclei_example.com.jsonl"
        output_file.write_text(
            '{"template-id":"test","info":{"name":"Test","severity":"medium"}}\n'
        )

        result = await nuclei_scan(target="https://example.com")
        assert "Found 1 findings" in result
        assert "MEDIUM" in result

    @pytest.mark.asyncio
    async def test_scan_with_tags(self, tmp_path, monkeypatch):
        """Test scan with tag filters."""
        mock_settings = MagicMock()
        mock_settings.loot_dir = tmp_path / "loot"
        mock_settings.loot_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        captured_args = []

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_create_subprocess(*args, **kwargs):
            captured_args.extend(args)
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        await nuclei_scan(target="https://example.com", tags="cve,exposure")

        # Check that tags were passed
        assert "-tags" in captured_args
        assert "cve,exposure" in captured_args

    @pytest.mark.asyncio
    async def test_scan_with_severity_filter(self, tmp_path, monkeypatch):
        """Test scan with severity filter."""
        mock_settings = MagicMock()
        mock_settings.loot_dir = tmp_path / "loot"
        mock_settings.loot_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        captured_args = []

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_create_subprocess(*args, **kwargs):
            captured_args.extend(args)
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        await nuclei_scan(target="https://example.com", severity="high,critical")

        assert "-severity" in captured_args
        assert "high,critical" in captured_args

    @pytest.mark.asyncio
    async def test_scan_json_output(self, tmp_path, monkeypatch):
        """Test scan with JSON output format."""
        mock_settings = MagicMock()
        mock_settings.loot_dir = tmp_path / "loot"
        mock_settings.loot_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_create_subprocess(*args, **kwargs):
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        # Create fake output file
        output_file = mock_settings.loot_dir / "nuclei_example.com.jsonl"
        output_file.write_text('{"template-id":"test","info":{"name":"Test","severity":"high"}}\n')

        result = await nuclei_scan(target="https://example.com", output_format="json")

        parsed = json.loads(result)
        assert parsed["target"] == "https://example.com"
        assert parsed["findings_count"] == 1


class TestNucleiTemplates:
    """Tests for nuclei_templates tool."""

    @pytest.mark.asyncio
    async def test_templates_nuclei_not_installed(self, monkeypatch):
        """Test template listing when nuclei is not installed."""

        async def mock_create_subprocess(*args, **kwargs):
            raise FileNotFoundError("nuclei not found")

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        result = await nuclei_templates()
        assert "Error: nuclei is not installed" in result

    @pytest.mark.asyncio
    async def test_templates_list_all(self, monkeypatch):
        """Test listing all templates."""
        template_output = """cves/2021/CVE-2021-44228.yaml
cves/2022/CVE-2022-1388.yaml
exposures/configs/git-config.yaml
panels/apache-airflow-panel.yaml"""

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(template_output.encode(), b""))

        async def mock_create_subprocess(*args, **kwargs):
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        result = await nuclei_templates()
        assert "Found 4 templates" in result
        assert "CVE-2021-44228" in result

    @pytest.mark.asyncio
    async def test_templates_with_search(self, monkeypatch):
        """Test filtering templates by search term."""
        template_output = """cves/2021/CVE-2021-44228.yaml
cves/2022/CVE-2022-1388.yaml
exposures/configs/git-config.yaml"""

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(template_output.encode(), b""))

        async def mock_create_subprocess(*args, **kwargs):
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        result = await nuclei_templates(search="CVE-2021")
        assert "CVE-2021-44228" in result
        assert "CVE-2022" not in result

    @pytest.mark.asyncio
    async def test_templates_with_tag_filter(self, monkeypatch):
        """Test filtering templates by tag."""
        captured_args = []

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        async def mock_create_subprocess(*args, **kwargs):
            captured_args.extend(args)
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        await nuclei_templates(tag="cve")

        assert "-tags" in captured_args
        assert "cve" in captured_args

    @pytest.mark.asyncio
    async def test_templates_with_limit(self, monkeypatch):
        """Test limiting template results."""
        # Generate 30 template lines
        template_lines = [f"template-{i}.yaml" for i in range(30)]
        template_output = "\n".join(template_lines)

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(template_output.encode(), b""))

        async def mock_create_subprocess(*args, **kwargs):
            return mock_proc

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_create_subprocess)

        result = await nuclei_templates(limit=10)
        assert "Found 30 templates" in result
        assert "and 20 more" in result


class TestConstants:
    """Tests for module constants."""

    def test_severity_levels(self):
        """Test that all severity levels are defined."""
        expected = ["info", "low", "medium", "high", "critical"]
        assert SEVERITY_LEVELS == expected

    def test_template_tags(self):
        """Test that common template tags are defined."""
        assert "cve" in TEMPLATE_TAGS
        assert "exposure" in TEMPLATE_TAGS
        assert "panel" in TEMPLATE_TAGS
        assert "misconfig" in TEMPLATE_TAGS
        assert "xss" in TEMPLATE_TAGS
        assert "sqli" in TEMPLATE_TAGS
        assert "rce" in TEMPLATE_TAGS
