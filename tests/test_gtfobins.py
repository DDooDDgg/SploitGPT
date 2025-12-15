"""
Tests for SploitGPT knowledge modules
"""

from sploitgpt.knowledge.gtfobins import (
    GTFOBINS_DB,
    find_reverse_shell,
    find_sudo_escalation,
    find_suid_escalation,
    get_privesc_options,
)


class TestGTFOBins:
    """Tests for GTFOBins integration."""
    
    def test_gtfobins_db_has_entries(self):
        """Test that GTFOBins database is populated."""
        assert len(GTFOBINS_DB) > 20
        assert "python" in GTFOBINS_DB
        assert "bash" in GTFOBINS_DB
        assert "vim" in GTFOBINS_DB
    
    def test_find_suid_escalation(self):
        """Test finding SUID escalation techniques."""
        # Known SUID binaries
        assert find_suid_escalation("python") is not None
        assert find_suid_escalation("/usr/bin/python") is not None
        assert find_suid_escalation("vim") is not None
        
        # Unknown binaries
        assert find_suid_escalation("unknownbinary") is None
    
    def test_find_sudo_escalation(self):
        """Test finding sudo escalation techniques."""
        assert find_sudo_escalation("vim") is not None
        assert find_sudo_escalation("less") is not None
        assert find_sudo_escalation("docker") is not None
    
    def test_find_reverse_shell(self):
        """Test generating reverse shell commands."""
        shell = find_reverse_shell("python", "10.0.0.1", 4444)
        assert shell is not None
        assert "10.0.0.1" in shell
        assert "4444" in shell
        
        shell = find_reverse_shell("nc", "attacker.com", 9001)
        assert shell is not None
        assert "attacker.com" in shell
        assert "9001" in shell
    
    def test_get_privesc_options(self):
        """Test getting privesc options for multiple binaries."""
        binaries = ["/usr/bin/python", "/usr/bin/vim", "/usr/bin/less", "/usr/bin/cat"]
        options = get_privesc_options(binaries, "suid")
        
        # Should find options for known binaries
        assert len(options) >= 2
        
        # Each option should have required fields
        for opt in options:
            assert "binary" in opt
            assert "technique" in opt
            assert "command" in opt
    
    def test_python_entry_complete(self):
        """Test that Python entry has all techniques."""
        entry = GTFOBINS_DB.get("python")
        assert entry is not None
        assert entry.suid is not None
        assert entry.sudo is not None
        assert entry.shell is not None
        assert entry.reverse_shell is not None
