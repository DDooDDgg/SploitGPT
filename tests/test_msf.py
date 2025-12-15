"""
Tests for Metasploit RPC integration
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sploitgpt.msf import MetasploitRPC, MSFModule, MSFSession


class TestMetasploitRPC:
    """Tests for MSF RPC client."""
    
    @pytest.fixture
    def msf_client(self):
        """Create an MSF client."""
        return MetasploitRPC(
            host="127.0.0.1",
            port=55553,
            username="msf",
            password="testpass",
            ssl=False,
        )
    
    def test_client_init(self, msf_client):
        """Test client initialization."""
        assert msf_client.host == "127.0.0.1"
        assert msf_client.port == 55553
        assert msf_client.username == "msf"
        assert msf_client.token is None
    
    def test_base_url(self, msf_client):
        """Test base URL generation."""
        assert "127.0.0.1:55553" in msf_client.base_url
        assert "http://" in msf_client.base_url
        
        # With SSL
        msf_ssl = MetasploitRPC(ssl=True)
        assert "https://" in msf_ssl.base_url
    
    @pytest.mark.asyncio
    async def test_connect_success(self, msf_client):
        """Test successful connection."""
        with patch.object(msf_client, '_call', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"result": "success", "token": "abc123"}
            
            result = await msf_client.connect()
            
            assert result is True
            assert msf_client.token == "abc123"
    
    @pytest.mark.asyncio
    async def test_connect_failure(self, msf_client):
        """Test failed connection."""
        with patch.object(msf_client, '_call', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {"result": "failure", "error": "bad password"}
            
            result = await msf_client.connect()
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_search_modules(self, msf_client):
        """Test module search."""
        msf_client.token = "test-token"
        msf_client._client = MagicMock()
        
        mock_results = [
            {
                "type": "exploit",
                "fullname": "exploit/unix/ftp/vsftpd_234_backdoor",
                "rank": "excellent",
                "name": "VSFTPD 2.3.4 Backdoor",
                "references": [],
            }
        ]
        
        with patch.object(msf_client, '_call', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = mock_results
            
            modules = await msf_client.search_modules("vsftpd")
            
            assert len(modules) == 1
            assert modules[0].name == "exploit/unix/ftp/vsftpd_234_backdoor"
            assert modules[0].rank == "excellent"


class TestMSFModule:
    """Tests for MSF module dataclass."""
    
    def test_module_creation(self):
        """Test creating a module."""
        mod = MSFModule(
            type="exploit",
            name="exploit/windows/smb/ms17_010_eternalblue",
            rank="great",
            description="MS17-010 EternalBlue SMB Remote Code Execution",
            references=["CVE-2017-0144"],
        )
        
        assert mod.type == "exploit"
        assert "eternalblue" in mod.name
        assert mod.short_name == "ms17_010_eternalblue"
    
    def test_short_name(self):
        """Test short name extraction."""
        mod = MSFModule(
            type="auxiliary",
            name="auxiliary/scanner/smb/smb_ms17_010",
            rank="normal",
            description="MS17-010 Scanner",
            references=[],
        )
        
        assert mod.short_name == "smb_ms17_010"


class TestMSFSession:
    """Tests for MSF session dataclass."""
    
    def test_session_creation(self):
        """Test creating a session."""
        session = MSFSession(
            id=1,
            type="meterpreter",
            tunnel_local="192.168.1.10:4444",
            tunnel_peer="10.0.0.5:54321",
            via_exploit="exploit/unix/ftp/vsftpd_234_backdoor",
            via_payload="cmd/unix/interact",
            info="root @ target",
            workspace="default",
        )
        
        assert session.id == 1
        assert session.type == "meterpreter"
        assert "10.0.0.5" in session.tunnel_peer
