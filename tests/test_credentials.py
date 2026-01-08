"""
Tests for credential management functionality.

Tests the secure credential storage and retrieval using keyring.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.core.credentials import (
    KEYRING_SERVICE,
    CredentialInfo,
    CredentialType,
    delete_credential,
    get_credential,
    get_credential_status,
    get_msf_password,
    get_shodan_api_key,
    is_keyring_available,
    list_credentials,
    set_msf_password,
    set_shodan_api_key,
    store_credential,
)


class TestCredentialType:
    """Tests for CredentialType enum."""

    def test_credential_types_exist(self):
        """Test that all expected credential types exist."""
        assert CredentialType.MSF_PASSWORD.value == "msf_password"
        assert CredentialType.SHODAN_API_KEY.value == "shodan_api_key"
        assert CredentialType.OPENAI_API_KEY.value == "openai_api_key"
        assert CredentialType.ANTHROPIC_API_KEY.value == "anthropic_api_key"
        assert CredentialType.CUSTOM.value == "custom"

    def test_credential_type_is_string(self):
        """Test that CredentialType values are strings."""
        assert isinstance(CredentialType.MSF_PASSWORD.value, str)
        assert isinstance(CredentialType.SHODAN_API_KEY.value, str)


class TestCredentialInfo:
    """Tests for CredentialInfo dataclass."""

    def test_credential_info_creation(self):
        """Test creating a CredentialInfo object."""
        info = CredentialInfo(
            name="Test Credential",
            credential_type=CredentialType.MSF_PASSWORD,
            is_set=True,
            source="keyring",
            env_var="TEST_VAR",
        )
        assert info.name == "Test Credential"
        assert info.credential_type == CredentialType.MSF_PASSWORD
        assert info.is_set is True
        assert info.source == "keyring"
        assert info.env_var == "TEST_VAR"

    def test_credential_info_default_env_var(self):
        """Test CredentialInfo with default env_var."""
        info = CredentialInfo(
            name="Test",
            credential_type=CredentialType.CUSTOM,
            is_set=False,
            source="none",
        )
        assert info.env_var is None


class TestStoreCredential:
    """Tests for store_credential function."""

    def test_store_credential_with_keyring(self):
        """Test storing credential when keyring is available."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = store_credential("test_cred", "secret_value", CredentialType.CUSTOM)

            assert result is True
            mock_keyring.set_password.assert_called_once_with(
                KEYRING_SERVICE, "test_cred", "secret_value"
            )

    def test_store_credential_with_type(self):
        """Test storing credential with specific type creates correct key."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = store_credential("default", "password123", CredentialType.MSF_PASSWORD)

            assert result is True
            mock_keyring.set_password.assert_called_once_with(
                KEYRING_SERVICE, "msf_password:default", "password123"
            )

    def test_store_credential_no_keyring(self):
        """Test storing credential when keyring is unavailable."""
        with patch("sploitgpt.core.credentials._get_keyring", return_value=None):
            result = store_credential("test_cred", "secret_value")

            assert result is False

    def test_store_credential_keyring_error(self):
        """Test storing credential when keyring raises an error."""
        mock_keyring = MagicMock()
        mock_keyring.set_password.side_effect = Exception("Keyring error")
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = store_credential("test_cred", "secret_value")

            assert result is False


class TestGetCredential:
    """Tests for get_credential function."""

    def test_get_credential_from_keyring(self):
        """Test retrieving credential from keyring."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "stored_secret"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = get_credential("test_cred", CredentialType.CUSTOM)

            assert result == "stored_secret"

    def test_get_credential_with_type(self):
        """Test retrieving credential with specific type uses correct key."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "msf_secret"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = get_credential("default", CredentialType.MSF_PASSWORD)

            assert result == "msf_secret"
            mock_keyring.get_password.assert_called_once_with(
                KEYRING_SERVICE, "msf_password:default"
            )

    def test_get_credential_fallback_to_env(self):
        """Test falling back to environment variable."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {"TEST_VAR": "env_value"}):
                result = get_credential("test_cred", CredentialType.CUSTOM, "TEST_VAR")

                assert result == "env_value"

    def test_get_credential_no_keyring_with_env(self):
        """Test getting credential when keyring unavailable but env set."""
        with patch("sploitgpt.core.credentials._get_keyring", return_value=None):
            with patch.dict(os.environ, {"TEST_VAR": "env_value"}):
                result = get_credential("test_cred", CredentialType.CUSTOM, "TEST_VAR")

                assert result == "env_value"

    def test_get_credential_not_found(self):
        """Test getting credential that doesn't exist anywhere."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {}, clear=True):
                result = get_credential("nonexistent", CredentialType.CUSTOM, "NONEXISTENT_VAR")

                assert result is None

    def test_get_credential_keyring_error_fallback(self):
        """Test fallback to env when keyring lookup fails."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.side_effect = Exception("Keyring error")
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {"TEST_VAR": "env_fallback"}):
                result = get_credential("test_cred", CredentialType.CUSTOM, "TEST_VAR")

                assert result == "env_fallback"


class TestDeleteCredential:
    """Tests for delete_credential function."""

    def test_delete_credential_success(self):
        """Test deleting credential from keyring."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = delete_credential("test_cred", CredentialType.CUSTOM)

            assert result is True
            mock_keyring.delete_password.assert_called_once_with(KEYRING_SERVICE, "test_cred")

    def test_delete_credential_with_type(self):
        """Test deleting credential with specific type."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = delete_credential("default", CredentialType.MSF_PASSWORD)

            assert result is True
            mock_keyring.delete_password.assert_called_once_with(
                KEYRING_SERVICE, "msf_password:default"
            )

    def test_delete_credential_no_keyring(self):
        """Test deleting credential when keyring is unavailable."""
        with patch("sploitgpt.core.credentials._get_keyring", return_value=None):
            result = delete_credential("test_cred")

            assert result is False

    def test_delete_credential_error(self):
        """Test deleting credential when keyring raises error."""
        mock_keyring = MagicMock()
        mock_keyring.delete_password.side_effect = Exception("Delete error")
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = delete_credential("test_cred")

            assert result is False


class TestMsfPasswordFunctions:
    """Tests for MSF password convenience functions."""

    def test_get_msf_password_from_keyring(self):
        """Test getting MSF password from keyring."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "keyring_msf_pass"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = get_msf_password()

            assert result == "keyring_msf_pass"

    def test_get_msf_password_from_env(self):
        """Test getting MSF password from environment."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {"SPLOITGPT_MSF_PASSWORD": "env_msf_pass"}):
                result = get_msf_password()

                assert result == "env_msf_pass"

    def test_get_msf_password_from_config(self):
        """Test getting MSF password falls back to config."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        mock_settings = MagicMock()
        mock_settings.msf_password = "config_msf_pass"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                # Clear the SPLOITGPT_MSF_PASSWORD env var
                env = os.environ.copy()
                env.pop("SPLOITGPT_MSF_PASSWORD", None)
                with patch.dict(os.environ, env, clear=True):
                    result = get_msf_password()

                    assert result == "config_msf_pass"

    def test_set_msf_password(self):
        """Test setting MSF password."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = set_msf_password("new_password")

            assert result is True
            mock_keyring.set_password.assert_called_once_with(
                KEYRING_SERVICE, "msf_password:default", "new_password"
            )


class TestShodanApiFunctions:
    """Tests for Shodan API key convenience functions."""

    def test_get_shodan_api_key_from_keyring(self):
        """Test getting Shodan API key from keyring."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "keyring_shodan_key"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = get_shodan_api_key()

            assert result == "keyring_shodan_key"

    def test_get_shodan_api_key_from_env_shodan(self):
        """Test getting Shodan API key from SHODAN_API_KEY env."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {"SHODAN_API_KEY": "env_shodan_key"}):
                result = get_shodan_api_key()

                assert result == "env_shodan_key"

    def test_get_shodan_api_key_from_env_sploitgpt(self):
        """Test getting Shodan API key from SPLOITGPT_SHODAN_API_KEY env."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        env = {"SPLOITGPT_SHODAN_API_KEY": "sploitgpt_shodan_key"}
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, env, clear=True):
                result = get_shodan_api_key()

                assert result == "sploitgpt_shodan_key"

    def test_get_shodan_api_key_from_config(self):
        """Test getting Shodan API key falls back to config."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        mock_settings = MagicMock()
        mock_settings.shodan_api_key = "config_shodan_key"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch.dict(os.environ, {}, clear=True):
                with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                    result = get_shodan_api_key()

                    assert result == "config_shodan_key"

    def test_set_shodan_api_key(self):
        """Test setting Shodan API key."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            result = set_shodan_api_key("new_shodan_key")

            assert result is True
            mock_keyring.set_password.assert_called_once_with(
                KEYRING_SERVICE, "shodan_api_key:default", "new_shodan_key"
            )


class TestKeyringAvailability:
    """Tests for keyring availability checking."""

    def test_keyring_available_true(self):
        """Test is_keyring_available returns True when keyring works."""
        mock_keyring = MagicMock()
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            assert is_keyring_available() is True

    def test_keyring_available_false(self):
        """Test is_keyring_available returns False when keyring unavailable."""
        with patch("sploitgpt.core.credentials._get_keyring", return_value=None):
            assert is_keyring_available() is False


class TestListCredentials:
    """Tests for list_credentials function."""

    def test_list_credentials_returns_all(self):
        """Test list_credentials returns all credential types."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        mock_settings = MagicMock()
        mock_settings.msf_password = None
        mock_settings.shodan_api_key = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                with patch.dict(os.environ, {}, clear=True):
                    creds = list_credentials()

                    assert len(creds) >= 2
                    names = [c.name for c in creds]
                    assert "MSF Password" in names
                    assert "Shodan API Key" in names

    def test_list_credentials_shows_keyring_source(self):
        """Test list_credentials correctly identifies keyring source."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "stored_value"
        mock_settings = MagicMock()
        mock_settings.msf_password = "config_value"
        mock_settings.shodan_api_key = "config_value"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                creds = list_credentials()

                msf_cred = next(c for c in creds if c.name == "MSF Password")
                assert msf_cred.is_set is True
                assert msf_cred.source == "keyring"

    def test_list_credentials_shows_env_source(self):
        """Test list_credentials correctly identifies env source."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        mock_settings = MagicMock()
        mock_settings.msf_password = None
        mock_settings.shodan_api_key = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                with patch.dict(os.environ, {"SPLOITGPT_MSF_PASSWORD": "env_pass"}):
                    creds = list_credentials()

                    msf_cred = next(c for c in creds if c.name == "MSF Password")
                    assert msf_cred.is_set is True
                    assert msf_cred.source == "env"


class TestGetCredentialStatus:
    """Tests for get_credential_status function."""

    def test_credential_status_structure(self):
        """Test get_credential_status returns correct structure."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = None
        mock_settings = MagicMock()
        mock_settings.msf_password = None
        mock_settings.shodan_api_key = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                with patch.dict(os.environ, {}, clear=True):
                    status = get_credential_status()

                    assert "keyring_available" in status
                    assert "credentials" in status
                    assert isinstance(status["credentials"], dict)

    def test_credential_status_shows_secure_flag(self):
        """Test get_credential_status correctly sets secure flag."""
        mock_keyring = MagicMock()
        mock_keyring.get_password.return_value = "keyring_value"
        mock_settings = MagicMock()
        mock_settings.msf_password = "config_value"
        mock_settings.shodan_api_key = "config_value"
        with patch("sploitgpt.core.credentials._get_keyring", return_value=mock_keyring):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                status = get_credential_status()

                assert status["credentials"]["MSF Password"]["secure"] is True

    def test_credential_status_keyring_unavailable(self):
        """Test get_credential_status when keyring is unavailable."""
        mock_settings = MagicMock()
        mock_settings.msf_password = "config_value"
        mock_settings.shodan_api_key = None
        with patch("sploitgpt.core.credentials._get_keyring", return_value=None):
            with patch("sploitgpt.core.config.get_settings", return_value=mock_settings):
                with patch.dict(os.environ, {}, clear=True):
                    status = get_credential_status()

                    assert status["keyring_available"] is False
                    # Should still show credentials from config
                    assert status["credentials"]["MSF Password"]["is_set"] is True
                    assert status["credentials"]["MSF Password"]["secure"] is False
