"""
Credential Management Module

Securely stores and retrieves credentials using the system keyring.
Falls back to environment variables if keyring is unavailable.
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Literal

logger = logging.getLogger(__name__)

# Service name for keyring storage
KEYRING_SERVICE = "sploitgpt"


class CredentialType(str, Enum):
    """Types of credentials that can be stored."""

    MSF_PASSWORD = "msf_password"
    SHODAN_API_KEY = "shodan_api_key"
    OPENAI_API_KEY = "openai_api_key"
    ANTHROPIC_API_KEY = "anthropic_api_key"
    CUSTOM = "custom"


@dataclass
class CredentialInfo:
    """Information about a stored credential."""

    name: str
    credential_type: CredentialType
    is_set: bool
    source: Literal["keyring", "env", "config", "none"]
    env_var: str | None = None


def _get_keyring():
    """Get keyring module, returning None if unavailable."""
    try:
        import keyring
        from keyring.errors import KeyringError

        # Test if keyring backend is available
        try:
            # Try to get the backend - this will fail if no backend is configured
            backend = keyring.get_keyring()
            # Check if it's a null/fail backend
            backend_name = type(backend).__name__.lower()
            if "fail" in backend_name or "null" in backend_name:
                logger.debug(f"Keyring backend is null/fail type: {backend_name}")
                return None
            return keyring
        except KeyringError as e:
            logger.debug(f"Keyring not available: {e}")
            return None
    except ImportError:
        logger.debug("Keyring module not installed")
        return None


def _keyring_available() -> bool:
    """Check if keyring is available and functional."""
    return _get_keyring() is not None


def store_credential(
    name: str,
    value: str,
    credential_type: CredentialType = CredentialType.CUSTOM,
) -> bool:
    """
    Store a credential securely in the system keyring.

    Args:
        name: Unique name for the credential
        value: The credential value to store
        credential_type: Type of credential (for organization)

    Returns:
        True if stored successfully, False otherwise
    """
    keyring = _get_keyring()
    if keyring is None:
        logger.warning("Keyring not available. Credential not stored securely.")
        return False

    try:
        # Use credential type as part of the key for organization
        key = (
            f"{credential_type.value}:{name}" if credential_type != CredentialType.CUSTOM else name
        )
        keyring.set_password(KEYRING_SERVICE, key, value)
        logger.info(f"Credential '{name}' stored in keyring")
        return True
    except Exception as e:
        logger.error(f"Failed to store credential '{name}': {e}")
        return False


def get_credential(
    name: str,
    credential_type: CredentialType = CredentialType.CUSTOM,
    env_fallback: str | None = None,
) -> str | None:
    """
    Retrieve a credential from keyring or environment.

    Args:
        name: Name of the credential to retrieve
        credential_type: Type of credential
        env_fallback: Environment variable name to check as fallback

    Returns:
        The credential value, or None if not found
    """
    # First, try keyring
    keyring = _get_keyring()
    if keyring is not None:
        try:
            key = (
                f"{credential_type.value}:{name}"
                if credential_type != CredentialType.CUSTOM
                else name
            )
            value = keyring.get_password(KEYRING_SERVICE, key)
            if value:
                return value
        except Exception as e:
            logger.debug(f"Keyring lookup failed for '{name}': {e}")

    # Fallback to environment variable
    if env_fallback:
        value = os.environ.get(env_fallback)
        if value:
            return value

    return None


def delete_credential(
    name: str,
    credential_type: CredentialType = CredentialType.CUSTOM,
) -> bool:
    """
    Delete a credential from the keyring.

    Args:
        name: Name of the credential to delete
        credential_type: Type of credential

    Returns:
        True if deleted successfully, False otherwise
    """
    keyring = _get_keyring()
    if keyring is None:
        logger.warning("Keyring not available")
        return False

    try:
        key = (
            f"{credential_type.value}:{name}" if credential_type != CredentialType.CUSTOM else name
        )
        keyring.delete_password(KEYRING_SERVICE, key)
        logger.info(f"Credential '{name}' deleted from keyring")
        return True
    except Exception as e:
        logger.debug(f"Failed to delete credential '{name}': {e}")
        return False


def list_credentials() -> list[CredentialInfo]:
    """
    List all known credential slots and their status.

    Returns:
        List of CredentialInfo objects describing each credential
    """
    credentials = []

    # Check MSF password
    msf_value = get_msf_password()
    msf_source: Literal["keyring", "env", "config", "none"] = "none"
    if msf_value:
        # Determine source
        keyring = _get_keyring()
        if keyring:
            try:
                key = f"{CredentialType.MSF_PASSWORD.value}:default"
                if keyring.get_password(KEYRING_SERVICE, key):
                    msf_source = "keyring"
            except Exception:
                pass
        if msf_source == "none" and os.environ.get("SPLOITGPT_MSF_PASSWORD"):
            msf_source = "env"
        elif msf_source == "none":
            msf_source = "config"

    credentials.append(
        CredentialInfo(
            name="MSF Password",
            credential_type=CredentialType.MSF_PASSWORD,
            is_set=msf_value is not None,
            source=msf_source,
            env_var="SPLOITGPT_MSF_PASSWORD",
        )
    )

    # Check Shodan API key
    shodan_value = get_shodan_api_key()
    shodan_source: Literal["keyring", "env", "config", "none"] = "none"
    if shodan_value:
        keyring = _get_keyring()
        if keyring:
            try:
                key = f"{CredentialType.SHODAN_API_KEY.value}:default"
                if keyring.get_password(KEYRING_SERVICE, key):
                    shodan_source = "keyring"
            except Exception:
                pass
        if shodan_source == "none" and (
            os.environ.get("SHODAN_API_KEY") or os.environ.get("SPLOITGPT_SHODAN_API_KEY")
        ):
            shodan_source = "env"
        elif shodan_source == "none":
            shodan_source = "config"

    credentials.append(
        CredentialInfo(
            name="Shodan API Key",
            credential_type=CredentialType.SHODAN_API_KEY,
            is_set=shodan_value is not None,
            source=shodan_source,
            env_var="SHODAN_API_KEY",
        )
    )

    return credentials


# Convenience functions for specific credentials


def get_msf_password() -> str | None:
    """Get the Metasploit RPC password."""
    # Try keyring first
    value = get_credential("default", CredentialType.MSF_PASSWORD, "SPLOITGPT_MSF_PASSWORD")
    if value:
        return value

    # Fall back to config default
    from sploitgpt.core.config import get_settings

    return get_settings().msf_password


def set_msf_password(password: str) -> bool:
    """Store the Metasploit RPC password in keyring."""
    return store_credential("default", password, CredentialType.MSF_PASSWORD)


def get_shodan_api_key() -> str | None:
    """Get the Shodan API key."""
    # Try keyring first
    value = get_credential("default", CredentialType.SHODAN_API_KEY)
    if value:
        return value

    # Try environment variables
    value = os.environ.get("SHODAN_API_KEY") or os.environ.get("SPLOITGPT_SHODAN_API_KEY")
    if value:
        return value

    # Fall back to config
    from sploitgpt.core.config import get_settings

    return get_settings().shodan_api_key


def set_shodan_api_key(api_key: str) -> bool:
    """Store the Shodan API key in keyring."""
    return store_credential("default", api_key, CredentialType.SHODAN_API_KEY)


def is_keyring_available() -> bool:
    """Check if system keyring is available for secure storage."""
    return _keyring_available()


def get_credential_status() -> dict[str, dict]:
    """
    Get detailed status of all credentials.

    Returns:
        Dictionary mapping credential names to their status info
    """
    status = {
        "keyring_available": is_keyring_available(),
        "credentials": {},
    }

    for cred in list_credentials():
        status["credentials"][cred.name] = {
            "is_set": cred.is_set,
            "source": cred.source,
            "env_var": cred.env_var,
            "secure": cred.source == "keyring",
        }

    return status
