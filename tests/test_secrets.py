"""Unit tests for Google Cloud Secret Manager integration and multi-tier secret resolution."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from sre_agent.secrets import SecretManagerClient


def test_secret_manager_fetches_from_gcp_secret_manager_when_available() -> None:
    """Verify SecretManagerClient retrieves secrets from Google Cloud Secret Manager API."""
    mock_gcp_client = MagicMock()
    mock_response = MagicMock()
    mock_response.payload.data = b"super-secure-secret-payload"
    mock_gcp_client.access_secret_version.return_value = mock_response

    client = SecretManagerClient(
        project_id="public-demo-project",
        gcp_client=mock_gcp_client,
        allow_ephemeral_fallback=False,
    )
    val = client.get_secret("PAGERDUTY_WEBHOOK_SECRET")
    assert val == "super-secure-secret-payload"
    mock_gcp_client.access_secret_version.assert_called_once_with(
        request={
            "name": "projects/public-demo-project/secrets/PAGERDUTY_WEBHOOK_SECRET/versions/latest"
        }
    )


def test_secret_manager_resolves_environment_variable_when_gcp_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify SecretManagerClient falls back to injected environment variables."""
    monkeypatch.setenv("INCIDENT_SIGNING_SECRET", "env-injected-signing-secret")
    client = SecretManagerClient(project_id=None, allow_ephemeral_fallback=False)
    assert client.get_secret("INCIDENT_SIGNING_SECRET") == "env-injected-signing-secret"


def test_secret_manager_generates_cryptographic_ephemeral_secret_in_sandbox() -> None:
    """Verify sandbox fallback generates a cryptographic 64-hex-char ephemeral secret, never a static literal."""
    client = SecretManagerClient(project_id=None, allow_ephemeral_fallback=True)
    secret_a = client.get_secret("MISSING_SANDBOX_SECRET_A")
    secret_b = client.get_secret("MISSING_SANDBOX_SECRET_B")

    assert len(secret_a) == 64
    assert secret_a != secret_b
    # Cached on repeat lookup within the same instance
    assert client.get_secret("MISSING_SANDBOX_SECRET_A") == secret_a


def test_secret_manager_raises_in_strict_production_mode_when_missing() -> None:
    """Verify fail-closed behavior in production mode when secret is absent."""
    client = SecretManagerClient(project_id=None, allow_ephemeral_fallback=False)
    with pytest.raises(RuntimeError, match="Secret 'UNCONFIGURED_PROD_SECRET' could not be resolved"):
        client.get_secret("UNCONFIGURED_PROD_SECRET")
