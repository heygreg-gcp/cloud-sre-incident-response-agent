"""Secure Secret Management via Google Cloud Secret Manager.

Eliminates hardcoded API keys or static fallback literals by resolving credentials
through a strict multi-tiered hierarchy:
1. Google Cloud Secret Manager (`google.cloud.secretmanager.SecretManagerServiceClient`)
2. Runtime Environment Variable injection (Cloud Run / Vertex AI Agent Engine secret mounts)
3. Cryptographically random ephemeral secret (`secrets.token_hex(32)`) in sandbox test mode,
   or fail-closed `RuntimeError` in strict production mode.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any

logger = logging.getLogger(__name__)


class SecretManagerClient:
    """Client for retrieving secrets from Google Cloud Secret Manager without hardcoded keys."""

    def __init__(
        self,
        project_id: str | None = None,
        gcp_client: Any | None = None,
        allow_ephemeral_fallback: bool = True,
    ) -> None:
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self._gcp_client = gcp_client
        self.allow_ephemeral_fallback = allow_ephemeral_fallback
        self._cache: dict[str, str] = {}

    def _get_gcp_client(self) -> Any | None:
        if self._gcp_client is not None:
            return self._gcp_client
        if not self.project_id:
            return None
        try:
            from google.cloud import secretmanager

            self._gcp_client = secretmanager.SecretManagerServiceClient()
            return self._gcp_client
        except Exception:
            return None

    def get_secret(self, secret_id: str, version: str = "latest") -> str:
        """Resolve a secret by ID using Secret Manager, environment injection, or ephemeral generation."""
        if not secret_id or not secret_id.strip():
            raise ValueError("secret_id must be a non-empty string.")

        cache_key = f"{secret_id}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Tier 1: Google Cloud Secret Manager API
        client = self._get_gcp_client()
        if client is not None and self.project_id:
            resource_name = (
                f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            )
            try:
                response = client.access_secret_version(request={"name": resource_name})
                raw_bytes: bytes = response.payload.data
                resolved = raw_bytes.decode("utf-8", errors="ignore").strip()
                if resolved:
                    self._cache[cache_key] = resolved
                    return resolved
            except Exception as exc:
                logger.debug(
                    "Cloud Secret Manager lookup for '%s' fell back to environment: %s",
                    secret_id,
                    type(exc).__name__,
                )

        # Tier 2: Environment variable injection
        env_value = os.environ.get(secret_id, "").strip()
        if env_value:
            self._cache[cache_key] = env_value
            return env_value

        # Tier 3: Ephemeral cryptographic token (sandbox/testing) or fail-closed
        if self.allow_ephemeral_fallback:
            logger.warning(
                "Generating ephemeral secret for '%s'. Instance-isolated for sandbox/test execution only!",
                secret_id,
            )
            ephemeral = secrets.token_hex(32)
            self._cache[cache_key] = ephemeral
            return ephemeral

        raise RuntimeError(
            f"Secret '{secret_id}' could not be resolved from Google Cloud Secret Manager or environment."
        )
