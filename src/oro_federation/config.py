"""Federation configuration.

Provides federation-specific configuration with env var support.
Uses a protocol-based injection pattern so the calling application
can provide its own config implementation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@runtime_checkable
class FederationConfigProtocol(Protocol):
    """Protocol defining federation configuration requirements.

    This allows federation to depend on a config interface rather than
    a concrete settings class. Calling applications should implement
    this protocol and register via set_federation_config().
    """

    @property
    def federation_node_did(self) -> str | None:
        """Node DID for this federation instance."""
        ...

    @property
    def federation_private_key(self) -> str | None:
        """Ed25519 private key hex for signing."""
        ...

    @property
    def federation_sync_interval_seconds(self) -> int:
        """Interval between sync operations."""
        ...

    @property
    def port(self) -> int:
        """Server port (used as fallback for DID generation)."""
        ...


@dataclass
class FederationSettings:
    """Concrete federation configuration.

    Reads from environment variables with VALENCE_ prefix.
    Can be instantiated directly for testing.
    """

    # Identity
    federation_node_did: str | None = None
    federation_private_key: str | None = None
    federation_public_key: str | None = None
    federation_did: str | None = None

    # Security
    require_tls: bool = False
    federation_require_auth: bool = False

    # Sync
    federation_sync_interval_seconds: int = 300
    federation_max_hop_count: int = 3

    # Privacy
    federation_default_visibility: str = "private"
    federation_privacy_epsilon: float = 1.0
    federation_privacy_delta: float = 1e-5
    federation_min_aggregation_contributors: int = 3

    # Network
    port: int = 8420
    federation_capabilities: list[str] = field(default_factory=list)
    federation_domains: list[str] = field(default_factory=list)
    federation_bootstrap_nodes: list[str] = field(default_factory=list)
    federation_publish_trust_anchors: bool = False

    # Trust
    trust_registry_path: str | None = None

    # Embedding
    openai_api_key: str = ""

    @classmethod
    def from_env(cls) -> FederationSettings:
        """Create settings from environment variables."""
        return cls(
            federation_node_did=os.environ.get("VALENCE_FEDERATION_NODE_DID"),
            federation_private_key=os.environ.get("VALENCE_FEDERATION_PRIVATE_KEY"),
            federation_public_key=os.environ.get("VALENCE_FEDERATION_PUBLIC_KEY"),
            federation_did=os.environ.get("VALENCE_FEDERATION_DID"),
            require_tls=os.environ.get("VALENCE_REQUIRE_TLS", "").lower() in ("1", "true", "yes"),
            federation_require_auth=os.environ.get("VALENCE_FEDERATION_REQUIRE_AUTH", "").lower()
            in ("1", "true", "yes"),
            federation_sync_interval_seconds=int(os.environ.get("VALENCE_FEDERATION_SYNC_INTERVAL", "300")),
            federation_max_hop_count=int(os.environ.get("VALENCE_FEDERATION_MAX_HOP_COUNT", "3")),
            federation_default_visibility=os.environ.get("VALENCE_FEDERATION_DEFAULT_VISIBILITY", "private"),
            federation_privacy_epsilon=float(os.environ.get("VALENCE_FEDERATION_PRIVACY_EPSILON", "1.0")),
            federation_privacy_delta=float(os.environ.get("VALENCE_FEDERATION_PRIVACY_DELTA", "1e-5")),
            federation_min_aggregation_contributors=int(
                os.environ.get("VALENCE_FEDERATION_MIN_AGGREGATION_CONTRIBUTORS", "3")
            ),
            port=int(os.environ.get("VALENCE_PORT", "8420")),
            trust_registry_path=os.environ.get("VALENCE_TRUST_REGISTRY"),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        )


# Global federation config - set by application layer at startup
_federation_config: FederationConfigProtocol | None = None
_core_settings: FederationSettings | None = None


def set_federation_config(config: FederationConfigProtocol) -> None:
    """Set the global federation config.

    Called by the application layer at startup to inject its settings.

    Args:
        config: An object implementing FederationConfigProtocol
    """
    global _federation_config
    _federation_config = config


def get_federation_config() -> FederationConfigProtocol:
    """Get the global federation config.

    Returns:
        The configured federation settings.

    Raises:
        RuntimeError: If federation config hasn't been set yet.
    """
    if _federation_config is None:
        raise RuntimeError("Federation config not initialized. Call set_federation_config() at application startup.")
    return _federation_config


def get_federation_config_or_none() -> FederationConfigProtocol | None:
    """Get the global federation config, or None if not set."""
    return _federation_config


def clear_federation_config() -> None:
    """Clear the global federation config. For testing."""
    global _federation_config
    _federation_config = None


def get_config() -> FederationSettings:
    """Get federation-specific settings.

    Returns:
        FederationSettings loaded from environment.
    """
    global _core_settings
    if _core_settings is None:
        _core_settings = FederationSettings.from_env()
    return _core_settings


def clear_config_cache() -> None:
    """Clear the config cache. For testing."""
    global _core_settings
    _core_settings = None
