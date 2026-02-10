"""Global test fixtures for our-federation test suite."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest

# ============================================================================
# PostgreSQL Availability Detection
# ============================================================================


def _check_postgres_available() -> tuple[bool, str | None]:
    """Check if PostgreSQL is available for integration tests."""
    try:
        import psycopg2
    except ImportError:
        return False, "psycopg2 not installed"

    host = os.environ.get("VKB_DB_HOST", "localhost")
    port = int(os.environ.get("VKB_DB_PORT", "5432"))
    dbname = os.environ.get("VKB_DB_NAME", "valence")
    user = os.environ.get("VKB_DB_USER", "valence")
    password = os.environ.get("VKB_DB_PASSWORD", "")

    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=dbname,
            user=user,
            password=password,
            connect_timeout=3,
        )
        conn.close()
        return True, None
    except psycopg2.OperationalError as e:
        return False, f"PostgreSQL connection failed: {e}"
    except Exception as e:
        return False, f"Unexpected error connecting to PostgreSQL: {e}"


POSTGRES_AVAILABLE, POSTGRES_ERROR = _check_postgres_available()


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers and check PostgreSQL availability."""
    config.addinivalue_line("markers", "unit: Unit tests (no external dependencies)")
    config.addinivalue_line("markers", "integration: Integration tests (require external services)")
    config.addinivalue_line("markers", "slow: Slow tests (>5s)")
    config.addinivalue_line("markers", "requires_postgres: mark test as requiring a real PostgreSQL database")
    config._postgres_available = POSTGRES_AVAILABLE  # type: ignore[attr-defined]
    config._postgres_error = POSTGRES_ERROR  # type: ignore[attr-defined]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Add skip markers to tests that require PostgreSQL when DB is unavailable."""
    if POSTGRES_AVAILABLE:
        return

    skip_postgres = pytest.mark.skip(reason=f"PostgreSQL not available: {POSTGRES_ERROR}")

    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_postgres)
        elif "requires_postgres" in item.keywords:
            item.add_marker(skip_postgres)


# ============================================================================
# Environment Fixtures
# ============================================================================


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Remove all VKB_ and VALENCE_ environment variables."""
    from our_federation.config import clear_config_cache, clear_federation_config

    env_prefixes = ("VKB_", "VALENCE_", "OPENAI_")
    for key in list(os.environ.keys()):
        if any(key.startswith(prefix) for prefix in env_prefixes):
            monkeypatch.delenv(key, raising=False)
    clear_config_cache()
    clear_federation_config()
    yield
    clear_config_cache()
    clear_federation_config()


@pytest.fixture
def env_with_db_vars(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Set up database environment variables."""
    monkeypatch.setenv("VKB_DB_HOST", "localhost")
    monkeypatch.setenv("VKB_DB_PORT", "5432")
    monkeypatch.setenv("VKB_DB_NAME", "valence_test")
    monkeypatch.setenv("VKB_DB_USER", "valence")
    monkeypatch.setenv("VKB_DB_PASSWORD", "testpass")
    yield


# ============================================================================
# Database Mocking Fixtures
# ============================================================================


@pytest.fixture
def mock_get_cursor() -> Any:
    """Mock the get_cursor context manager from our_db."""
    mock_cursor = MagicMock()
    mock_cursor.execute = MagicMock()
    mock_cursor.fetchone = MagicMock(return_value=None)
    mock_cursor.fetchall = MagicMock(return_value=[])
    mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
    mock_cursor.__exit__ = MagicMock(return_value=False)

    with patch("our_db.get_cursor", return_value=mock_cursor):
        yield mock_cursor


# ============================================================================
# Model Factory Fixtures
# ============================================================================


@pytest.fixture
def sample_uuid() -> UUID:
    """Generate a sample UUID."""
    return uuid4()


@pytest.fixture
def sample_datetime() -> datetime:
    """Generate a sample datetime."""
    return datetime(2024, 1, 15, 10, 30, 0)


@pytest.fixture
def belief_row_factory() -> Any:
    """Factory for creating belief database rows."""

    def factory(
        id: UUID | None = None,
        content: str = "Test belief content",
        confidence: dict[str, Any] | None = None,
        domain_path: list[str] | None = None,
        status: str = "active",
        **kwargs: Any,
    ) -> dict[str, Any]:
        now = datetime.now()
        return {
            "id": id or uuid4(),
            "content": content,
            "confidence": json.dumps(confidence or {"overall": 0.7}),
            "domain_path": domain_path or ["test", "domain"],
            "valid_from": kwargs.get("valid_from"),
            "valid_until": kwargs.get("valid_until"),
            "created_at": kwargs.get("created_at", now),
            "modified_at": kwargs.get("modified_at", now),
            "source_id": kwargs.get("source_id"),
            "extraction_method": kwargs.get("extraction_method"),
            "supersedes_id": kwargs.get("supersedes_id"),
            "superseded_by_id": kwargs.get("superseded_by_id"),
            "status": status,
        }

    return factory


# ============================================================================
# Helper Functions
# ============================================================================


def make_uuid() -> UUID:
    """Generate a new UUID for tests."""
    return uuid4()


def make_datetime(days_ago: int = 0) -> datetime:
    """Generate a datetime, optionally in the past."""
    return datetime.now() - timedelta(days=days_ago)


pytest.make_uuid = make_uuid  # type: ignore[attr-defined]
pytest.make_datetime = make_datetime  # type: ignore[attr-defined]
