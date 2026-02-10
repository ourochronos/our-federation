"""Federation exception hierarchy."""

from __future__ import annotations

from typing import Any


class FederationException(Exception):
    """Base exception for all federation errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


# Alias for backward compatibility with code that imported ValenceException
ValenceException = FederationException
