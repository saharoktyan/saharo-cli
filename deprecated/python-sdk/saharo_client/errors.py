from __future__ import annotations


class SaharoClientError(Exception):
    """Base client error."""


class NetworkError(SaharoClientError):
    """Transport/network layer error."""


class ApiError(SaharoClientError):
    def __init__(self, status_code: int, message: str, details: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details


class AuthError(ApiError):
    """Auth-related API error."""
