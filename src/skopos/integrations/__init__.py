"""Integrations package for external adapters (scaffold).

Adapters should be no-op by default and only perform network activity when
explicitly enabled via configuration.
"""

__all__ = [
    "adapter",
    "snyk_adapter",
    "socket_adapter",
]
