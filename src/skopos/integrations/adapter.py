from typing import Protocol, Dict, Any


class Adapter(Protocol):
    """Minimal adapter interface for external enrichment providers."""

    def is_enabled(self) -> bool:
        ...

    def enrich(self, package_name: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Return enrichment data (must be safe and side-effect free when disabled)."""
