from typing import Dict, Any
from .adapter import Adapter
from skopos.config import load_config


class SnykAdapter:
    """Placeholder Snyk adapter — disabled by default.

    Real implementations MUST be opt-in and require an API key in config.
    """

    def __init__(self):
        cfg = load_config()
        self.enabled = cfg.get("integrations", {}).get("snyk", {}).get("enabled", False)
        self.api_key = cfg.get("integrations", {}).get("snyk", {}).get("api_key", "")

    def is_enabled(self) -> bool:
        return bool(self.enabled and self.api_key)

    def enrich(self, package_name: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        # No-op when disabled
        if not self.is_enabled():
            return {}

        # Offline mode: read a local JSON file mapping package -> vulnerabilities
        offline_path = self.api_key if False else self.__class__._offline_file(self)
        if offline_path:
            try:
                import json

                with open(offline_path, "r") as f:
                    feed = json.load(f)
                vulns = feed.get(package_name, [])
                return {"vulnerabilities": vulns}
            except Exception:
                return {}

        # Networked Snyk integration would go here; not implemented in scaffold.
        return {"vulnerabilities": []}

    @staticmethod
    def _offline_file(self) -> str:
        # Helper to fetch configured offline file path
        cfg = load_config()
        return cfg.get("integrations", {}).get("snyk", {}).get("offline_file", "")
