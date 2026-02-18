import tomllib
from pathlib import Path
from typing import Any, Dict

DEFAULTS: Dict[str, Any] = {
    "targets": {
        "requests": 1,
        "urllib3": 1,
        "pip": 1,
        "boto3": 1,
        "botocore": 1,
        "pandas": 1,
        "numpy": 1,
        "tensorflow": 2,
        "torch": 1,
        "django": 1,
        "flask": 1,
        "cryptography": 2,
        "pydantic": 1,
        "openai": 1,
        "ansible": 1,
        "matplotlib": 2,
        "scipy": 1,
        "selenium": 1,
        "pyyaml": 1,
        "sqlalchemy": 1,
        "celery": 1,
        "jinja2": 1,
        "pillow": 1,
        "psycopg2": 1,
        "pyjwt": 1,
        "requests-oauthlib": 1,
        "tqdm": 1,
    },
    # How many extra characters beyond the brand name may indicate keyword-stuffing
    "keyword_extra_chars": 8,
    # Scoring weights used by the aggregate score calculation
    "scoring_weights": {
        "typosquatting": 100,
        "payload_risk": 50,
        "resurrection": 40,
        "obfuscation": 30,
        "new_account": 20,
        "hidden_identity": 10,
        "low_velocity": 10,
    },
}


def deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge dict b into a and return the result."""
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


_CACHED: Dict[str, Any] | None = None


def load_config(path: str | None = None) -> Dict[str, Any]:
    """Load the configuration, merging user config over defaults.

    By default reads `~/.skopos/config.toml` if present.
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    cfg = dict(DEFAULTS)
    user_path = Path(path) if path else Path.home() / ".skopos" / "config.toml"
    try:
        if user_path.exists():
            with open(user_path, "rb") as f:
                user_cfg = tomllib.load(f)
            cfg = deep_merge(cfg, user_cfg)
    except Exception:
        # If parsing fails, silently keep defaults to avoid breaking behavior
        pass

    _CACHED = cfg
    return cfg


def reset_cache() -> None:
    """Reset the cached config (useful in tests)."""
    global _CACHED
    _CACHED = None
