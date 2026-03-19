"""Configuration loader for business-profiler.

Loads optional API keys from environment variables or config file.
All keys are optional — core workflow uses only free sources.
"""

import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "business-profiler"
CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_DIR = Path.home() / ".cache" / "business-profiler"


def load_config() -> dict:
    """Load configuration from env vars and config file.

    Priority: environment variables > config file > defaults.

    Returns:
        Dict with configuration values
    """
    config = {
        "fofa_email": None,
        "fofa_key": None,
        "securitytrails_key": None,
    }

    # Load from config file
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                file_config = json.load(f)
            config.update({k: v for k, v in file_config.items() if v})
        except Exception:
            pass

    # Override with environment variables
    env_mappings = {
        "FOFA_EMAIL": "fofa_email",
        "FOFA_KEY": "fofa_key",
        "SECURITYTRAILS_KEY": "securitytrails_key",
    }

    for env_var, config_key in env_mappings.items():
        val = os.environ.get(env_var)
        if val:
            config[config_key] = val

    return config


def get_cache_dir() -> Path:
    """Get cache directory, creating it if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def has_api(name: str) -> bool:
    """Check if an optional API key is configured."""
    config = load_config()
    return bool(config.get(name))


if __name__ == "__main__":
    print(json.dumps(load_config(), indent=2))
    print(f"Cache dir: {get_cache_dir()}")
