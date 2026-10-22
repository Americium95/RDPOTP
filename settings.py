"""Read local RDPOTP settings with environment-variable overrides."""
import configparser
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("config.ini")
_CONFIG = configparser.ConfigParser(interpolation=None)
_CONFIG.read(CONFIG_PATH, encoding="utf-8-sig")


def get(section, key, default, cast=str, env=None):
    raw = os.environ.get(env) if env else None
    if raw is None:
        raw = _CONFIG.get(section, key, fallback=str(default))
    try:
        if cast is bool:
            return str(raw).strip().lower() in ("1", "true", "yes", "on")
        return cast(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid setting {section}.{key} ({env or 'config.ini'}): {raw!r}"
        ) from exc


if __name__ == "__main__":
    import sys
    section, key = sys.argv[1:3]
    defaults = {("server", "port"): (3390, int, "RDP_PORT")}
    default, cast, env = defaults[(section, key)]
    print(get(section, key, default, cast, env))

