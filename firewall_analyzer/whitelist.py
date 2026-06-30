"""
Whitelist support for Firewall Analyzer.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

CONFIG_FILE = Path("config.yaml")
DEFAULT_WHITELIST_FILE = Path("whitelist.txt")


def get_whitelist_file(config_file: Path = CONFIG_FILE) -> Path:
    if not config_file.exists():
        return DEFAULT_WHITELIST_FILE

    with config_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("whitelist_file:"):
                value = stripped.split(":", 1)[1].strip()
                return Path(value)

    return DEFAULT_WHITELIST_FILE


def load_whitelist() -> list[ipaddress._BaseNetwork]:
    networks = []
    whitelist_file = get_whitelist_file()

    if not whitelist_file.exists():
        return networks

    with whitelist_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            try:
                networks.append(ipaddress.ip_network(stripped, strict=False))
            except ValueError:
                continue

    return networks


def is_whitelisted(ip: str, whitelist: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(ip_address in network for network in whitelist)
