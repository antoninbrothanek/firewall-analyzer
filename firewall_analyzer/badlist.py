"""
Badlist support for Firewall Analyzer.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

CONFIG_FILE = Path("config.yaml")
DEFAULT_BADLIST_FILE = Path("badlist.txt")


def get_badlist_file(config_file: Path = CONFIG_FILE) -> Path:
    if not config_file.exists():
        return DEFAULT_BADLIST_FILE

    with config_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("badlist_file:"):
                value = stripped.split(":", 1)[1].strip()
                return Path(value)

    return DEFAULT_BADLIST_FILE


def load_badlist() -> list[ipaddress._BaseNetwork]:
    networks = []
    badlist_file = get_badlist_file()

    if not badlist_file.exists():
        return networks

    with badlist_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            try:
                networks.append(ipaddress.ip_network(stripped, strict=False))
            except ValueError:
                continue

    return networks


def is_badlisted(ip: str, badlist: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(ip_address in network for network in badlist)
