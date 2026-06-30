"""
Whitelist support for Firewall Analyzer.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path


CONFIG_FILE = Path("config.yaml")


def load_whitelist(config_file: Path = CONFIG_FILE) -> list[ipaddress._BaseNetwork]:
    networks = []

    if not config_file.exists():
        return networks

    in_whitelist = False

    with config_file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped == "whitelist:":
                in_whitelist = True
                continue

            if in_whitelist:
                if not stripped.startswith("- "):
                    break

                value = stripped[2:].strip()

                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    continue

    return networks


def is_whitelisted(ip: str, whitelist: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(ip_address in network for network in whitelist)
