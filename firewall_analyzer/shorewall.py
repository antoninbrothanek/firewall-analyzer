import re

from .config import SHOREWALL_RULES


def load_published_services() -> dict[str, str]:
    services = {}

    if not SHOREWALL_RULES.exists():
        return services

    with SHOREWALL_RULES.open("r", encoding="utf-8", errors="ignore") as rules:
        for line in rules:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            fields = re.split(r"\s+", line)

            if not fields:
                continue

            action = fields[0]

            if action not in {"DNAT", "ACCEPT"}:
                continue

            proto = None
            for item in ("tcp", "udp"):
                if item in fields:
                    proto = item.upper()
                    break

            if proto is None:
                continue

            port = fields[-1]

            if ":" in port:
                try:
                    first, last = map(int, port.split(":", 1))
                except ValueError:
                    continue

                for p in range(first, last + 1):
                    services[f"{proto}/{p}"] = action
            else:
                if port.isdigit():
                    services[f"{proto}/{port}"] = action

    return services
