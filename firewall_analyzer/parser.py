from collections import Counter, defaultdict
from pathlib import Path

from .config import MARKER


def parse_tokens(line: str) -> dict[str, str]:
    result = {}

    for token in line.split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value

    return result


def analyze_log(log_file: Path):
    total = 0

    src_counter = Counter()
    dpt_counter = Counter()
    proto_counter = Counter()
    service_profiles = defaultdict(Counter)

    ip_profiles = defaultdict(
        lambda: {
            "total": 0,
            "protocols": Counter(),
            "dports": Counter(),
            "sports": Counter(),
            "proto_dport": Counter(),
            "icmp_types": Counter(),
        }
    )

    with log_file.open("r", encoding="utf-8", errors="ignore") as logfile:
        for line in logfile:
            if MARKER not in line:
                continue

            total += 1
            data = parse_tokens(line)

            src = data.get("SRC")
            proto = data.get("PROTO")
            dpt = data.get("DPT")
            spt = data.get("SPT")
            icmp_type = data.get("TYPE")

            if src:
                src_counter[src] += 1
                profile = ip_profiles[src]
                profile["total"] += 1

                if proto:
                    profile["protocols"][proto] += 1

                if dpt:
                    profile["dports"][dpt] += 1

                if spt:
                    profile["sports"][spt] += 1

                if proto and dpt:
                    service = f"{proto}/{dpt}"
                    profile["proto_dport"][service] += 1
                    service_profiles[service][src] += 1

                if proto == "ICMP" and icmp_type:
                    profile["icmp_types"][icmp_type] += 1

            if proto:
                proto_counter[proto] += 1

            if dpt:
                dpt_counter[dpt] += 1

    return total, src_counter, dpt_counter, proto_counter, ip_profiles, service_profiles
