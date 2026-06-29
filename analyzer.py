#!/usr/bin/env python3
"""
Firewall Analyzer v0.7
"""

from collections import Counter, defaultdict
from pathlib import Path
import re
import signal
import sys

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

LOG_FILE = Path("/var/log/syslog")
SHOREWALL_RULES = Path("/etc/shorewall/rules")
MARKER = "net-fw DROP"
TOP_COUNT = 20
PROFILE_COUNT = 10

DANGEROUS_SERVICES = {
    "TCP/23": ("Telnet scanner", 60),
    "TCP/445": ("SMB scanner", 70),
    "TCP/3389": ("RDP scanner", 60),
    "UDP/5060": ("SIP scanner", 80),
    "TCP/1433": ("MSSQL scanner", 50),
    "TCP/3306": ("MySQL scanner", 50),
    "TCP/5432": ("PostgreSQL scanner", 50),
    "TCP/6379": ("Redis scanner", 60),
    "TCP/27017": ("MongoDB scanner", 50),
    "TCP/9200": ("Elasticsearch scanner", 50),
}

REVIEW_SERVICES = {
    "TCP/22": ("SSH probing", 30),
    "TCP/2222": ("Published SSH DNAT probing", 50),
    "TCP/25": ("SMTP probing", 20),
    "TCP/465": ("SMTPS probing", 20),
    "TCP/587": ("Submission probing", 20),
    "TCP/993": ("IMAPS probing", 20),
    "UDP/13231": ("Published WireGuard probing", 50),
    "UDP/13232": ("Published WireGuard probing", 50),
}

LIKELY_BENIGN_PREFIXES = (
    "157.240.",
    "31.13.",
    "31.14.",
    "17.253.",
)


def parse_tokens(line: str) -> dict[str, str]:
    result = {}

    for token in line.split():
        if "=" in token:
            key, value = token.split("=", 1)
            result[key] = value

    return result


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


def is_icmp_only(profile: dict) -> bool:
    protocols = profile["protocols"]
    return bool(protocols) and set(protocols.keys()) == {"ICMP"}


def is_high_udp_port_only(profile: dict) -> bool:
    protocols = profile["protocols"]
    proto_dport = profile["proto_dport"]

    if not protocols or set(protocols.keys()) != {"UDP"}:
        return False

    if not proto_dport:
        return False

    for service in proto_dport:
        proto, port_text = service.split("/", 1)

        if proto != "UDP":
            return False

        try:
            port = int(port_text)
        except ValueError:
            return False

        if port < 49152:
            return False

    return True


def calculate_threat_score(ip: str, profile: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    total = profile["total"]
    proto_dport = profile["proto_dport"]

    if is_icmp_only(profile):
        score -= 80
        reasons.append("-80 pouze ICMP provoz")

    if ip.startswith(LIKELY_BENIGN_PREFIXES) and is_high_udp_port_only(profile):
        score -= 100
        reasons.append("-100 pravděpodobně legitimní CDN/aplikační UDP provoz")

    for service, (description, points) in DANGEROUS_SERVICES.items():
        if service in proto_dport:
            score += points
            reasons.append(f"+{points} {description} ({service})")

    for service, (description, points) in REVIEW_SERVICES.items():
        if service in proto_dport:
            score += points
            reasons.append(f"+{points} {description} ({service})")

    tcp_services = [
        service for service in proto_dport
        if service.startswith("TCP/")
    ]

    if len(tcp_services) >= 10:
        score += 40
        reasons.append(f"+40 skenování více TCP portů ({len(tcp_services)})")

    if total >= 1000:
        score += 30
        reasons.append("+30 více než 1000 DROP paketů")
    elif total >= 100:
        score += 15
        reasons.append("+15 více než 100 DROP paketů")
    elif total >= 50:
        score += 10
        reasons.append("+10 více než 50 DROP paketů")

    score = max(0, min(score, 100))

    if not reasons:
        reasons.append("0 bez jasného rizikového vzoru")

    return score, reasons


def classify_score(score: int) -> str:
    if score >= 60:
        return "BAN"

    if score >= 20:
        return "REVIEW"

    return "IGNORE"


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


def print_top(title: str, counter: Counter, limit: int = TOP_COUNT) -> None:
    print()
    print(title)
    print("-" * len(title))

    for item, count in counter.most_common(limit):
        print(f"{item:>20} {count:>8}")


def print_ip_profiles(
    src_counter: Counter,
    ip_profiles: dict,
    published_services: dict[str, str],
) -> None:
    print()
    print("=" * 60)
    print(f"IP profily TOP {PROFILE_COUNT}")
    print("=" * 60)

    for ip, count in src_counter.most_common(PROFILE_COUNT):
        profile = ip_profiles[ip]
        score, reasons = calculate_threat_score(ip, profile)
        recommendation = classify_score(score)

        print()
        print("-" * 60)
        print(f"IP: {ip}")
        print(f"Celkem DROP : {profile['total']}")
        print(f"Threat Score: {score}/100")
        print(f"Doporučení  : {recommendation}")

        print()
        print("Důvody:")
        for reason in reasons:
            print(f"  {reason}")

        print()
        print("Protokoly:")
        for proto, proto_count in profile["protocols"].most_common():
            print(f"  {proto:>8} {proto_count:>8}")

        print()
        print("TOP cílové porty / služby:")
        for item, item_count in profile["proto_dport"].most_common(10):
            label = ""
            if item in published_services:
                label = f"  [PUBLISHED: {published_services[item]}]"
            print(f"  {item:>12} {item_count:>8}{label}")

        if profile["icmp_types"]:
            print()
            print("ICMP typy:")
            for item, item_count in profile["icmp_types"].most_common(10):
                print(f"  TYPE={item:>4} {item_count:>8}")


def print_service_profiles(
    service_profiles: dict,
    published_services: dict[str, str],
) -> None:
    print()
    print("=" * 60)
    print("Service Profile")
    print("=" * 60)

    for service, counter in sorted(
        service_profiles.items(),
        key=lambda item: sum(item[1].values()),
        reverse=True,
    ):
        total = sum(counter.values())

        published_label = ""
        if service in published_services:
            published_label = f" [PUBLISHED: {published_services[service]}]"

        print()
        print("-" * 60)
        print(f"{service}{published_label}")
        print("-" * 60)
        print(f"Celkem DROP: {total}")

        print()
        print("TOP zdrojové IP:")

        for ip, count in counter.most_common(10):
            print(f"  {ip:>20} {count:>8}")


def collect_blacklist_candidates(ip_profiles: dict) -> list[tuple[str, int, str, int]]:
    candidates = []

    for ip, profile in ip_profiles.items():
        score, reasons = calculate_threat_score(ip, profile)
        recommendation = classify_score(score)

        if recommendation != "BAN":
            continue

        main_reason = reasons[0] if reasons else "bez důvodu"
        candidates.append((ip, score, main_reason, profile["total"]))

    candidates.sort(key=lambda item: (item[1], item[3]), reverse=True)
    return candidates


def print_blacklist_candidates(ip_profiles: dict) -> None:
    candidates = collect_blacklist_candidates(ip_profiles)

    print()
    print("=" * 60)
    print("Blacklist Candidates")
    print("=" * 60)

    if not candidates:
        print()
        print("Žádní kandidáti k ručnímu zabanování.")
        return

    print()
    print("Tyto IP mají doporučení BAN. Skript je pouze vypisuje.")
    print("Ruční přidání proveď například:")
    print("  sudo ./scripts/add-to-badlist.sh <IP>")
    print()

    for ip, score, reason, total in candidates:
        print(f"{ip:>20}  score {score:>3}/100  drops {total:>6}  {reason}")


def main() -> None:
    if not LOG_FILE.exists():
        print(f"Log {LOG_FILE} neexistuje.")
        sys.exit(1)

    published_services = load_published_services()

    try:
        (
            total,
            src_counter,
            dpt_counter,
            proto_counter,
            ip_profiles,
            service_profiles,
        ) = analyze_log(LOG_FILE)

    except PermissionError:
        print()
        print("Nemám oprávnění číst log.")
        print(f"Spusť: sudo python3 {Path(__file__).name}")
        print()
        sys.exit(1)

    print("=" * 60)
    print("Firewall Analyzer v0.7")
    print("=" * 60)
    print(f"Log soubor : {LOG_FILE}")
    print(f"Shorewall rules: {SHOREWALL_RULES}")
    print(f"Publikované služby načtené ze Shorewallu: {len(published_services)}")
    print(f"DROP paketů: {total}")

    print_top("TOP zdrojové IP", src_counter)
    print_top("TOP cílové porty", dpt_counter)
    print_top("Protokoly", proto_counter)

    print_ip_profiles(src_counter, ip_profiles, published_services)
    print_service_profiles(service_profiles, published_services)
    print_blacklist_candidates(ip_profiles)


if __name__ == "__main__":
    main()
