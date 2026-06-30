"""
History Engine for Firewall Analyzer.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .scoring import calculate_threat_score, classify_score

STATE_DIR = Path("state")
HISTORY_FILE = STATE_DIR / "ip-history.json"


def load_history() -> dict:
    if not HISTORY_FILE.exists():
        return {}

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_history(history: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, sort_keys=True)


def get_attack_fingerprint(profile: dict) -> list[str]:
    services = profile.get("proto_dport", {})
    attacks = set()

    for service in services:
        if service == "TCP/22":
            attacks.add("SSH")
        elif service == "TCP/2222":
            attacks.add("SSH-PUBLISHED")
        elif service == "TCP/23":
            attacks.add("TELNET")
        elif service == "TCP/445":
            attacks.add("SMB")
        elif service == "TCP/3389":
            attacks.add("RDP")
        elif service == "UDP/5060":
            attacks.add("SIP")
        elif service == "TCP/1433":
            attacks.add("MSSQL")
        elif service == "TCP/3306":
            attacks.add("MYSQL")
        elif service == "TCP/5432":
            attacks.add("POSTGRESQL")
        elif service == "TCP/6379":
            attacks.add("REDIS")
        elif service == "TCP/27017":
            attacks.add("MONGODB")
        elif service == "TCP/9200":
            attacks.add("ELASTICSEARCH")

    return sorted(attacks)


def update_history(ip_profiles: dict) -> dict:
    history = load_history()
    now = datetime.now().isoformat(timespec="seconds")

    for ip, profile in ip_profiles.items():
        score, reasons = calculate_threat_score(ip, profile)
        recommendation = classify_score(score)
        attack_fingerprint = get_attack_fingerprint(profile)

        item = history.setdefault(
            ip,
            {
                "first_seen": now,
                "last_seen": now,
                "runs_seen": 0,
                "total_drops": 0,
                "attack_fingerprint": [],
            },
        )

        previous_fingerprint = set(item.get("attack_fingerprint", []))
        previous_fingerprint.update(attack_fingerprint)

        item["last_seen"] = now
        item["runs_seen"] += 1
        item["total_drops"] += profile["total"]
        item["last_score"] = score
        item["last_recommendation"] = recommendation
        item["last_reason"] = reasons[0] if reasons else "bez důvodu"
        item["attack_fingerprint"] = sorted(previous_fingerprint)

    save_history(history)
    return history


def print_history_report(history: dict, limit: int = 20) -> None:
    print()
    print("=" * 60)
    print("History Report")
    print("=" * 60)

    if not history:
        print()
        print("Historie je zatím prázdná.")
        return

    print()
    print("TOP Persistent Attackers")
    print("-" * 60)

    items = sorted(
        history.items(),
        key=lambda item: item[1].get("total_drops", 0),
        reverse=True,
    )

    for ip, data in items[:limit]:
        runs = max(data.get("runs_seen", 1), 1)
        total_drops = data.get("total_drops", 0)
        average = total_drops / runs
        fingerprint = ", ".join(data.get("attack_fingerprint", [])) or "-"

        print()
        print(ip)
        print(f"  First seen     : {data.get('first_seen', '-')}")
        print(f"  Last seen      : {data.get('last_seen', '-')}")
        print(f"  Runs           : {runs}")
        print(f"  Drops          : {total_drops}")
        print(f"  Average        : {average:.1f} drops/run")
        print(f"  Last score     : {data.get('last_score', '-')}/100")
        print(f"  Recommendation : {data.get('last_recommendation', '-')}")
        print(f"  Last reason    : {data.get('last_reason', '-')}")
        print(f"  Fingerprint    : {fingerprint}")
