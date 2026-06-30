"""
History Engine for Firewall Analyzer.

Udržuje databázi známých útočníků mezi jednotlivými běhy programu.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

STATE_DIR = Path("state")
HISTORY_FILE = STATE_DIR / "ip-history.json"


def load_history() -> dict:
    """
    Načte databázi historie.

    Pokud soubor neexistuje nebo je poškozený,
    vrátí prázdný slovník.
    """

    if not HISTORY_FILE.exists():
        return {}

    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)

    except Exception:
        return {}


def save_history(history: dict) -> None:
    """
    Uloží databázi historie.
    """

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, sort_keys=True)


def update_history(ip_profiles: dict) -> dict:
    """
    Aktualizuje historii z aktuálního běhu analyzátoru.
    """

    history = load_history()
    now = datetime.now().isoformat(timespec="seconds")

    for ip, profile in ip_profiles.items():

        item = history.setdefault(
            ip,
            {
                "first_seen": now,
                "last_seen": now,
                "runs_seen": 0,
                "total_drops": 0,
            },
        )

        item["last_seen"] = now
        item["runs_seen"] += 1
        item["total_drops"] += profile["total"]

    save_history(history)

    return history


def print_history_report(history: dict, limit: int = 20) -> None:
    """
    Vytiskne přehled nejaktivnějších útočníků.
    """

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
        key=lambda item: item[1]["total_drops"],
        reverse=True,
    )

    for ip, data in items[:limit]:

        runs = max(data["runs_seen"], 1)
        average = data["total_drops"] / runs

        print()
        print(ip)
        print(f"  First seen : {data['first_seen']}")
        print(f"  Last seen  : {data['last_seen']}")
        print(f"  Runs       : {runs}")
        print(f"  Drops      : {data['total_drops']}")
        print(f"  Average    : {average:.1f} drops/run")
