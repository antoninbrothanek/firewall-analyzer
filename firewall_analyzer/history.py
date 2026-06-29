import json
from datetime import datetime
from pathlib import Path

STATE_DIR = Path("state")
HISTORY_FILE = STATE_DIR / "ip-history.json"


def load_history() -> dict:
    if not HISTORY_FILE.exists():
        return {}

    with HISTORY_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_history(history: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    with HISTORY_FILE.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, sort_keys=True)


def update_history(ip_profiles: dict) -> dict:
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
    print()
    print("=" * 60)
    print("History Report")
    print("=" * 60)

    if not history:
        print()
        print("Historie je zatím prázdná.")
        return

    print()
    print("TOP IP podle celkového počtu DROP paketů:")
    print()

    items = sorted(
        history.items(),
        key=lambda item: item[1].get("total_drops", 0),
        reverse=True,
    )

    for ip, data in items[:limit]:
        print(
            f"{ip:>18}  "
            f"drops {data.get('total_drops', 0):>8}  "
            f"runs {data.get('runs_seen', 0):>4}  "
            f"first {data.get('first_seen', '-'):<19}  "
            f"last {data.get('last_seen', '-'):<19}"
        )
