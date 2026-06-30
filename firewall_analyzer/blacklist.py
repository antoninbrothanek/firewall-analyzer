from .scoring import calculate_threat_score, classify_score
from .whitelist import is_whitelisted

MIN_DROPS_FOR_BLACKLIST = 10


def collect_blacklist_candidates(
    ip_profiles: dict,
    whitelist: list | None = None,
) -> list[tuple[str, int, str, int]]:
    candidates = []
    whitelist = whitelist or []

    for ip, profile in ip_profiles.items():
        if is_whitelisted(ip, whitelist):
            continue

        score, reasons = calculate_threat_score(ip, profile)
        recommendation = classify_score(score)

        if recommendation != "BAN":
            continue

        if profile["total"] < MIN_DROPS_FOR_BLACKLIST:
            continue

        main_reason = reasons[0] if reasons else "bez důvodu"
        candidates.append((ip, score, main_reason, profile["total"]))

    candidates.sort(key=lambda item: (item[1], item[3]), reverse=True)
    return candidates


def print_blacklist_candidates(
    ip_profiles: dict,
    whitelist: list | None = None,
) -> None:
    candidates = collect_blacklist_candidates(ip_profiles, whitelist)

    print()
    print("=" * 60)
    print("Blacklist Candidates")
    print("=" * 60)

    if not candidates:
        print()
        print("Žádní kandidáti k ručnímu zabanování.")
        return

    print()
    print(
        f"Kandidáti mají Threat Score = BAN a alespoň "
        f"{MIN_DROPS_FOR_BLACKLIST} DROP paketů."
    )
    print()
    print("Whitelistované IP/sítě jsou z kandidátů vynechány.")
    print()
    print("Ruční přidání:")
    print("  sudo ./scripts/add-to-badlist.sh <IP>")
    print()

    print(f"{'IP':>18}  {'Score':>7}  {'Drops':>8}  Důvod")
    print("-" * 78)

    for ip, score, reason, total in candidates:
        print(
            f"{ip:>18}  "
            f"{score:>3}/100  "
            f"{total:>8}  "
            f"{reason}"
        )
