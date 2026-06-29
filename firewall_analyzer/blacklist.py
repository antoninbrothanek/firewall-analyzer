from .scoring import calculate_threat_score, classify_score

#
# Minimální počet DROP paketů,
# aby se IP dostala mezi kandidáty blacklistu.
#
MIN_DROPS_FOR_BLACKLIST = 10


def collect_blacklist_candidates(
    ip_profiles: dict,
) -> list[tuple[str, int, str, int]]:
    """
    Vrátí seznam IP adres doporučených pro blacklist.

    Podmínky:

      • Threat Score = BAN
      • minimálně MIN_DROPS_FOR_BLACKLIST DROP paketů
    """

    candidates = []

    for ip, profile in ip_profiles.items():

        score, reasons = calculate_threat_score(ip, profile)
        recommendation = classify_score(score)

        if recommendation != "BAN":
            continue

        if profile["total"] < MIN_DROPS_FOR_BLACKLIST:
            continue

        main_reason = reasons[0] if reasons else "bez důvodu"

        candidates.append(
            (
                ip,
                score,
                main_reason,
                profile["total"],
            )
        )

    #
    # Nejprve podle skóre,
    # potom podle počtu DROP paketů.
    #
    candidates.sort(
        key=lambda item: (
            item[1],
            item[3],
        ),
        reverse=True,
    )

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
    print(
        f"Kandidáti mají Threat Score = BAN a alespoň "
        f"{MIN_DROPS_FOR_BLACKLIST} DROP paketů."
    )
    print()
    print("Ruční přidání:")
    print("  sudo ./scripts/add-to-badlist.sh <IP>")
    print()

    print(
        f"{'IP':>18}  {'Score':>7}  {'Drops':>8}  Důvod"
    )
    print("-" * 78)

    for ip, score, reason, total in candidates:

        print(
            f"{ip:>18}  "
            f"{score:>3}/100  "
            f"{total:>8}  "
            f"{reason}"
        )
