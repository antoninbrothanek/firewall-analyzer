from collections import Counter

from .config import TOP_COUNT, PROFILE_COUNT
from .scoring import calculate_threat_score, classify_score


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
