#!/usr/bin/env python3
"""
Firewall Analyzer v0.9
"""

import argparse
from pathlib import Path
import signal
import sys

from firewall_analyzer.config import LOG_FILE, SHOREWALL_RULES
from firewall_analyzer.parser import analyze_log
from firewall_analyzer.shorewall import load_published_services
from firewall_analyzer.reports import (
    print_top,
    print_ip_profiles,
    print_service_profiles,
)
from firewall_analyzer.blacklist import print_blacklist_candidates

signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Firewall Analyzer - Shorewall DROP log analyzer"
    )

    parser.add_argument(
        "--candidates-only",
        action="store_true",
        help="zobrazí pouze kandidáty na blacklist",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

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

    if args.candidates_only:
        print_blacklist_candidates(ip_profiles)
        return

    print("=" * 60)
    print("Firewall Analyzer v0.9")
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
