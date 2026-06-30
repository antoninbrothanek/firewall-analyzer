#!/usr/bin/env python3
"""
Firewall Analyzer v1.1-dev
"""

import argparse
from pathlib import Path
import signal
import sys

from firewall_analyzer.config import LOG_FILE, SHOREWALL_RULES
from firewall_analyzer.parser import analyze_log
from firewall_analyzer.shorewall import load_published_services
from firewall_analyzer.history import update_history, print_history_report
from firewall_analyzer.whitelist import load_whitelist
from firewall_analyzer.reports import (
    print_top,
    print_ip_profiles,
    print_service_profiles,
)
from firewall_analyzer.blacklist import print_blacklist_candidates

signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Firewall Analyzer - Shorewall DROP analyzer"
    )

    parser.add_argument(
        "--candidates-only",
        action="store_true",
        help="zobrazí pouze kandidáty blacklistu",
    )

    parser.add_argument(
        "--log-file",
        type=Path,
        default=LOG_FILE,
        help="cesta k analyzovanému logu",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.log_file.exists():
        print(f"Log {args.log_file} neexistuje.")
        sys.exit(1)

    published_services = load_published_services()
    whitelist = load_whitelist()

    try:
        (
            total,
            src_counter,
            dpt_counter,
            proto_counter,
            ip_profiles,
            service_profiles,
        ) = analyze_log(args.log_file)

    except PermissionError:
        print()
        print("Nemám oprávnění číst log.")
        print(f"Spusť: sudo python3 {Path(__file__).name}")
        print()
        sys.exit(1)

    history = update_history(ip_profiles)

    if args.candidates_only:
        print_blacklist_candidates(ip_profiles, whitelist)
        return

    print("=" * 60)
    print("Firewall Analyzer v1.1-dev")
    print("=" * 60)
    print(f"Log soubor : {args.log_file}")
    print(f"Shorewall rules: {SHOREWALL_RULES}")
    print(f"Publikované služby načtené ze Shorewallu: {len(published_services)}")
    print(f"Whitelist sítí: {len(whitelist)}")
    print(f"DROP paketů: {total}")
    print(f"Historie IP : {len(history)} záznamů")

    print_top("TOP zdrojové IP", src_counter)
    print_top("TOP cílové porty", dpt_counter)
    print_top("Protokoly", proto_counter)

    print_ip_profiles(src_counter, ip_profiles, published_services)
    print_service_profiles(service_profiles, published_services)
    print_blacklist_candidates(ip_profiles, whitelist)
    print_history_report(history)


if __name__ == "__main__":
    main()
