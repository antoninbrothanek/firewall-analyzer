from .config import (
    DANGEROUS_SERVICES,
    REVIEW_SERVICES,
    LIKELY_BENIGN_PREFIXES,
)


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
