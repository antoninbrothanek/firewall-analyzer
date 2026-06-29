#!/bin/bash
set -euo pipefail

BAD_IP_FILE="/etc/shorewall/bad.ip"
IPSET_NAME="badlist"

if [ "$#" -ne 1 ]; then
    echo "Použití: $0 <IP_ADRESA>"
    exit 1
fi

IP="$1"

if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "ERROR: Neplatný formát IPv4 adresy: $IP"
    exit 1
fi

IFS='.' read -r A B C D <<< "$IP"

for OCTET in "$A" "$B" "$C" "$D"; do
    if [ "$OCTET" -lt 0 ] || [ "$OCTET" -gt 255 ]; then
        echo "ERROR: Neplatná IPv4 adresa: $IP"
        exit 1
    fi
done

if ! ipset list "$IPSET_NAME" >/dev/null 2>&1; then
    echo "ERROR: ipset '$IPSET_NAME' neexistuje"
    exit 1
fi

if grep -qxF "$IP" "$BAD_IP_FILE"; then
    echo "INFO: $IP už je v $BAD_IP_FILE"
else
    echo "$IP" >> "$BAD_IP_FILE"
    echo "OK: $IP přidána do $BAD_IP_FILE"
fi

ipset add "$IPSET_NAME" "$IP" -exist
echo "OK: $IP přidána do ipsetu $IPSET_NAME"

echo
echo "Kontrola:"
ipset test "$IPSET_NAME" "$IP" || true
