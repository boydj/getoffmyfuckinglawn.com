#!/usr/bin/env bash
# Download X4BNet's list of datacenter and hosting ASNs (MIT licensed,
# https://github.com/X4BNet/lists_vpn), validate it, and swap it into place
# atomically. `lawn bots` uses it to mark clients on hosting networks; it is
# a hint, never a verdict (VPN users come from hosting networks too). Run by
# lawn-asn-refresh.service (as user lawn) after the ASN dataset. Safe to run
# by hand.
set -euo pipefail

URL="${LAWN_HOSTING_URL:-https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt}"
DEST="${LAWN_HOSTING_DEST:-/var/lib/lawn/hosting-asns.txt}"
# The real list has several hundred ASNs; far fewer means an error page or
# a truncated download.
MIN_ASNS="${LAWN_HOSTING_MIN_ASNS:-200}"

dir="$(dirname -- "$DEST")"
tmp="$(mktemp -- "$dir/.hosting-asns.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

echo "hosting-refresh: downloading $URL"
curl --fail --silent --show-error --location \
	--retry 3 --retry-delay 10 --connect-timeout 20 --max-time 120 \
	--user-agent "lawn-hosting-refresh (+https://getoffmyfuckinglawn.com/)" \
	--output "$tmp" -- "$URL"

# Every useful line is "AS<number>", optionally followed by "# comment".
n="$(grep -cE '^AS[0-9]+([[:space:]]|$)' -- "$tmp" || true)"
if [ "$n" -lt "$MIN_ASNS" ]; then
	echo "hosting-refresh: only $n ASN lines (< $MIN_ASNS); keeping the old file" >&2
	exit 1
fi

if [ -f "$DEST" ] && cmp -s -- "$tmp" "$DEST"; then
	echo "hosting-refresh: list unchanged ($n ASNs)"
	exit 0
fi

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$DEST"
trap - EXIT
echo "hosting-refresh: installed $DEST ($n ASNs)"
