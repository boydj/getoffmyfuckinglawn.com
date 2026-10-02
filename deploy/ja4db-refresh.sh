#!/usr/bin/env bash
# Download FoxIO's JA4+ signature database (https://ja4db.com), check that it
# looks like the JSON array of signatures it should be, and swap it into place
# atomically. `lawn bots` uses it, privately, to name JA4 fingerprints. Run by
# lawn-asn-refresh.service (as user lawn) after the ASN datasets. Safe to run
# by hand.
set -euo pipefail

URL="${LAWN_JA4DB_URL:-https://ja4db.com/api/download/}"
DEST="${LAWN_JA4DB_DEST:-/var/lib/lawn/ja4db.json}"
# Several hundred signatures at least; far fewer means an error page.
MIN_ENTRIES="${LAWN_JA4DB_MIN_ENTRIES:-200}"

dir="$(dirname -- "$DEST")"
tmp="$(mktemp -- "$dir/.ja4db.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

echo "ja4db-refresh: downloading $URL"
curl --fail --silent --show-error --location \
	--retry 3 --retry-delay 10 --connect-timeout 20 --max-time 300 \
	--max-filesize 268435456 \
	--user-agent "lawn-ja4db-refresh (+https://getoffmyfuckinglawn.com/)" \
	--output "$tmp" -- "$URL"

# A JSON array whose objects carry ja4_fingerprint keys. lawn parses it
# properly; this only refuses obvious error pages and truncation.
first="$(head -c 64 -- "$tmp" | tr -d ' \t\r\n' | head -c 1)"
last="$(tail -c 64 -- "$tmp" | tr -d ' \t\r\n' | tail -c 1)"
n="$({ grep -o '"ja4_fingerprint"' -- "$tmp" || true; } | wc -l)"
if [ "$first" != "[" ] || [ "$last" != "]" ] || [ "$n" -lt "$MIN_ENTRIES" ]; then
	echo "ja4db-refresh: not the expected JSON array (starts '$first', ends '$last', $n entries); keeping the old file" >&2
	exit 1
fi

if [ -f "$DEST" ] && cmp -s -- "$tmp" "$DEST"; then
	echo "ja4db-refresh: database unchanged ($n entries)"
	exit 0
fi

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$DEST"
trap - EXIT
echo "ja4db-refresh: installed $DEST ($n entries)"
