#!/usr/bin/env bash
# Fetch the JA4 fingerprint table `lawn bots` uses, privately, to name JA4
# fingerprints, check it, and swap it into place atomically. Run by
# lawn-asn-refresh.service (as user lawn) after the ASN datasets. Safe to run
# by hand.
#
# Source: FoxIO's JA4DB closed its public download in May 2026. This is the
# last public snapshot, the CSV export at github.com/Niicolaa/ja4db-export
# (frozen on 2026-05-15; the repository states no licence), pinned to one
# commit so the data cannot change underneath us. It never changes, so the
# weekly run normally reports "unchanged".
set -euo pipefail

COMMIT="${LAWN_JA4DB_COMMIT:-af1618e515f827216c9c0904821a6c0f2575ee3d}"
URL="${LAWN_JA4DB_URL:-https://raw.githubusercontent.com/Niicolaa/ja4db-export/$COMMIT/csv/ja4_fingerprint.csv}"
DEST="${LAWN_JA4DB_DEST:-/var/lib/lawn/ja4db.csv}"
# The snapshot has about 74,500 rows; far fewer means a truncated download.
MIN_ROWS="${LAWN_JA4DB_MIN_ROWS:-10000}"
HEADER='application,library,device,os,user_agent_string,certificate_authority,verified,notes,observation_count,ja4_fingerprint'

dir="$(dirname -- "$DEST")"
tmp="$(mktemp -- "$dir/.ja4db.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

echo "ja4db-refresh: downloading $URL"
curl --fail --silent --show-error --location \
	--retry 3 --retry-delay 10 --retry-all-errors --connect-timeout 20 --max-time 300 \
	--max-filesize 268435456 \
	--user-agent "lawn-ja4db-refresh (+https://getoffmyfuckinglawn.com/)" \
	--output "$tmp" -- "$URL"

first="$(head -n 1 -- "$tmp" | tr -d '\r')"
rows="$(wc -l <"$tmp")"
if [ "$first" != "$HEADER" ] || [ "$rows" -lt "$MIN_ROWS" ]; then
	echo "ja4db-refresh: not the expected CSV (header '${first:0:80}', $rows rows); keeping the old file" >&2
	exit 1
fi

if [ -f "$DEST" ] && cmp -s -- "$tmp" "$DEST"; then
	echo "ja4db-refresh: unchanged ($rows rows)"
	exit 0
fi

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$DEST"
trap - EXIT
echo "ja4db-refresh: installed $DEST ($rows rows)"
