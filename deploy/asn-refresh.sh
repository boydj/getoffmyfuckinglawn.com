#!/usr/bin/env bash
# Download the iptoasn.com ip2asn-combined dataset, validate it, and swap it
# into place atomically. Run by lawn-asn-refresh.service (as user lawn); the
# unit reloads lawn afterwards. Safe to run by hand.
set -euo pipefail

URL="${LAWN_ASN_URL:-https://iptoasn.com/data/ip2asn-combined.tsv.gz}"
DEST="${LAWN_ASN_DEST:-/var/lib/lawn/ip2asn-combined.tsv.gz}"
# The real file is several MB; anything under 1 MB is an error page or a
# truncated download.
MIN_BYTES="${LAWN_ASN_MIN_BYTES:-1000000}"

dir="$(dirname -- "$DEST")"
# Temp file on the same filesystem so the final mv is an atomic rename.
tmp="$(mktemp -- "$dir/.ip2asn.XXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

echo "asn-refresh: downloading $URL"
curl --fail --silent --show-error --location \
	--retry 3 --retry-delay 10 --connect-timeout 20 --max-time 600 \
	--user-agent "lawn-asn-refresh (+https://getoffmyfuckinglawn.com/)" \
	--output "$tmp" -- "$URL"

size="$(stat -c %s -- "$tmp")"
if [ "$size" -lt "$MIN_BYTES" ]; then
	echo "asn-refresh: download is only $size bytes (< $MIN_BYTES); keeping the old file" >&2
	exit 1
fi

if ! gzip -t -- "$tmp"; then
	echo "asn-refresh: download is not valid gzip; keeping the old file" >&2
	exit 1
fi

# Every line is: range_start TAB range_end TAB asn TAB country TAB description.
first="$(gzip -dc -- "$tmp" | head -n 1 || true)"
if [ "$(printf '%s\n' "$first" | awk -F '\t' '{print NF}')" != "5" ]; then
	echo "asn-refresh: unexpected format (first line: ${first:0:120}); keeping the old file" >&2
	exit 1
fi

if [ -f "$DEST" ] && cmp -s -- "$tmp" "$DEST"; then
	echo "asn-refresh: dataset unchanged ($size bytes)"
	exit 0
fi

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$DEST"
trap - EXIT
echo "asn-refresh: installed $DEST ($size bytes)"
