#!/usr/bin/env bash
# Nightly SQLite backup with VACUUM INTO, keeping the newest 7 backups.
# Run by lawn-backup.service as user lawn. Safe to run by hand (as lawn or
# root) and safe to re-run on the same day: that day's backup is replaced.
set -euo pipefail

DB="${LAWN_DB:-/var/lib/lawn/lawn.db}"
DIR="${LAWN_BACKUP_DIR:-/var/lib/lawn/backups}"
KEEP="${LAWN_BACKUP_KEEP:-7}"

if [ ! -f "$DB" ]; then
	echo "backup: $DB does not exist yet; nothing to do"
	exit 0
fi

mkdir -p -- "$DIR"
day="$(date -u +%Y-%m-%d)"
final="$DIR/lawn-$day.db"
# VACUUM INTO refuses to overwrite, so write to a fresh temp name and rename.
tmp="$DIR/.lawn-$day.$$.tmp"
trap 'rm -f -- "$tmp"' EXIT
rm -f -- "$tmp"

# The path is ours (no quotes possible), so interpolating it into SQL is safe.
case "$tmp" in *"'"*) echo "backup: refusing path with a quote: $tmp" >&2; exit 1 ;; esac

sqlite3 -bail -cmd ".timeout 60000" "$DB" "VACUUM INTO '$tmp';"

check="$(sqlite3 -readonly "$tmp" "PRAGMA quick_check;")"
if [ "$check" != "ok" ]; then
	echo "backup: quick_check failed on the new backup: $check" >&2
	exit 1
fi

chmod 0640 -- "$tmp"
mv -f -- "$tmp" "$final"
trap - EXIT
echo "backup: wrote $final ($(stat -c %s -- "$final") bytes)"

# Rotation: names sort by date, so keep the newest $KEEP.
find "$DIR" -maxdepth 1 -type f -name 'lawn-????-??-??.db' -print \
	| sort -r | tail -n +"$((KEEP + 1))" \
	| while IFS= read -r old; do
		echo "backup: removing $old"
		rm -f -- "$old"
	done
