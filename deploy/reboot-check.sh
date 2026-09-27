#!/usr/bin/env bash
# Reboot the host when it needs it. Run daily inside the maintenance window by
# lawn-reboot-check.timer, as a backstop to unattended-upgrades' own
# Automatic-Reboot. Reboots when either:
#   - a package asked for one (/run/reboot-required), or
#   - a newer kernel is installed than the one running.
# If a reboot for a given kernel did not take effect (the bootloader keeps
# picking an older one), it logs an error and fails instead of rebooting
# every day.
set -euo pipefail

state="${STATE_DIRECTORY:-/var/lib/lawn-reboot-check}"
boot="${BOOT_DIR:-/boot}" # overridable for testing
run="${RUN_DIR:-/run}"
mkdir -p -- "$state"
log() { echo "reboot-check: $*"; }

running="$(uname -r)"
newest="$(find "$boot" -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null |
	sed 's/^vmlinuz-//' | sort -V | tail -n 1)"

reason=""
if [ -e "$run/reboot-required" ]; then
	pkgs="$(tr '\n' ' ' <"$run/reboot-required.pkgs" 2>/dev/null || true)"
	reason="reboot required by packages: ${pkgs:-unknown}"
elif [ -n "$newest" ] && [ "$newest" != "$running" ]; then
	if [ "$(cat -- "$state/kernel-target" 2>/dev/null || true)" = "$newest" ]; then
		log "ERROR: already rebooted once for kernel $newest but still running $running;" \
			"check the bootloader default. Not rebooting again."
		exit 1
	fi
	echo "$newest" >"$state/kernel-target"
	reason="kernel $newest is installed but $running is running"
fi

if [ -z "$reason" ]; then
	rm -f -- "$state/kernel-target"
	log "no reboot needed (kernel $running)"
	exit 0
fi

log "rebooting: $reason"
systemctl reboot --no-block
