#!/usr/bin/env bash
# One-screen summary of the host's patch state. `make patch-status` runs it
# over SSH; it only reads, never changes anything.
set -uo pipefail

section() { printf '\n== %s\n' "$*"; }

# shellcheck disable=SC1091
. /etc/os-release
running="$(uname -r)"
newest="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null |
	sed 's/^vmlinuz-//' | sort -V | tail -n 1)"

echo "host:     $(hostname) ($PRETTY_NAME)"
echo "uptime:   $(uptime -p) (since $(uptime -s))"
echo "kernel:   running $running, newest installed ${newest:-unknown}"
if [ -e /run/reboot-required ]; then
	echo "reboot:   REQUIRED by $(tr '\n' ' ' </run/reboot-required.pkgs 2>/dev/null || echo unknown)"
elif [ -n "$newest" ] && [ "$newest" != "$running" ]; then
	echo "reboot:   REQUIRED (newer kernel installed)"
else
	echo "reboot:   not required"
fi
echo "lawn:     $(/usr/local/bin/lawn version 2>/dev/null || echo 'not installed')"

section "pending upgrades (as of the last apt update)"
pending="$(apt list --upgradable 2>/dev/null | tail -n +2)"
echo "${pending:-none}"

section "recent unattended-upgrades activity"
log=/var/log/unattended-upgrades/unattended-upgrades.log
if [ -r "$log" ]; then
	grep -hE 'Packages that will be upgraded|No packages found|All upgrades installed|ERROR' "$log" |
		tail -n 6
else
	echo "no log yet ($log)"
fi

section "services running outdated libraries"
svcs="$(needrestart -b -r l 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p')"
echo "${svcs:-none}"

section "timers"
systemctl list-timers --no-pager apt-daily.timer apt-daily-upgrade.timer 'lawn-*'

section "failed units"
failed="$(systemctl --failed --no-pager --no-legend)"
echo "${failed:-none}"
