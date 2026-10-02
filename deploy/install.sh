#!/usr/bin/env bash
# Remote half of deploy.sh: runs as root on the host against an unpacked
# bundle. Idempotent and safe to re-run.
#
# Bundle layout (built by deploy.sh):
#   bin/lawn                     static linux/amd64 binary
#   bin/caddy                    lawn's Caddy build (caddy/), linux/amd64
#   templates/                   copy of web/templates
#   corpus/                      *.txt training corpus
#   config/crawlers.yaml
#   config/config.example.yaml
#   deploy/                      units, timers, scripts, Caddyfile
#
# Usage: install.sh BUNDLE_DIR   (env LAWN_DOMAIN optional after first run)
set -euo pipefail

src="${1:?usage: install.sh BUNDLE_DIR}"
if [ "$(id -u)" -ne 0 ]; then
	echo "install: must run as root" >&2
	exit 1
fi

LIB=/usr/local/lib/lawn
BIN=/usr/local/bin/lawn
log() { echo "install: $*"; }

for f in bin/lawn bin/caddy config/crawlers.yaml config/config.example.yaml deploy/host-setup.sh deploy/Caddyfile deploy/torrc; do
	[ -e "$src/$f" ] || { echo "install: bundle is missing $f" >&2; exit 1; }
done

# ---------------------------------------------- units, scripts, Caddyfile
units=(
	lawn.service
	lawn-asn-refresh.service lawn-asn-refresh.timer
	lawn-verify-refresh.service lawn-verify-refresh.timer
	lawn-backup.service lawn-backup.timer
	lawn-reboot-check.service lawn-reboot-check.timer
)
for u in "${units[@]}"; do
	install -m 0644 -o root -g root "$src/deploy/$u" "/etc/systemd/system/$u"
done
install -d -m 0755 "$LIB"
for s in host-setup.sh asn-refresh.sh hosting-refresh.sh ja4db-refresh.sh backup.sh reboot-check.sh patch-status.sh; do
	install -m 0755 -o root -g root "$src/deploy/$s" "$LIB/$s"
done
install -m 0644 -o root -g root "$src/deploy/Caddyfile" "$LIB/Caddyfile"
install -m 0644 -o root -g root "$src/deploy/torrc" "$LIB/torrc"
# Put in place as /usr/bin/caddy by host-setup.sh (before it validates the
# Caddyfile, which needs the ja4 plugin).
install -m 0755 -o root -g root "$src/bin/caddy" "$LIB/caddy"

# Packages, user, dirs, secret, Caddy, sysctl, journald, timers.
"$LIB/host-setup.sh"

# ------------------------------------------------------------- app files
# replace_dir SRC DST: swap a directory's contents in with two renames.
replace_dir() {
	local from="$1" to="$2"
	rm -rf -- "$to.new" "$to.old"
	cp -R -- "$from" "$to.new"
	chown -R root:root "$to.new"
	find "$to.new" -type d -exec chmod 0755 {} +
	find "$to.new" -type f -exec chmod 0644 {} +
	if [ -e "$to" ]; then mv -- "$to" "$to.old"; fi
	mv -- "$to.new" "$to"
	rm -rf -- "$to.old"
}
replace_dir "$src/templates" /opt/lawn/templates
replace_dir "$src/corpus" /opt/lawn/corpus

# crawlers.yaml is repo-managed data: always replaced.
install -m 0640 -o root -g lawn "$src/config/crawlers.yaml" /etc/lawn/crawlers.yaml
# The example is kept alongside for diffing against the live config.
install -m 0640 -o root -g lawn "$src/config/config.example.yaml" /etc/lawn/config.example.yaml

# config.yaml is operator-owned after the first deploy: never clobbered.
if [ ! -e /etc/lawn/config.yaml ]; then
	domain="$(sed -n 's/^LAWN_DOMAIN=//p' /etc/lawn/caddy.env)"
	log "creating /etc/lawn/config.yaml for https://$domain"
	sed "s|^base_url:.*|base_url: \"https://$domain\"|" \
		"$src/config/config.example.yaml" >/etc/lawn/.config.yaml.new
	chown root:lawn /etc/lawn/.config.yaml.new
	chmod 0640 /etc/lawn/.config.yaml.new
	mv -f /etc/lawn/.config.yaml.new /etc/lawn/config.yaml
elif ! cmp -s <(grep -Eo '^[a-z_]+:' "$src/config/config.example.yaml" | sort -u) \
	<(grep -Eo '^[a-z_]+:' /etc/lawn/config.yaml | sort -u); then
	log "NOTE: /etc/lawn/config.yaml top-level keys differ from config.example.yaml;"
	log "      review: diff -u /etc/lawn/config.yaml /etc/lawn/config.example.yaml"
fi

# ---------------------------------------------------------------- binary
install -m 0755 -o root -g root "$src/bin/lawn" "$BIN.new"

# Preflight: the new binary must at least execute on this host (right
# architecture, not truncated) before it replaces the running one. Config or
# runtime problems are caught by the health check below, which rolls back.
if ! out="$(cd /opt/lawn && runuser -u lawn -- "$BIN.new" gen-robots -config /etc/lawn/config.yaml 2>&1)"; then
	rm -f -- "$BIN.new"
	echo "install: new binary failed preflight (lawn gen-robots); nothing changed:" >&2
	echo "$out" >&2
	exit 1
fi

if [ -f "$BIN" ] && ! cmp -s -- "$BIN" "$BIN.new"; then
	cp -p -- "$BIN" "$BIN.prev"
fi
mv -f -- "$BIN.new" "$BIN"

systemctl daemon-reload
systemctl enable --quiet lawn.service
log "restarting lawn (drops in-flight drips; crawlers come back)"
systemctl restart lawn.service

# ---------------------------------------------------------- health check
healthy() {
	local _
	for _ in $(seq 1 30); do
		# Quiet: the first attempts race the service start.
		if curl -fs --max-time 2 -o /dev/null http://127.0.0.1:8080/healthz; then
			return 0
		fi
		sleep 1
	done
	return 1
}

if ! healthy; then
	echo "install: lawn failed its health check; recent logs:" >&2
	journalctl -u lawn.service -n 50 --no-pager >&2 || true
	if [ -f "$BIN.prev" ]; then
		echo "install: rolling back to $BIN.prev" >&2
		cp -p -- "$BIN.prev" "$BIN.new"
		mv -f -- "$BIN.new" "$BIN"
		systemctl restart lawn.service
		healthy && echo "install: previous binary is serving again" >&2
	fi
	exit 1
fi
log "lawn is healthy on 127.0.0.1:8080"

systemctl reload caddy.service

# Through Caddy with TLS. Non-fatal: certificates only arrive once the
# domain's nameservers point at this host's DNS records.
domain="$(sed -n 's/^LAWN_DOMAIN=//p' /etc/lawn/caddy.env)"
if err="$(curl -fsS --max-time 10 -o /dev/null --resolve "$domain:443:127.0.0.1" "https://$domain/healthz" 2>&1)"; then
	log "https://$domain/healthz OK through Caddy"
else
	log "WARNING: https://$domain/healthz not reachable through Caddy yet: ${err#curl: }"
	log "         Usually the certificate is still pending (nameservers not delegated yet, or"
	log "         Caddy is backing off after earlier failures). Check: journalctl -u caddy -n 50"
	log "         Once DNS resolves to this host: systemctl restart caddy"
fi

systemctl list-timers --no-pager 'lawn-*' || true
log "done"
