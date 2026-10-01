#!/usr/bin/env bash
# Idempotent base provisioning for a lawn host (Debian 12; also works on
# Ubuntu 22.04+). Run as root by cloud-init on first boot and by
# deploy/install.sh on every deploy, so a plain Debian box without OpenTofu
# can be brought up with `make deploy` alone.
#
# Expects the systemd units already in /etc/systemd/system and asn-refresh.sh,
# backup.sh, reboot-check.sh, Caddyfile, torrc and caddy (lawn's Caddy build)
# in /usr/local/lib/lawn. On cloud-init's first run, before any deploy, only
# the packaged Caddy is installed.
#
# Env:
#   LAWN_DOMAIN  site domain; written to /etc/lawn/caddy.env when set. Required
#                on the first run unless that file already exists.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "host-setup: must run as root" >&2
	exit 1
fi

export DEBIAN_FRONTEND=noninteractive
# needrestart: only list during this script's own apt runs (no prompts, no
# surprise restarts mid-deploy). Unattended upgrades use conf.d/lawn.conf ('a').
export NEEDRESTART_MODE=l
export HOME="${HOME:-/root}"
LIB=/usr/local/lib/lawn
LAWN_DOMAIN="${LAWN_DOMAIN:-}"

log() { echo "host-setup: $*"; }

# write_if_changed DEST MODE: write stdin to DEST (atomically) only when the
# content differs. Returns 0 if the file changed, 1 if it was already current.
write_if_changed() {
	local dest="$1" mode="$2" tmp
	tmp="$(mktemp -- "$(dirname -- "$dest")/.tmp.XXXXXX")"
	cat >"$tmp"
	if [ -f "$dest" ] && cmp -s -- "$tmp" "$dest"; then
		rm -f -- "$tmp"
		chmod "$mode" -- "$dest"
		return 1
	fi
	chmod "$mode" -- "$tmp"
	mv -f -- "$tmp" "$dest"
	log "wrote $dest"
	return 0
}

installed() {
	[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null || true)" = "install ok installed" ]
}

# ---------------------------------------------------------------- packages
pkgs=(ca-certificates curl gnupg sqlite3 unattended-upgrades needrestart)
missing=()
for p in "${pkgs[@]}"; do
	installed "$p" || missing+=("$p")
done
if [ "${#missing[@]}" -gt 0 ]; then
	log "installing ${missing[*]}"
	apt-get update -q
	apt-get install -y -q --no-install-recommends "${missing[@]}"
fi

# ------------------------------------------------------------------- caddy
# Official Caddy apt repository (https://caddyserver.com/docs/install).
keyring=/usr/share/keyrings/caddy-stable-archive-keyring.gpg
srclist=/etc/apt/sources.list.d/caddy-stable.list
if [ ! -s "$keyring" ]; then
	log "adding Caddy apt signing key"
	tmpkey="$(mktemp)"
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o "$tmpkey"
	gpg --batch --yes --dearmor -o "$keyring" "$tmpkey"
	rm -f -- "$tmpkey"
	chmod o+r "$keyring"
fi
if [ ! -s "$srclist" ]; then
	log "adding Caddy apt repository"
	tmplist="$(mktemp)"
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' -o "$tmplist"
	grep -q '^deb ' "$tmplist" || { echo "host-setup: unexpected Caddy repo list" >&2; exit 1; }
	install -m 0644 "$tmplist" "$srclist"
	rm -f -- "$tmplist"
fi
if ! installed caddy; then
	log "installing caddy"
	apt-get update -q
	apt-get install -y -q caddy
fi

# lawn's own Caddy build (caddy/ in the repo: Caddy plus the JA4 plugin),
# shipped by deploy.sh as $LIB/caddy. Installed the way Caddy documents for
# custom builds of the Debian package: the packaged binary is diverted to
# /usr/bin/caddy.default and alternatives point /usr/bin/caddy at
# /usr/bin/caddy.custom. The package keeps its unit, user and upgrades
# (which now land in caddy.default), and never overwrites our binary, so
# Caddy itself is updated by deploying a newer caddy/go.mod.
caddy_changed=0
if [ -x "$LIB/caddy" ]; then
	if ! dpkg-divert --list /usr/bin/caddy | grep -q 'caddy.default'; then
		log "diverting the packaged caddy binary to /usr/bin/caddy.default"
		dpkg-divert --quiet --divert /usr/bin/caddy.default --rename /usr/bin/caddy
	fi
	if ! cmp -s -- "$LIB/caddy" /usr/bin/caddy.custom; then
		install -m 0755 -o root -g root "$LIB/caddy" /usr/bin/caddy.custom.new
		mv -f -- /usr/bin/caddy.custom.new /usr/bin/caddy.custom
		caddy_changed=1
		log "installed lawn's caddy build: $(/usr/bin/caddy.custom version)"
	fi
	update-alternatives --quiet --install /usr/bin/caddy caddy /usr/bin/caddy.default 10
	update-alternatives --quiet --install /usr/bin/caddy caddy /usr/bin/caddy.custom 50
	update-alternatives --quiet --set caddy /usr/bin/caddy.custom
fi

# ---------------------------------------------------- user and directories
if ! getent passwd lawn >/dev/null; then
	log "creating system user lawn"
	useradd --system --user-group --home-dir /var/lib/lawn --no-create-home \
		--shell /usr/sbin/nologin --comment "lawn tarpit" lawn
fi

install -d -m 0750 -o root -g lawn /etc/lawn
install -d -m 0755 -o root -g root /opt/lawn /opt/lawn/corpus /opt/lawn/templates "$LIB"
install -d -m 0750 -o lawn -g lawn /var/lib/lawn \
	/var/lib/lawn/public /var/lib/lawn/ranges /var/lib/lawn/backups

# ------------------------------------------------------------------ secret
# /etc/lawn/env is normally written by cloud-init from OpenTofu's
# random_password. On a host provisioned some other way, generate one here.
# Never overwritten once present.
envf=/etc/lawn/env
if [ ! -e "$envf" ]; then
	log "no $envf; generating a new LAWN_SECRET"
	(umask 077; printf 'LAWN_SECRET=%s\n' "$(head -c 36 /dev/urandom | base64 | tr -d '\n/+=')" >"$envf")
fi
if ! grep -Eq '^LAWN_SECRET=.{16,}$' "$envf"; then
	echo "host-setup: $envf exists but has no LAWN_SECRET of >= 16 chars; fix it by hand" >&2
	exit 1
fi
chown root:lawn "$envf"
chmod 0640 "$envf"

# ------------------------------------------------------------ caddy config
caddyenv=/etc/lawn/caddy.env
if [ -n "$LAWN_DOMAIN" ]; then
	if ! printf '%s' "$LAWN_DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'; then
		echo "host-setup: invalid LAWN_DOMAIN: $LAWN_DOMAIN" >&2
		exit 1
	fi
	printf 'LAWN_DOMAIN=%s\n' "$LAWN_DOMAIN" | write_if_changed "$caddyenv" 0644 || true
fi
if [ ! -s "$caddyenv" ]; then
	echo "host-setup: $caddyenv missing; run with LAWN_DOMAIN=example.com" >&2
	exit 1
fi

install -d -m 0755 /etc/systemd/system/caddy.service.d
write_if_changed /etc/systemd/system/caddy.service.d/lawn.conf 0644 <<'UNIT' || true
# Managed by lawn host-setup.sh: gives the Caddyfile its {$LAWN_DOMAIN}.
[Service]
EnvironmentFile=/etc/lawn/caddy.env
UNIT

if [ -f "$LIB/Caddyfile" ]; then
	# shellcheck disable=SC1090
	# caddy validate logs JSON to stderr; only show it when validation fails.
	if ! out="$(set -a; . "$caddyenv"; set +a; caddy validate --config "$LIB/Caddyfile" --adapter caddyfile 2>&1)"; then
		echo "host-setup: Caddyfile failed validation:" >&2
		echo "$out" >&2
		exit 1
	fi
	write_if_changed /etc/caddy/Caddyfile 0644 <"$LIB/Caddyfile" || true
fi

# ------------------------------------------------------------ kernel knobs
if write_if_changed /etc/sysctl.d/60-lawn.conf 0644 <<'SYSCTL'; then
# Managed by lawn host-setup.sh: many long-lived slow connections.
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 1048576
# HTTP/3: quic-go (Caddy) wants ~7.5 MB UDP socket buffers.
net.core.rmem_max = 7500000
net.core.wmem_max = 7500000
SYSCTL
	sysctl -q -p /etc/sysctl.d/60-lawn.conf
fi

# ----------------------------------------------------------------- journald
install -d -m 0755 /etc/systemd/journald.conf.d
if write_if_changed /etc/systemd/journald.conf.d/60-lawn.conf 0644 <<'JOURNAL'; then
# Managed by lawn host-setup.sh: cap journal size on a small disk.
[Journal]
Storage=persistent
SystemMaxUse=200M
SystemKeepFree=1G
SystemMaxFileSize=25M
RuntimeMaxUse=50M
MaxRetentionSec=1month
JOURNAL
	systemctl restart systemd-journald
fi

# ------------------------------------------------------ unattended-upgrades
write_if_changed /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'APT' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT
write_if_changed /etc/apt/apt.conf.d/52lawn-unattended-upgrades 0644 <<'APT' || true
// Managed by lawn host-setup.sh. Merged with 50unattended-upgrades; listed
// explicitly so the image's defaults can't silently narrow them.
Unattended-Upgrade::Origins-Pattern {
	// Debian security updates, point releases, and stable-updates (tzdata etc.).
	"origin=Debian,codename=${distro_codename},label=Debian";
	"origin=Debian,codename=${distro_codename},label=Debian-Security";
	"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
	"origin=Debian,codename=${distro_codename}-updates";
	// Caddy from its official Cloudsmith repository.
	"site=dl.cloudsmith.io";
	// Tor from the Tor Project's repository (onion mirror).
	"site=deb.torproject.org";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// Reboot at 04:30 UTC when an upgrade asks for it, even with SSH sessions
// open. lawn-reboot-check.timer (04:45) is the backstop for new kernels.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
APT
# Restart services that still map replaced libraries (OpenSSL, libc, ...)
# right after unattended upgrades, instead of waiting for a reboot.
install -d -m 0755 /etc/needrestart/conf.d
write_if_changed /etc/needrestart/conf.d/lawn.conf 0644 <<'NR' || true
# Managed by lawn host-setup.sh.
$nrconf{restart} = 'a';
$nrconf{kernelhints} = 0;
NR
systemctl enable --quiet unattended-upgrades.service 2>/dev/null || true
systemctl enable --quiet --now apt-daily.timer apt-daily-upgrade.timer

# ------------------------------------------------------------ host firewall
# Vultr's Debian/Ubuntu images ship with ufw enabled and only SSH allowed, so
# the public ports would be dropped on the box even though the Vultr firewall
# group opens them (ACME then fails with "Timeout during connect"). Open the
# same ports as infra/main.tf's public_ports and leave everything else as the
# image set it; SSH is still limited to admin_cidrs by the Vultr firewall
# group. `ufw allow` is idempotent.
public_ports=(80/tcp 443/tcp 443/udp 70/tcp 1965/tcp)
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
	for port in "${public_ports[@]}"; do
		ufw allow "$port" >/dev/null
	done
	log "ufw is active: allowed ${public_ports[*]}"
fi

# ---------------------------------------------------------------------- tor
# The onion mirror (deploy/torrc). Tor from the Tor Project's own repository,
# as they recommend (support.torproject.org/apt/tor-deb-repo/): distribution
# packages lag behind, and the Tor network retires old versions.
# The key URL and fingerprint are the Tor Project's published ones; the
# downloaded key must carry exactly that fingerprint or setup stops.
tor_fpr=A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
tor_keyring=/usr/share/keyrings/deb.torproject.org-keyring.gpg
tor_srclist=/etc/apt/sources.list.d/tor.list
if [ ! -s "$tor_keyring" ]; then
	log "adding Tor Project apt signing key"
	tmpkey="$(mktemp)"
	curl -1sLf "https://deb.torproject.org/torproject.org/$tor_fpr.asc" -o "$tmpkey"
	fprs="$(gpg --batch --show-keys --with-colons "$tmpkey" 2>/dev/null || true)"
	if ! grep -q "^fpr:::::::::$tor_fpr:" <<<"$fprs"; then
		rm -f -- "$tmpkey"
		echo "host-setup: Tor Project key does not have fingerprint $tor_fpr; refusing it" >&2
		exit 1
	fi
	gpg --batch --yes --dearmor -o "$tor_keyring" "$tmpkey"
	rm -f -- "$tmpkey"
	chmod o+r "$tor_keyring"
fi
# shellcheck disable=SC1091
codename="$(. /etc/os-release && echo "${VERSION_CODENAME:?}")"
if printf 'deb [signed-by=%s] https://deb.torproject.org/torproject.org %s main\n' "$tor_keyring" "$codename" |
	write_if_changed "$tor_srclist" 0644; then
	apt-get update -q
fi
if ! installed tor || ! installed deb.torproject.org-keyring; then
	log "installing tor"
	apt-get update -q
	# The keyring package keeps the signing key current from now on.
	apt-get install -y -q tor deb.torproject.org-keyring
fi
# tor creates this itself, but create it first with tor's ownership so the
# root-run config check below can never leave it owned by root.
install -d -m 0700 -o debian-tor -g debian-tor /var/lib/tor/lawn
if [ -f "$LIB/torrc" ]; then
	if ! out="$(tor --verify-config --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f "$LIB/torrc" 2>&1)"; then
		echo "host-setup: torrc failed validation:" >&2
		echo "$out" >&2
		exit 1
	fi
	if write_if_changed /etc/tor/torrc 0644 <"$LIB/torrc"; then
		# Single onion mode can't be toggled by a reload.
		systemctl restart tor@default.service
	fi
fi
# tor.service is the enable-able umbrella; Debian's tor-generator hangs the
# tor@default instance (which reads /etc/tor/torrc) off it.
systemctl enable --quiet --now tor.service
systemctl start tor@default.service

# Hand the onion address to the app (sitemap links, Onion-Location). tor
# writes it on first start; allow it a moment.
hostf=/var/lib/tor/lawn/hostname
for _ in $(seq 1 30); do
	[ -s "$hostf" ] && break
	sleep 1
done
if [ -s "$hostf" ]; then
	onion="$(tr -d '[:space:]' <"$hostf")"
	if ! printf '%s' "$onion" | grep -Eq '^[a-z2-7]{56}\.onion$'; then
		echo "host-setup: $hostf does not hold a v3 onion address: $onion" >&2
		exit 1
	fi
	{ grep -v '^LAWN_ONION_ADDRESS=' "$envf" || true; printf 'LAWN_ONION_ADDRESS=%s\n' "$onion"; } |
		write_if_changed "$envf" 0640 || true
	chown root:lawn "$envf"
	log "onion service: http://$onion/"
else
	log "WARNING: tor has not written $hostf yet; the app runs without the onion address until the next deploy (check: journalctl -u tor@default -n 50)"
fi

# ------------------------------------------------------------------ systemd
systemctl daemon-reload
# lawn.service is ConditionPathExists-gated on the binary, so enabling it
# before the first deploy is harmless.
systemctl enable --quiet lawn.service
systemctl enable --quiet --now lawn-asn-refresh.timer lawn-verify-refresh.timer lawn-backup.timer \
	lawn-reboot-check.timer
systemctl enable --quiet caddy.service
if systemctl is-active --quiet caddy.service; then
	# A reload keeps the old binary running; a new build needs a restart
	# (which drops open connections, as restarting lawn does anyway).
	if [ "$caddy_changed" = 1 ]; then
		systemctl restart caddy.service
	else
		systemctl reload caddy.service
	fi
else
	systemctl start caddy.service
fi

# ------------------------------------------------------------- ASN dataset
if [ ! -s /var/lib/lawn/ip2asn-combined.tsv.gz ] || { [ -x "$LIB/hosting-refresh.sh" ] && [ ! -s /var/lib/lawn/hosting-asns.txt ]; }; then
	log "fetching initial ASN datasets"
	systemctl start lawn-asn-refresh.service || log "WARNING: initial ASN download failed; the weekly timer will retry (or: systemctl start lawn-asn-refresh)"
fi

log "done"
