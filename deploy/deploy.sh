#!/usr/bin/env bash
# Ship lawn to a host over SSH and (re)start it. Idempotent; safe to re-run.
#
# Usage: deploy/deploy.sh [HOST]
#
# Env:
#   DEPLOY_HOST       target host or IP (or first argument)          required
#   DEPLOY_USER       SSH user; non-root users need passwordless sudo  default root
#   SSH_KEY           private key file                                 optional
#   SSH_PORT          SSH port                                         default 22
#   SSH_KNOWN_HOSTS   known_hosts file to pin the host key; when set,
#                     host key checking is strict. Otherwise
#                     StrictHostKeyChecking=accept-new (trust on first
#                     use, then pinned in ~/.ssh/known_hosts).         optional
#   LAWN_DOMAIN       site domain; required on a host's first deploy
#                     unless cloud-init already wrote it              optional
#   LAWN_BINARY       binary to ship                                   default dist/lawn
#
# The binary must already be built (make deploy does that).
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

DEPLOY_HOST="${1:-${DEPLOY_HOST:-}}"
DEPLOY_USER="${DEPLOY_USER:-root}"
SSH_KEY="${SSH_KEY:-}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KNOWN_HOSTS="${SSH_KNOWN_HOSTS:-}"
LAWN_DOMAIN="${LAWN_DOMAIN:-}"
LAWN_BINARY="${LAWN_BINARY:-$root/dist/lawn}"

die() { echo "deploy: $*" >&2; exit 1; }

[ -n "$DEPLOY_HOST" ] || die "set DEPLOY_HOST (or pass the host as the first argument)"
# These are interpolated into the remote command line, so keep them boring.
[[ "$DEPLOY_HOST" =~ ^[A-Za-z0-9.:-]+$ ]] || die "invalid DEPLOY_HOST: $DEPLOY_HOST"
[[ "$DEPLOY_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid DEPLOY_USER: $DEPLOY_USER"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "invalid SSH_PORT: $SSH_PORT"
if [ -n "$LAWN_DOMAIN" ] && ! [[ "$LAWN_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
	die "invalid LAWN_DOMAIN: $LAWN_DOMAIN"
fi

[ -x "$LAWN_BINARY" ] || die "$LAWN_BINARY not found; run 'make build-linux' first"
for p in web/templates corpus config/crawlers.yaml config/config.example.yaml \
	deploy/install.sh deploy/host-setup.sh deploy/Caddyfile; do
	[ -e "$root/$p" ] || die "missing $p"
done

ssh_opts=(-p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15)
if [ -n "$SSH_KEY" ]; then
	ssh_opts+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi
if [ -n "$SSH_KNOWN_HOSTS" ]; then
	ssh_opts+=(-o "UserKnownHostsFile=$SSH_KNOWN_HOSTS" -o StrictHostKeyChecking=yes)
else
	ssh_opts+=(-o StrictHostKeyChecking=accept-new)
fi

# ------------------------------------------------------------ bundle
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/bin" "$stage/config" "$stage/deploy"
cp -- "$LAWN_BINARY" "$stage/bin/lawn"
cp -R -- "$root/web/templates" "$stage/templates"
cp -R -- "$root/corpus" "$stage/corpus"
cp -- "$root/config/crawlers.yaml" "$root/config/config.example.yaml" "$stage/config/"
cp -- "$root"/deploy/*.service "$root"/deploy/*.timer "$root"/deploy/*.sh "$root/deploy/Caddyfile" "$stage/deploy/"

sudo=""
[ "$DEPLOY_USER" = "root" ] || sudo="sudo -n"

# POSIX sh on the far side: unpack to a private temp dir, run install.sh as
# root, always clean up.
remote="set -eu
d=\$(mktemp -d /tmp/lawn-deploy.XXXXXX)
trap 'rm -rf \"\$d\"' EXIT
tar --no-same-owner -xzf - -C \"\$d\"
$sudo env LAWN_DOMAIN='$LAWN_DOMAIN' bash \"\$d/deploy/install.sh\" \"\$d\""

echo "deploy: shipping to $DEPLOY_USER@$DEPLOY_HOST"
# shellcheck disable=SC2029 # $remote is meant to be expanded locally.
COPYFILE_DISABLE=1 tar -C "$stage" -czf - . |
	ssh "${ssh_opts[@]}" "$DEPLOY_USER@$DEPLOY_HOST" "$remote"
echo "deploy: done"
