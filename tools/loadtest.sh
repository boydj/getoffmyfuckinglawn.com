#!/usr/bin/env bash
# SPEC section 12 load test: build lawn, start it on a throwaway config, hold
# N slow connections against the maze while sampling its RSS/CPU, then stop it.
#
# Usage: tools/loadtest.sh [conns] [max_conns_global] [max_conns_per_asn] [max_conns_per_ip] [duration]
#   defaults:              5000   5000               200                 20                 60s
#
# Environment:
#   LOADTEST_PORT      server port (default 18080; admin port is +1)
#   LOADTEST_RAMP      ramp-up time (default 10s)
#   LOADTEST_IPS       distinct synthetic X-Forwarded-For clients (default = conns;
#                      set lower, e.g. 100, to exercise the per-IP cap)
#   LOADTEST_ARGS      extra flags for the load tool (e.g. "-max-cpu-pct 60")
#
# To see limits kick in, ask for more connections than the global cap, e.g.
#   tools/loadtest.sh 6000 5000
# and check the "fast (limited)" line: those clients got the page without the
# drip, and there must be zero 5xx.
set -euo pipefail

CONNS=${1:-5000}
GLOBAL=${2:-5000}
PER_ASN=${3:-200}
PER_IP=${4:-20}
DURATION=${5:-60s}
PORT=${LOADTEST_PORT:-18080}
ADMIN_PORT=$((PORT + 1))
RAMP=${LOADTEST_RAMP:-10s}
IPS=${LOADTEST_IPS:-$CONNS}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/lawn-loadtest.XXXXXX")
SERVER_PID=""

cleanup() {
	local rc=$?
	if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill -TERM "$SERVER_PID" 2>/dev/null || true
		for _ in $(seq 1 50); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.1; done
		kill -KILL "$SERVER_PID" 2>/dev/null || true
	fi
	if [[ $rc -ne 0 && -f "$TMP/lawn.log" ]]; then
		echo "--- last 40 lines of server log ---" >&2
		tail -n 40 "$TMP/lawn.log" >&2 || true
	fi
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "building lawn and loadtest..."
(cd "$ROOT" && go build -o "$TMP/lawn" ./cmd/lawn && go build -o "$TMP/loadtest" ./tools/loadtest)

mkdir -p "$TMP/public" "$TMP/ranges"
cat >"$TMP/config.yaml" <<EOF
listen: "127.0.0.1:${PORT}"
admin_listen: "127.0.0.1:${ADMIN_PORT}"
base_url: "http://127.0.0.1:${PORT}"
trusted_proxies: ["127.0.0.1/32"]
server_secret_env: "LAWN_SECRET"
db_path: "${TMP}/lawn.db"
asn_db_path: "${TMP}/no-asn-data.tsv.gz"
public_dir: "${TMP}/public"
corpus_dir: "${ROOT}/corpus"
crawlers_file: "${ROOT}/config/crawlers.yaml"
drip:     { chunk_bytes: 16, interval: 1s, max_duration: 10m }
limits:   { max_conns_global: ${GLOBAL}, max_conns_per_asn: ${PER_ASN}, max_conns_per_ip: ${PER_IP} }
attrib:   { ranges_cache_dir: "${TMP}/ranges" }
EOF

# The server needs one fd per held connection plus headroom.
ulimit -n "$(ulimit -Hn)" 2>/dev/null || true

LAWN_SECRET="loadtest-$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" \
	"$TMP/lawn" serve -config "$TMP/config.yaml" >"$TMP/lawn.log" 2>&1 &
SERVER_PID=$!

echo "waiting for lawn (pid $SERVER_PID) on 127.0.0.1:${PORT}..."
for i in $(seq 1 100); do
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		echo "lawn exited during startup" >&2
		exit 1
	fi
	if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
		break
	fi
	if [[ $i -eq 100 ]]; then
		echo "lawn did not start listening within 10s" >&2
		exit 1
	fi
	sleep 0.1
done

# shellcheck disable=SC2086 # LOADTEST_ARGS is intentionally word-split
"$TMP/loadtest" \
	-url "http://127.0.0.1:${PORT}/lawn/" \
	-conns "$CONNS" -duration "$DURATION" -ramp "$RAMP" \
	-ips "$IPS" -interval 1s \
	-pid "$SERVER_PID" -max-rss-mb 500 -max-cpu-pct 50 \
	${LOADTEST_ARGS:-}
