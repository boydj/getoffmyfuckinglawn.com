# getoffmyfuckinglawn.com

A tarpit for AI scrapers that ignore `robots.txt`, plus a factual wall of shame.

`robots.txt` says one thing: stay out of `/lawn/`. Anything that goes in anyway gets an endless maze of generated pages, trickled out 16 bytes a second for up to 10 minutes per page. Every request is logged, and violators are attributed (verified crawler, spoofed user agent, unverifiable claim, or anonymous by ASN). The results are published as a static, no-JS leaderboard, a JSON feed, and a plain-text blocklist.

Clients that respect `robots.txt`, search engines included, are never trapped and never shamed.

- **Spec:** [SPEC.md](SPEC.md) is the source of truth.
- **Decisions:** [DECISIONS.md](DECISIONS.md) logs every choice the spec didn't dictate, and every deviation.

## How it works

| Path | What |
|---|---|
| `/` | Homepage, methodology (`/#methodology`), hidden `rel="nofollow"` bait links into `/lawn/` |
| `/robots.txt` | `User-agent: *` / `Disallow: /lawn/`, with every fetch logged |
| `/sitemap.xml` | A few `/lawn/` entry URLs as bait |
| `/lawn/*` | The maze. Each hit is a violation |
| `/shame/`, `/shame/org/<slug>/` | Static leaderboard and per-org pages, rebuilt every 5 min |
| `/shame/feed.json`, `/shame/blocklist.txt` | Machine-readable offenders; CIDRs of verified and spoofing offenders |
| `/healthz` | `ok` |
| `/metrics` | Prometheus text, **admin listener only** (`127.0.0.1:9090`) |

**The maze pages**
- Pages are deterministic: a ChaCha8 PRNG is seeded with `HMAC-SHA256(secret, path)`.
- Text comes from an order-2 Markov chain trained on three public-domain Project Gutenberg novels in `corpus/`.
- Each page is 2–8 KB, with 3–8 paragraphs and 10–20 links to deeper `/lawn/<token>` URLs. The token encodes the depth.

**The drip.** Headers go out immediately. The body follows in 16-byte chunks every second (±30% jitter), flushed each time, until 10 minutes have passed; then the rest goes out at once.

**Limits**
- Beyond 5000 connections in total, 200 per ASN, or 20 per IP, pages are served fast instead of dripped, and still logged. Load shedding never returns a 5xx.
- A daily egress cap switches `/lawn/*` to a tiny static page until UTC midnight.

**The hot path** never blocks on SQLite or DNS. Logging goes through a buffered channel to a batched SQLite (WAL) writer. Crawler verification (reverse DNS with forward confirmation, or vendor-published IP ranges) runs in a background worker pool, and results are cached in `identities` for 7 days.

**Publication rules** (SPEC.md §8, fixed)
- Pages state only facts: org or ASN, UA, disallowed-fetch count, time held.
- Individual IPs are shown **only** for verified corporate crawlers; everything else is shown as the ASN plus a /24 or /48 at most.
- `unverifiable` and `anonymous` are never presented as confirmed.

## Repository layout

```
cmd/lawn/            CLI: serve, build-shame, verify-refresh, stats, gen-robots
internal/app/        wiring, background loops, end-to-end integration test
internal/config/     config.yaml loader + LAWN_* env overrides
internal/maze/       Markov chain, page generator, token/depth scheme
internal/drip/       slow writer, connection limiter, egress accounting
internal/logstore/   SQLite schema/migrations, batched writer, sessions, retention rollup
internal/attrib/     ASN table, crawler UA matching, rDNS + IP-range verification
internal/shame/      aggregation, templates rendering, feed, blocklist, IP display rule
internal/server/     routing, trusted-proxy client IP, timeouts, metrics, homepage
web/templates/       homepage, shared partials, shame templates (embedded in the binary)
corpus/              public-domain training texts
config/              config.example.yaml, crawlers.yaml
infra/               OpenTofu: Vultr instance, firewall, DNS, SSH key, cloud-init
deploy/              systemd units + timers, Caddyfile, host setup / deploy scripts
tools/               load test
.github/workflows/   CI (lint, test, build, tofu validate) and manual deploy
```

## Local development

You need Go (the version in `go.mod`; `GOTOOLCHAIN=auto` fetches it) and `staticcheck` (`go install honnef.co/go/tools/cmd/staticcheck@latest`). OpenTofu is needed only for `make validate`/`plan`.

```sh
make test        # unit + integration tests (-race)
make vet         # go vet + staticcheck
make lint        # vet + gofmt + shellcheck + tofu fmt
make validate    # tofu fmt -check + tofu validate (no credentials needed)
make run         # serve on 127.0.0.1:8080 (admin :9090) with throwaway state in data/dev
make loadtest    # 5000 slow connections against a local server; see tools/loadtest.sh
```

`make run` uses no ASN file, so ASN attribution is off locally. For a quick walk through the maze:

```sh
curl -s localhost:8080/sitemap.xml | grep -o '/lawn/[^<]*' | head -1   # a bait URL
curl -sN localhost:8080/lawn/<token>                                   # watch it drip
curl -s localhost:9090/metrics | grep ^lawn_
```

### CLI

Every command takes `-config <path>`. The default is `$LAWN_CONFIG`, then `/etc/lawn/config.yaml` if it exists, then built-in defaults.

```
lawn serve                     # server + shame rebuild ticker + retention + verification workers
lawn build-shame               # one-off leaderboard build into public_dir/shame
lawn verify-refresh            # refetch vendor IP ranges, re-verify stale identities
lawn stats [--since 24h|7d|30d|all] [--limit N]   # top offenders to stdout
lawn gen-robots                # print robots.txt in effect (also validates the config)
```

- **SIGHUP** (`systemctl reload lawn`) reloads the ASN table and `crawlers.yaml`.
- **SIGTERM** shuts down gracefully and drains the log writer.

### Configuration

- `config/config.example.yaml` documents every key; the spec defaults are built in.
- `LAWN_SECRET` (the HMAC key, at least 16 bytes) comes only from the environment, from the variable named by `server_secret_env`.
- Paths, listeners and trusted proxies can be overridden with `LAWN_DB_PATH`, `LAWN_PUBLIC_DIR`, `LAWN_ASN_DB_PATH`, `LAWN_CORPUS_DIR`, `LAWN_CRAWLERS_FILE`, `LAWN_TEMPLATES_DIR`, `LAWN_RANGES_CACHE_DIR`, `LAWN_LISTEN`, `LAWN_ADMIN_LISTEN`, `LAWN_BASE_URL` and `LAWN_TRUSTED_PROXIES` (comma-separated).

`config/crawlers.yaml` lists the known crawlers and how each is verified, with a comment citing the vendor's documentation. Where a vendor publishes no verification method, the entry is `verify: none` with a TODO, and hits carrying that UA are labelled "claimed, unverifiable".

## Deploy

Everything goes through `make`. The target is one dedicated Vultr instance that runs nothing else, because it deliberately attracts abusive traffic.

**What gets built**
- **`infra/`** (OpenTofu, official `vultr/vultr` provider) creates:
  - a Debian 12 `vc2-2c-2gb` instance (2 vCPU / 2 GB, region `ewr` by default, IPv6 on);
  - a firewall group: SSH only from `admin_cidrs`, 80/443 and ICMP from anywhere;
  - your SSH key;
  - a Vultr DNS zone with A/AAAA records for the apex and `www`;
  - `LAWN_SECRET`, generated once with `random_password`.
- **cloud-init** (first boot):
  - writes the `deploy/` units, scripts and Caddyfile;
  - puts the secret in `/etc/lawn/env`;
  - runs `deploy/host-setup.sh`, which installs Caddy (official apt repo), sqlite3, unattended-upgrades and needrestart, creates the `lawn` user and directories, caps journald, tunes socket sysctls, enables the timers, and downloads the iptoasn.com ASN dataset.
- **`make deploy`**
  - cross-compiles a static linux/amd64 binary and ships it, the templates, the corpus, `crawlers.yaml` and the `deploy/` files over one SSH connection;
  - re-runs the idempotent host setup, preflights the new binary, swaps it in atomically and restarts;
  - health-checks the service and rolls back to the previous binary if the check fails.

### First-time setup

Prerequisites: OpenTofu ≥ 1.8, Go, `make`, `ssh`, `tar`, and a Vultr account with an API key (Account → API; allow your IP in the key's access control).

```sh
# 1. Inputs: SSH public key path and your admin CIDR(s).
cp infra/terraform.tfvars.example infra/terraform.tfvars
$EDITOR infra/terraform.tfvars
export VULTR_API_KEY=...            # environment only, never a file in the repo

# 2. Server, firewall, SSH key, DNS zone.
make plan                           # optional review
make infra                          # tofu init + apply; prints ipv4, ipv6, nameservers, ssh

# 3. At your registrar: set the domain's nameservers to ns1.vultr.com and ns2.vultr.com.
#    This is the only manual step. Caddy obtains certificates once DNS resolves.

# 4. Ship the app (DEPLOY_HOST and LAWN_DOMAIN default to the tofu outputs).
make deploy

# 5. Verify.
curl -sI https://getoffmyfuckinglawn.com/
curl -s  https://getoffmyfuckinglawn.com/robots.txt
curl -sN https://getoffmyfuckinglawn.com/lawn/x | head -c 64     # arrives ~16 bytes/s
make ssh    # then: systemctl status lawn caddy; systemctl list-timers 'lawn-*'
```

Cloud-init takes a few minutes after `make infra`; `make ssh` and then `cloud-init status --wait` shows when it's done. The leaderboard appears at `/shame/` after the first rebuild. After the NS change propagates, `systemctl restart caddy` on the host makes Caddy retry certificates immediately.

**Another Debian 12 / Ubuntu 22.04+ host** (not created by OpenTofu):

```sh
make deploy DEPLOY_HOST=203.0.113.10 LAWN_DOMAIN=example.com [DEPLOY_USER=admin SSH_KEY=~/.ssh/id_ed25519]
```

On such a host, `host-setup.sh` generates `LAWN_SECRET` itself if `/etc/lawn/env` is missing, and firewalling SSH is up to you.

### Routine deploys

```sh
make deploy
```

Safe to re-run.
- **Replaced every time:** the binary (the previous one is kept as `lawn.prev`), templates, corpus, `crawlers.yaml`, units, timers, scripts and the Caddyfile.
- **`/etc/lawn/config.yaml`:** created on the first deploy, then never overwritten. The latest example sits next to it as `config.example.yaml`, and the deploy prints a note when the top-level keys drift.
- **`/etc/lawn/env` (the secret):** never touched. Changing the secret changes every maze URL.
- **Restarts:** a restart drops in-flight drips; crawlers come back on their own.

**From GitHub Actions:** run the `deploy` workflow by hand. It needs these secrets:
- `SSH_PRIVATE_KEY`
- `DEPLOY_HOST`
- ideally `SSH_KNOWN_HOSTS` (`ssh-keyscan <ip>` output captured from a trusted network). Without it the workflow trusts the first host key it sees and warns.

SSH is restricted to `admin_cidrs`, which doesn't include GitHub-hosted runners, so add their ranges or use a self-hosted runner.

### Host layout

| Path | What |
|---|---|
| `/usr/local/bin/lawn` (`lawn.prev`) | binary (and the previous one, for rollback) |
| `/etc/lawn/config.yaml` | live config: yours after the first deploy |
| `/etc/lawn/crawlers.yaml` | crawler list (replaced on deploy) |
| `/etc/lawn/env` | `LAWN_SECRET=...`, 0640 root:lawn, written once |
| `/etc/lawn/caddy.env` | `LAWN_DOMAIN=...` for the Caddyfile |
| `/opt/lawn/{corpus,templates}` | app files (WorkingDirectory) |
| `/var/lib/lawn/` | `lawn.db`, `ip2asn-combined.tsv.gz`, `public/`, `ranges/`, `backups/` |

- **Listeners:** the app listens on `127.0.0.1:8080` (site) and `127.0.0.1:9090` (metrics).
- **Caddy** terminates TLS and proxies to `:8080` unbuffered (`flush_interval -1`, no compression, no access log). It redirects `www` to the apex.
- **Service sandbox:** `lawn` runs as an unprivileged, sandboxed systemd service. It can write only under `/var/lib/lawn` and cannot reach the cloud metadata service, which holds the user-data and so the secret.

### Logs and operations

```sh
make logs                                            # journalctl -u lawn -f on the host
make patch-status                                    # pending updates, kernel, reboot needed, failed units
make ssh
lawn stats --since 24h                               # top offenders
systemctl reload lawn                                # re-read ASN table + crawlers.yaml
systemctl start lawn-asn-refresh                     # refresh ASN data now
systemctl start lawn-verify-refresh                  # re-verify identities now
ssh -L 9090:127.0.0.1:9090 root@<ip>                 # then curl localhost:9090/metrics
```

**Timers**
- **Weekly iptoasn.com refresh:** validates gzip, size and format, swaps the file in atomically, then reloads lawn.
- **Daily `lawn verify-refresh`.**
- **Nightly `VACUUM INTO` backup:** `/var/lib/lawn/backups/lawn-YYYY-MM-DD.db`, `quick_check`ed, newest 7 kept.

**Patching and reboots.** The host keeps itself patched:
- **Daily unattended upgrades:** Debian security updates, point releases and `-updates`, plus Caddy from its official repository.
- **needrestart:** restarts any service still using a replaced library (OpenSSL, libc, …) right after each upgrade.
- **Reboots at 04:30 UTC** when an upgrade asks for one. `lawn-reboot-check.timer` runs at 04:45 as a backstop: it also reboots when a newer kernel is installed than the one running. If a reboot didn't switch to the new kernel, it fails the unit instead of rebooting every day.
- A reboot drops in-flight drips for about a minute; `lawn` and Caddy come back on their own.

`make patch-status` shows the current state. `systemctl --failed` on the host surfaces a stuck reboot check.

**The `lawn` binary** is patched by redeploying. CI runs `govulncheck` against the Go toolchain pinned in `go.mod` on every push and weekly, and a new Go vulnerability shows up as a failed scheduled run in GitHub's email. Dependabot opens weekly PRs for Go modules and Actions versions. To patch: bump the `toolchain` line in `go.mod` (or merge the Dependabot PR), then run `make deploy`.

**Retention.** Raw request rows older than `retention.raw_requests_days` (90) are rolled into `daily_aggregates` by the running server.

### Backups and restore

The backups live **on the same box**; copy them off if you care about them (`scp root@<ip>:/var/lib/lawn/backups/lawn-2026-09-26.db .`). To restore:

```sh
systemctl stop lawn
cd /var/lib/lawn && mv lawn.db lawn.db.broken && rm -f lawn.db-wal lawn.db-shm
install -o lawn -g lawn -m 0640 backups/lawn-2026-09-26.db lawn.db
systemctl start lawn
```

### Teardown

```sh
make destroy
```

This deletes the instance (with its database and on-box backups), the firewall group, the SSH key and **the Vultr DNS zone with all its records**. Copy backups off first, then point the domain's nameservers elsewhere at the registrar.

`infra/terraform.tfstate` stays behind until you delete it. It holds `LAWN_SECRET`, so treat it as sensitive.

### Cost and isolation

- **Cost:** check Vultr's current pricing for `vc2-2c-2gb`. Vultr DNS is free, and Vultr automatic backups are off because the box keeps its own.
- **Egress:** capped by `limits.daily_egress_bytes` (5 GiB/day by default, about 150 GB/month).
- **Isolation:** don't co-host anything else on the box or reuse its IP. Only 80/443 and ICMP are open to the world, and password SSH is off.

## Status

Built and tested; never applied to a real Vultr account. See the final section of [DECISIONS.md](DECISIONS.md) for what's untested and the open TODOs.

## License

[MIT](LICENSE). The texts in `corpus/` are public-domain Project Gutenberg works and are not covered by the license.
