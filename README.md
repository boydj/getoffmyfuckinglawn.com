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
| `/shame/well-behaved/`, `/shame/well-behaved.json` | Crawlers that read `robots.txt` and have never entered `/lawn/` |
| `/healthz` | `ok` |
| `/metrics` | Prometheus text, **admin listener only** (`127.0.0.1:9090`) |

**Protocols.** The same rule and the same maze are served over every protocol, and every request is logged with how it arrived (the `scheme` column, plus `proto` for the HTTP version):

| Where | How |
|---|---|
| `https://` (TCP 443, HTTP/1.1 and HTTP/2; UDP 443, HTTP/3) | Caddy with Let's Encrypt, advertising HTTP/3 with `Alt-Svc` |
| `http://` (TCP 80) | Caddy passes every plain-HTTP request to the app, which logs it, serves `/robots.txt` and `/lawn/` as over HTTPS, and redirects everything else to HTTPS with a 301. Bare-IP scanners on port 80 are logged too |
| `http://<onion>` (Tor) | See [Tor onion mirror](#tor-onion-mirror) |
| `gopher://` (TCP 70) | Served by `lawn` itself (RFC 1436). Root menu, `robots.txt`, and the maze as gopher menus with text in info lines |
| `gemini://` (TCP 1965, TLS) | Served by `lawn` itself, with a self-signed certificate kept in `/var/lib/lawn/gemini` (Gemini clients pin it on first use). Root page, `/robots.txt`, and the maze as gemtext |

A page has the same title, links, anchors and text in every format, so the maze is one maze. Gopher and Gemini maze responses are dripped like HTTP ones, links first, with the same limits and adaptive budget. Over a limit, Gopher gets an error item and Gemini a `44 60` (slow down). Gopher and Gemini have no user agent, so `lawn bots` groups such clients as "(gopher client)" and "(gemini client)". Like browsers, they need a bot signal (fetching `robots.txt`, entering `/lawn/`) to be listed.

**The maze pages**
- Pages are deterministic: a ChaCha8 PRNG is seeded with `HMAC-SHA256(secret, path)`.
- Text comes from an order-2 Markov chain trained on three public-domain Project Gutenberg novels in `corpus/`.
- Each page is 2–8 KB, with 3–8 paragraphs and 10–20 links to deeper `/lawn/<token>` URLs. The token encodes the depth.

**The drip.** Headers and the page's link block go out immediately. The rest of the body follows in 16-byte chunks every second (±30% jitter), flushed each time, until the client's budget runs out; then the rest goes out at once.
- **Budget:** 10 minutes for a client never seen giving up.
- **Adaptive:** once a client (ASN, or /24 or /48 when the ASN is unknown, plus user agent) has hung up after *t* seconds, its later pages finish at 0.8 × *t*. A crawler with a 30 s timeout then gets complete pages in about 24 s and keeps following links deeper, instead of timing out at depth 0 on every page.

**Limits**
- Beyond 5000 connections in total, 200 per ASN, or 20 per IP, pages are served fast instead of dripped, and still logged. Load shedding never returns a 5xx.

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
caddy/               lawn's Caddy build (own Go module): Caddy + JA4 TLS fingerprint plugin
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
make run         # serve on 127.0.0.1:8080 (admin :9090, gopher :7070, gemini :1965) with throwaway state in data/dev
make loadtest    # 5000 slow connections against a local server; see tools/loadtest.sh
make crawlers-check  # compare config/crawlers.yaml with public catalogues of vendor IP lists (leads only)
```

`make run` uses no ASN file, so ASN attribution is off locally. For a quick walk through the maze:

```sh
curl -s localhost:8080/sitemap.xml | grep -o '/lawn/[^<]*' | head -1   # a bait URL
curl -sN localhost:8080/lawn/<token>                                   # watch it drip
curl -s localhost:9090/metrics | grep ^lawn_
printf '/robots.txt\r\n' | nc localhost 7070                              # gopher
printf 'gemini://localhost/\r\n' | openssl s_client -quiet -connect localhost:1965 2>/dev/null   # gemini
```

### CLI

Every command takes `-config <path>`. The default is `$LAWN_CONFIG`, then `/etc/lawn/config.yaml` if it exists, then built-in defaults.

```
lawn serve                     # server + shame rebuild ticker + retention + verification workers
lawn build-shame               # one-off leaderboard build into public_dir/shame
lawn verify-refresh            # refetch vendor IP ranges, re-verify stale identities
lawn stats [--since 24h|7d|30d|all] [--limit N]   # top offenders to stdout
lawn gen-robots                # print robots.txt in effect (also validates the config)
lawn bots [--since 7d|36h|all] [--unknown] [--new] [--all] [--limit N] [--details N]
                               # private report on every bot seen, compliant or not
lawn visitors [--since 24h|7d|all] [--limit N] [--ip ADDR|CIDR] [--asn N] [--ua TEXT]
              [--path PREFIX] [--scheme https|http|gopher|gemini] [--lawn] [--operators]
                               # private per-request log, newest first; --ip ADDR = one client's timeline
```

- **SIGHUP** (`systemctl reload lawn`) reloads the ASN table, `crawlers.yaml` and `exclude_cidrs` from `config.yaml`. Other `config.yaml` changes need a restart.
- **SIGTERM** shuts down gracefully and drains the log writer.

### Configuration

- `config/config.example.yaml` documents every key; the spec defaults are built in.
- `LAWN_SECRET` (the HMAC key, at least 16 bytes) comes only from the environment, from the variable named by `server_secret_env`.
- Paths, listeners and trusted proxies can be overridden with `LAWN_DB_PATH`, `LAWN_PUBLIC_DIR`, `LAWN_ASN_DB_PATH`, `LAWN_CORPUS_DIR`, `LAWN_CRAWLERS_FILE`, `LAWN_TEMPLATES_DIR`, `LAWN_RANGES_CACHE_DIR`, `LAWN_LISTEN`, `LAWN_ADMIN_LISTEN`, `LAWN_BASE_URL`, `LAWN_TRUSTED_PROXIES` and `LAWN_EXCLUDE_CIDRS` (both comma-separated).
- **`exclude_cidrs`** lists your own networks. Visits from them are still logged, but left out of the wall, the well-behaved page, the feed, the blocklist, `lawn stats` and `lawn bots`. `lawn visitors` hides them unless you pass `--operators`, which shows them marked `*`. The filter is applied when reports are built, so adding a network also removes its past visits; removing it brings them back. SSH `admin_cidrs` is deliberately not copied in: it can hold shared addresses (an airline's, a café's), and excluding those would hide strangers too.

`config/crawlers.yaml` lists the known crawlers and how each is verified, with a comment citing the vendor's documentation. Where a vendor publishes no verification method, the entry is `verify: none` with a TODO, and hits carrying that UA are labelled "claimed, unverifiable".

## Deploy

Everything goes through `make`. The target is one dedicated Vultr instance that runs nothing else, because it deliberately attracts abusive traffic.

**What gets built**
- **`infra/`** (OpenTofu, official `vultr/vultr` provider) creates:
  - a Debian 12 `vc2-2c-2gb` instance (2 vCPU / 2 GB, region `ewr` by default, IPv6 on);
  - a firewall group: SSH only from `admin_cidrs`; from anywhere, TCP 80, 443, 70 (Gopher) and 1965 (Gemini), UDP 443 (HTTP/3) and ICMP;
  - your SSH key;
  - a Vultr DNS zone with A/AAAA records for the apex and `www`;
  - `LAWN_SECRET`, generated once with `random_password`.
- **cloud-init** (first boot):
  - writes the `deploy/` units, scripts and Caddyfile;
  - puts the secret in `/etc/lawn/env`;
  - runs `deploy/host-setup.sh`, which installs Caddy (official apt repo), Tor (the Tor Project's apt repo, signing key pinned by fingerprint), sqlite3, unattended-upgrades and needrestart, creates the `lawn` user and directories, caps journald, tunes socket sysctls, enables the timers, and downloads the iptoasn.com ASN dataset.
- **`make deploy`**
  - cross-compiles static linux/amd64 binaries of lawn and of lawn's Caddy build (`caddy/`, Caddy plus the JA4 plugin) and ships them, the templates, the corpus, `crawlers.yaml` and the `deploy/` files over one SSH connection;
  - installs that Caddy in place of the packaged binary, the way Caddy documents for custom builds: `dpkg-divert` moves the package's binary to `/usr/bin/caddy.default`, and `update-alternatives` points `/usr/bin/caddy` at `/usr/bin/caddy.custom`. The package keeps its unit and user;
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
- **Replaced every time:** the binary (the previous one is kept as `lawn.prev`), templates, corpus, `crawlers.yaml`, units, timers, scripts and the Caddyfile. Caddy is restarted (not reloaded) when its binary changed.
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
| `/var/lib/lawn/` | `lawn.db`, `ip2asn-combined.tsv.gz`, `hosting-asns.txt`, `public/`, `ranges/`, `backups/` |
| `/usr/bin/caddy.custom` | lawn's Caddy build (`/usr/bin/caddy` points here; the packaged binary is `caddy.default`) |

- **Listeners:** the app listens on `127.0.0.1:8080` (site) and `127.0.0.1:9090` (metrics).
- **Caddy** terminates TLS and proxies to `:8080` unbuffered (`flush_interval -1`, no compression, no access log). It redirects `www` to the apex. Its `ja4` listener wrapper records each TCP connection's TLS ClientHello, and the `ja4` directive passes the [JA4 fingerprint](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) to the app as `X-Lawn-Client-JA4` (stored in `requests.ja4`; HTTP/3 requests have none).
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
ssh -L 9090:127.0.0.1:9090 root@<ip>                 # then open http://localhost:9090/ (see below)
lawn visitors --since 24h                            # every recent visit, newest first
lawn visitors --lawn --since 7d                      # every maze hit this week
lawn visitors --ip 198.51.100.9 --since all          # one client's full timeline
```

**Viewing the maze without being logged.** The admin listener (`admin_listen`, localhost only) also serves the maze: `/lawn/...` renders exactly what the public site would, all at once, with no drip, no limits and no log row. Open an SSH tunnel with `ssh -L 9090:127.0.0.1:9090 root@<ip>` and browse `http://localhost:9090/`. That page lists the sitemap's entry points, and the links on each maze page keep working. `/metrics` is on the same port. Browsing the public site from your own networks is fine too once they are in `exclude_cidrs`.

**Timers**
- **Weekly iptoasn.com refresh:** validates gzip, size and format, swaps the file in atomically, then reloads lawn. The same unit then fetches [X4BNet's datacenter ASN list](https://github.com/X4BNet/lists_vpn) (MIT) into `hosting-asns.txt` for `lawn bots`; a failed download keeps the old file.
- **Daily `lawn verify-refresh`.**
- **Nightly `VACUUM INTO` backup:** `/var/lib/lawn/backups/lawn-YYYY-MM-DD.db`, `quick_check`ed, newest 7 kept.

**Patching and reboots.** The host keeps itself patched:
- **Daily unattended upgrades:** Debian security updates, point releases and `-updates`. The Caddy package still updates, but the binary that runs is lawn's own build, so Caddy is patched by redeploying (below).
- **needrestart:** restarts any service still using a replaced library (OpenSSL, libc, …) right after each upgrade.
- **Reboots at 04:30 UTC** when an upgrade asks for one. `lawn-reboot-check.timer` runs at 04:45 as a backstop: it also reboots when a newer kernel is installed than the one running. If a reboot didn't switch to the new kernel, it fails the unit instead of rebooting every day.
- A reboot drops in-flight drips for about a minute; `lawn` and Caddy come back on their own.

`make patch-status` shows the current state. `systemctl --failed` on the host surfaces a stuck reboot check.

**The `lawn` and Caddy binaries** are patched by redeploying. CI runs `govulncheck` on both modules (the app and `caddy/`) against the pinned Go toolchain on every push and weekly, and a new vulnerability shows up as a failed scheduled run in GitHub's email. Dependabot opens PRs for both modules' Go dependencies, Caddy included (daily), and Actions versions (weekly). To patch: bump the `toolchain` line in `go.mod`/`caddy/go.mod` (or merge the Dependabot PR), then run `make deploy`.

**Why requests ended.** Every `/lawn/` row records an `end_reason`:
- `complete`: dripped to the end.
- `cutoff`: budget reached, remainder sent at once.
- `client_gone`: the client hung up.
- `write_error`
- `shed`: over a connection cap.
- `head`

`referer`, `accept`, `accept_language` and `accept_encoding` are stored too, for analysis only; they are never published. Per-crawler summary:

```sh
sqlite3 -readonly /var/lib/lawn/lawn.db "
SELECT substr(user_agent,1,40) ua, end_reason, COUNT(*) n,
       ROUND(AVG(ts_end-ts_start)/1000.0,1) avg_s, ROUND(AVG(bytes_sent)) avg_bytes, MAX(depth) depth
FROM requests WHERE is_violation=1 AND ts_start > (strftime('%s','now')-86400)*1000
GROUP BY 1,2 ORDER BY n DESC LIMIT 30;"
```

`/metrics` also exposes `lawn_drip_end_total{reason=...}` and `lawn_patience_tracked`.

**Spotting new bots (`lawn bots`).** Every visitor is logged and classified, not only violators, and every client IP gets a reverse-DNS lookup. `lawn bots` (private, never published) groups every client that looks automated by the product name in its user agent:
- **What counts as automated:** the UA names a bot or an HTTP library, or the client fetched `robots.txt`, entered `/lawn/`, sent no `Accept-Language`, or has a crawler-looking reverse-DNS name. More signals catch scrapers that claim to be browsers (each is a fact, none alone a verdict):

  | Signal | Weight | What it means |
  |---|---|---|
  | `browser-ua-tls-like-library:<lib>` | 3 | its JA4 TLS fingerprint was also used by an HTTP library (python-requests, Go, curl…) in the same window |
  | `browser-ua-tls-offers-no-h2` | 3 | its TLS ClientHello doesn't offer HTTP/2; every browser does |
  | `browser-ua-no-sec-fetch` | 3 | a browser version that sends `Sec-Fetch-*` to HTTPS sites (Chrome 76+, Edge 79+, Firefox 90+, Safari 16.4+) never did |
  | `follows-links-before-page-ends` | 3 | fetched most of a page's links while that page was still dripping (`OPEN`) |
  | `browser-ua-over-https-http/1.1` | 2 | negotiated HTTP/1.1 although Caddy offers h2 |
  | `fast-maze-walk` | 2 | 30+ maze pages within one minute |
  | `metronome-timing` | 2 | 20+ gaps between maze fetches, evenly spaced (coefficient of variation < 0.25) |
  | `browser-ua-head-requests`, `deep-in-maze` (10+), `mostly-errors` | 1 | supporting |
  | `hosting-network`, `browser-ua-no-favicon` | 1 | supporting only: never list a client on their own (VPN users, cached favicons) |

  The existing signals weigh 3 (UA names a bot or library), 2 (robots.txt, no `Accept-Language`, crawler-looking PTR) and 1 (entered `/lawn/`). `SCORE` adds up a group's signals.
- **Browser-looking UAs** with those signals are grouped by network instead, which is how headless scrapers show up.
- **Each group gets a verdict:** `compliant`, `entered /lawn/`, `read robots.txt, entered /lawn/`, or `never fetched robots.txt`.
- **Flags:** `NEW` for groups first seen in the last 7 days, `UNKNOWN` for groups not in `crawlers.yaml`.
- **`OPEN` column (frontier amplification):** every maze link carries a short id of the page it came from, and each `/lawn/` row logs `page_id` and `parent_id`. `OPEN` is the share of followed links that the same user agent fetched while the parent page was *still dripping*, from any of its IPs. A high share means the crawler harvests links from the leading `<nav>` and fans out, so each held connection spawns more; a low share means it waits for pages to finish. The detail block gives the raw counts.
- **Detail blocks** for unknown and new groups: sample UA, contact URL, reverse-DNS domains, networks, header fingerprint, HTTP/TLS versions, JA4 fingerprints, fastest pace, and a `crawlers.yaml` stub to complete from the vendor's docs.

```sh
lawn bots --since 7d --unknown     # what's new that we don't recognise?
lawn bots --since all              # everything, including rolled-up history
```

**Retention.** Raw request rows older than `retention.raw_requests_days` (90) are rolled into `daily_aggregates` (violators) and `daily_visits` (every visitor) by the running server.

### Tor onion mirror

The whole site is also served as a Tor onion service, set up by `make deploy` with no extra steps. Tor only makes outbound connections, so no firewall change is needed.

- **How it works:** tor (`deploy/torrc`) runs a *single* onion service. The server's location isn't secret, so circuits are 3 hops instead of 6, while visitors stay anonymous. tor hands each connection to Caddy on `127.0.0.1:8081` with a PROXY header naming the client's circuit (`fc00:dead:beef:4dad::<id>`). Caddy proxies to the app like any other request.
- **In the logs:** onion visitors have no IP address. The circuit address is stored in its place, so sessions and per-client limits work per circuit. The network is "Tor onion service" (the reserved AS4294967295), with no country and no reverse DNS. Crawler claims over Tor can't be verified, so they're labelled "claimed, unverifiable". `lawn visitors --asn 4294967295` lists onion traffic.
- **Limits:** all onion traffic shares the per-network caps: 200 connections for the pseudo-ASN, and 50 connections at 10 new maze requests per second for its /48. tor itself allows at most 32 streams per circuit.
- **On the wall:** onion violators and well-behaved onion crawlers appear as one network, "Tor onion service". No circuit ID is ever published, and none goes into the blocklist.
- **Advertising the mirror:** the clearnet home page and wall pages send `Onion-Location`, so Tor Browser offers the mirror. The home page links it. Onion visitors get a sitemap that points at the onion mirror.

```sh
make onion-address      # the mirror's hostname
make keys-backup        # copy its private key and the Gemini certificate off the box to lawn-keys.tar.gz (gitignored; keep it safe)
```

- **The key is the address.** It lives only in `/var/lib/tor/lawn/`, and a rebuilt server gets a new address unless you restore it. The same goes for the Gemini certificate in `/var/lib/lawn/gemini/`: clients that pinned it reject a new one. To restore both on a new box, before the first deploy: `tar -C / -xzf lawn-keys.tar.gz`, then `chown -R debian-tor:debian-tor /var/lib/tor/lawn && chmod 700 /var/lib/tor/lawn` and `chown -R lawn:lawn /var/lib/lawn/gemini`. (A backup made with the older `make onion-backup` holds only the onion key: `tar -C /var/lib/tor -xzf onion-keys.tar.gz`.) Per tor(1), that directory must never be reused for a normal (anonymous) onion service.
- **To turn the mirror off:** `systemctl disable --now tor@default`, then remove `LAWN_ONION_ADDRESS` from `/etc/lawn/env` and `systemctl restart lawn`. The next deploy turns it back on.

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
- **Isolation:** don't co-host anything else on the box or reuse its IP. Only the public service ports (80, 443 over TCP and UDP, 70, 1965) and ICMP are open to the world, and password SSH is off.

## Status

Built and tested; never applied to a real Vultr account. See the final section of [DECISIONS.md](DECISIONS.md) for what's untested and the open TODOs.

## License

[MIT](LICENSE). The texts in `corpus/` are public-domain Project Gutenberg works and are not covered by the license.
