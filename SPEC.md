# SPEC: getoffmyfuckinglawn.com — AI Scraper Tarpit + Wall of Shame

## 1. Summary

A single-binary service that traps crawlers that ignore `robots.txt` in an infinite, slow-dripping maze of generated pages. It logs everything and publishes a static, no-JS leaderboard ranking offenders by time wasted.

**Core principle:** only clients that fetch paths explicitly disallowed in `robots.txt` are trapped and shamed. Every leaderboard entry must be a documented, factual violation.

## 2. Goals / Non-goals

**Goals**
- Hold robots.txt violators on slow connections for as long as possible, at minimal CPU, memory, and bandwidth cost.
- Attribute violators accurately: verified crawler vs. spoofed user agent vs. anonymous (by ASN).
- Publish a static leaderboard, per-org pages, a JSON feed, and a plain-text blocklist.
- Run on one small VPS or 1U box behind Caddy.

**Non-goals (v1)**
- No trapping of clients that respect robots.txt, including search engines.
- No JS, no analytics, and no third-party assets on any page.
- No admin UI. Config is a file and the CLI is enough.
- No distributed or multi-node deployment.

## 3. Stack

- **Language:** Go (latest stable), standard library first. Allowed deps: a SQLite driver (`modernc.org/sqlite` preferred for pure Go), `oschwald/maxminddb-golang`, a YAML parser.
- **Storage:** SQLite in WAL mode.
- **ASN data:** MaxMind GeoLite2-ASN `.mmdb`, with the path set in config. Never commit it to the repo.
- **Front end proxy:** Caddy for TLS, passing the real client IP via `X-Forwarded-For`. The app must only trust that header from configured proxy IPs.
- **Deploy:** systemd unit and a sample Caddyfile.
- **No Cloudflare or CDN** in front of `/lawn/`.

## 4. Routes

| Path | Behavior |
|---|---|
| `/` | Static homepage explaining the project. Contains hidden bait links into `/lawn/` (CSS-hidden, `rel="nofollow"`, `aria-hidden="true"`). |
| `/robots.txt` | `User-agent: *` / `Disallow: /lawn/`. Log every fetch. |
| `/sitemap.xml` | Lists a handful of `/lawn/` entry URLs as bait. |
| `/lawn/*` | **The maze** (section 5). Every hit is a violation. |
| `/shame/` | Static leaderboard, regenerated periodically (section 8). |
| `/shame/org/<slug>/` | Per-org detail page. |
| `/shame/feed.json` | Machine-readable offender data. |
| `/shame/blocklist.txt` | CIDRs of verified and high-confidence offenders, one per line. |
| `/healthz` | 200 OK. |
| `/metrics` | Prometheus text format. Bind to localhost or a separate admin port only. |

Every request to every route is logged. Only `/lawn/*` requests count as violations.

## 5. The Maze

### 5.1 Page generation
- Pages are **deterministic and stateless**. Seed a PRNG with `HMAC-SHA256(server_secret, request_path)`, so the same URL always returns the same page and outsiders can't predict content.
- Body text comes from an **order-2 Markov chain** trained at startup on a bundled public-domain corpus (a few Project Gutenberg texts in `corpus/`).
- Each page has a plausible `<title>`, 3–8 paragraphs, and **10–20 links** to child URLs.
- Child URL format: `/lawn/<token>`, where the token is base32 of a truncated HMAC of `(parent_path, index)`, optionally with 1–3 fake path segments for realism (e.g. `/lawn/archive/2019/<token>`).
- Encode the current **depth** so the logger can record max depth reached, either in the token or recoverable from the path.
- Target page size is 2–8 KB. Use no images and no external references.
- Content must never impersonate real people, real brands, or real news.

### 5.2 Slow drip
- Send the status line and headers immediately, then `Content-Type: text/html` and chunked transfer.
- Write the body in chunks of `drip.chunk_bytes` (default 16) every `drip.interval` (default 1s), with ±30% jitter.
- Cap a single connection at `drip.max_duration` (default 10m). After that, finish the page quickly.
- Flush after each chunk and detect client disconnects promptly.
- Memory per connection must stay small. Generate the page up front into a pooled buffer, then trickle it out.

### 5.3 Limits (self-protection)
- `limits.max_conns_global` (default 5000)
- `limits.max_conns_per_asn` (default 200)
- `limits.max_conns_per_ip` (default 20)
- Over any limit: serve the page **without** drip (fast, small) and still log it. Never 5xx because of load shedding.
- `limits.daily_egress_bytes` hard cap. Once exceeded, `/lawn/*` returns a tiny static page until UTC midnight.
- Set sensible server timeouts: read-header timeout, idle timeout, and max header bytes.

## 6. Logging & Data Model

Log asynchronously through a buffered channel to a batched SQLite writer. Request handling must never block on disk.

```sql
CREATE TABLE requests (
  id            INTEGER PRIMARY KEY,
  ts_start      INTEGER NOT NULL,      -- unix ms
  ts_end        INTEGER,               -- unix ms, set on completion/disconnect
  ip            TEXT NOT NULL,
  asn           INTEGER,
  asn_org       TEXT,
  user_agent    TEXT,
  method        TEXT,
  path          TEXT NOT NULL,
  depth         INTEGER,               -- NULL outside /lawn/
  is_violation  INTEGER NOT NULL,      -- 1 if /lawn/*
  bytes_sent    INTEGER,
  dripped       INTEGER NOT NULL,      -- 0 if served fast due to limits
  status        INTEGER
);
CREATE INDEX idx_req_ip_ts ON requests(ip, ts_start);
CREATE INDEX idx_req_violation ON requests(is_violation, ts_start);

CREATE TABLE robots_fetches (
  ip TEXT NOT NULL, user_agent TEXT, ts INTEGER NOT NULL
);

CREATE TABLE identities (           -- cached classification per (ip, ua)
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  claimed_org TEXT,                 -- from UA match, NULL if none
  status TEXT NOT NULL,             -- 'verified' | 'spoofed' | 'unverifiable' | 'anonymous'
  method TEXT,                      -- 'rdns' | 'ip_range' | 'none'
  checked_at INTEGER NOT NULL,
  PRIMARY KEY (ip, user_agent)
);
```

**Sessions** are derived at report time, not stored. A session is consecutive requests from the same `(ip, user_agent)` with gaps under `session.gap` (default 10m).

**Time held** for a request is `ts_end - ts_start`.

## 7. Attribution

### 7.1 User-agent matching
`config/crawlers.yaml` holds the known crawlers. Each entry has:
- `org`, a display name
- `ua_patterns`, a list of regexes
- `verify`, which is one of:
  - `rdns` with `domains` (reverse DNS must end in one of them, and forward DNS must resolve back to the IP)
  - `ip_ranges` with a `url` (a vendor-published JSON or text list, refreshed daily and cached) or static `cidrs`
  - `none`

Seed the file with the major AI and search crawlers (e.g. GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-User, CCBot, PerplexityBot, Bytespider, Amazonbot, Applebot-Extended, Google-Extended, meta-externalagent, Googlebot, Bingbot). **Populate verification details from each vendor's current official documentation, and leave `verify: none` with a TODO comment where no official method is found.** Do not invent URLs or ranges.

### 7.2 Classification
- UA matches a crawler and verification passes → `verified`
- UA matches a crawler and verification fails → `spoofed`
- UA matches a crawler whose `verify` is `none` → `unverifiable` (attribute by ASN; never presented as confirmed)
- No UA match → `anonymous` (attribute by ASN org)

Run verification asynchronously and off the hot path. Cache results in `identities` with a TTL (default 7d). Put a timeout on DNS lookups.

### 7.3 Flags
- **read_the_rules**: the client fetched `/robots.txt` before its first `/lawn/` hit in the same session.

## 8. Wall of Shame (static site builder)

A `build-shame` subcommand, also run on a ticker (default every 5 min), renders `html/template` output into `public/shame/` with atomic swap (write to temp dir, then rename).

**Leaderboard sections**
1. **Verified offenders.** Real crawlers from named orgs that ignored robots.txt. This is the headline table.
2. **Hall of Liars.** Spoofed UAs, grouped by claimed org and actual ASN org.
3. **Top ASNs.** All violators aggregated by ASN org.
4. **Read the rules, ignored them.** Offenders flagged with `read_the_rules`.

**Metrics per row:** total hours held, pages eaten, max depth, bytes sent, sessions, first seen, last seen. Show trailing windows for 24h, 7d, 30d, and all time.

**Global counters:** total bot-hours wasted, total pages served, and the deepest crawl ever.

**Per-org pages:** a daily time-series table rendered as plain HTML (an inline SVG sparkline is fine, but no JS), the top UAs seen, and sample paths.

**Publication rules**
- State only facts: org or ASN, UA string, count of disallowed fetches, time held. No claims about intent.
- Label every identity status clearly. `unverifiable` and `anonymous` are never presented as confirmed.
- **IP display:** show individual IPs only for `verified` corporate crawlers. For everything else, show the ASN and a /24 (IPv4) or /48 (IPv6) at most. Never publish individual IPs from residential or eyeball ASNs.
- The site footer shows the exact `robots.txt` in effect and links to a methodology section on the homepage.

**Feeds**
- `feed.json`: an array of `{org, status, asn, asn_org, cidrs, hours_held, pages, max_depth, first_seen, last_seen}`.
- `blocklist.txt`: CIDRs for `verified` offenders plus `spoofed` offenders with at least N violations (configurable). Include a comment header with generation time and methodology.

**Page style:** static, no JS, single inline stylesheet, dark and light via `prefers-color-scheme`, total page weight under 50 KB. Grumpy copy is encouraged, but the data tables stay strictly factual.

## 9. Config

`config.yaml`, with env var overrides for secrets:

```yaml
listen: "127.0.0.1:8080"
admin_listen: "127.0.0.1:9090"
trusted_proxies: ["127.0.0.1/32"]
server_secret_env: "LAWN_SECRET"
db_path: "/var/lib/lawn/lawn.db"
asn_db_path: "/var/lib/lawn/GeoLite2-ASN.mmdb"
public_dir: "/var/lib/lawn/public"
corpus_dir: "./corpus"
crawlers_file: "./config/crawlers.yaml"
drip:     { chunk_bytes: 16, interval: 1s, max_duration: 10m }
limits:   { max_conns_global: 5000, max_conns_per_asn: 200, max_conns_per_ip: 20, daily_egress_bytes: 5368709120 }
session:  { gap: 10m }
shame:    { rebuild_interval: 5m, blocklist_min_violations: 50 }
retention:{ raw_requests_days: 90 }
```

Raw rows older than `retention.raw_requests_days` are rolled into daily aggregates (add a `daily_aggregates` table) and then deleted.

## 10. CLI

```
lawn serve                 # run server + shame rebuild ticker
lawn build-shame           # one-off leaderboard build
lawn verify-refresh        # refresh vendor IP ranges, re-verify stale identities
lawn stats [--since 24h]   # print top offenders to stdout
lawn gen-robots            # print robots.txt in effect
```

## 11. Repo Layout

```
cmd/lawn/            main + subcommands
internal/maze/       markov, page gen, token/URL scheme
internal/drip/       slow writer, limits, egress accounting
internal/logstore/   sqlite schema, migrations, batched writer
internal/attrib/     UA matching, rDNS, IP ranges, ASN lookup
internal/shame/      aggregation queries, templates, feeds
internal/server/     routing, proxy IP handling, timeouts
web/templates/       homepage + shame templates
corpus/              public-domain training texts
config/              config.example.yaml, crawlers.yaml
deploy/              lawn.service, Caddyfile.example
```

## 12. Testing & Acceptance

**Unit tests**
- The same path always yields an identical page; different secrets yield different pages.
- Tokens and depth encode and decode round-trip.
- Classification covers all four statuses, using fake resolvers and fixture ranges.
- Session derivation and time-held math are correct.
- The IP display rule never outputs a residential /32.

**Integration test**
- Spin up the server, run a fake crawler that fetches robots.txt, ignores it, and walks 50 maze pages.
- Assert the logs, the `read_the_rules` flag, the leaderboard row, and the feed entries.

**Load test** (a script in `tools/`)
- 5000 concurrent slow connections on a 2 vCPU / 2 GB box.
- RSS stays under 500 MB and CPU stays under 50%.
- Limits kick in cleanly beyond the caps.

**Done when**
- `lawn serve` behind Caddy serves all routes.
- The maze drips correctly.
- The leaderboard rebuilds.
- All tests pass.
- `deploy/` files work on a fresh Debian or Ubuntu host.

## 13. Milestones

1. Skeleton: server, config, robots.txt, homepage, logging to SQLite.
2. Maze: Markov generator, deterministic tokens, slow drip, limits, egress cap.
3. Attribution: ASN lookup, crawler UA matching, rDNS and IP-range verification, caching.
4. Shame builder: aggregations, templates, feeds, publication rules.
5. Ops: retention and rollups, metrics, systemd and Caddy files, load test.

## 14. Instructions for Claude Code

- Work milestone by milestone. Commit at each milestone with passing tests.
- Prefer the standard library, and ask before adding any dependency not listed in section 3.
- Don't fabricate vendor verification URLs or IP ranges. Leave TODOs where official sources can't be confirmed.
- Keep the hot path allocation-light and never block on I/O to SQLite or DNS.
- Any change to the publication rules in section 8 requires flagging it to me first.
