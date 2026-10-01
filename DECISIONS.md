# DECISIONS

Choices SPEC.md didn't dictate, or places the implementation deviates from it. One line of rationale each.

## Lead / cross-cutting

- **Go 1.27 (toolchain go1.27.1).** Latest stable at build time; `modernc.org/sqlite` needs ≥ 1.25 anyway.
- **Module path `github.com/boydj/getoffmyfuckinglawn.com`.** Matches the GitHub repo.
- **Deps: `modernc.org/sqlite`, `gopkg.in/yaml.v3` only.** Both are named or implied by the spec; everything else is stdlib.
- **Corpus = Carroll's *Alice*, Austen's *Persuasion*, Chesterton's *The Man Who Was Thursday*.** Public-domain Project Gutenberg texts, taken from NLTK's Gutenberg corpus mirror on GitHub, since gutenberg.org was unreachable from the build sandbox.
- **Extra config keys: `base_url`, `templates_dir`, `attrib.*`, `log.*`.** The sitemap needs absolute URLs; the others expose tunables that were otherwise hard-coded. All have defaults, so the spec's config.yaml still works unchanged.
- **Generic env overrides `LAWN_*` (listen, paths, trusted proxies) on top of the secret env.** CLAUDE.md asks for env overrides; systemd `EnvironmentFile` makes them handy.
- **Templates embedded in the binary via `web/` (`go:embed`), with optional `templates_dir` override.** The binary stays self-contained; deploy still ships templates so the override can be used on the box.
- **Each request is logged once, on completion, with both `ts_start` and `ts_end`.** A single insert per request halves writer load; a request still in flight at crash time is lost, which is acceptable.
- **Session gap is measured from the latest `ts_end` seen in the session to the next `ts_start`.** Otherwise a crawler held 10 min by the drip would open a new "session" on every page.
- **`read_the_rules` is computed from `/robots.txt` rows in `requests` (same ip+ua, same session, before the first `/lawn/` hit).** Every request is logged, so this is equivalent to `robots_fetches` and keeps the flag inside one session derivation.
- **`daily_aggregates` is keyed by (day, ip, user_agent).** That keeps identity joins (verified/spoofed) working after raw rows are rolled up.
- **Identity status/method constants live in `logstore`.** Shame and attrib both need them; this avoids a shame→attrib dependency.
- **Server: one `ServeHTTP` switch instead of `ServeMux` for the public listener.** Every route shares the log/attribution preamble, and the hot path stays allocation-light.
- **Client IP: right-most X-Forwarded-For hop that isn't a trusted proxy, only when the direct peer is trusted.** Left-most entries are client-controlled and forgeable; garbage in the chain falls back to the last good hop.
- **Non-GET/HEAD requests get 405 (still logged); HEAD on `/lawn/*` is a violation but never dripped.** A HEAD has no body to trickle.
- **`/metrics` is hand-written Prometheus text on the admin listener only.** That avoids a client-library dependency for about 20 counters.
- **`/shame/` is served by the app from `public_dir` (no directory listings, no dotfiles).** "`lawn serve` serves all routes" (§12); Caddy stays a dumb TLS proxy.
- **Internal `internal/app` package does the wiring and background loops.** The CLI and the end-to-end integration test share the exact same wiring.
- **Retention rollup runs 1 min after start and every 6 h.** It's idempotent and cheap when nothing is due, so no separate timer is needed.
- **SIGHUP reloads the ASN table and crawlers file (`systemctl reload lawn`).** The weekly ASN refresh doesn't need to drop in-flight drips.
- **`lawn stats --since` accepts only 24h / 7d / 30d / all.** Those are the leaderboard's windows; arbitrary durations would need a second aggregation path.

## Maze / drip (teammate)

- **Page PRNG: ChaCha8 seeded with the full 32-byte HMAC-SHA256(secret, path).** It uses all the HMAC bytes, so outsiders can't predict pages, at zero allocations.
- **Child token = lowercase unpadded base32 of `uvarint(depth) ‖ first 10 bytes of HMAC(secret, parent_path ‖ 0x00 ‖ uint16 index)`.** Depth is recoverable from the URL alone; tokens are 18 chars at depth ≤ 127; depth is capped at 2^20.
- **Entry tokens use HMAC(secret, "\x00entry" ‖ uint32 i) at depth 0.** This keeps them in a separate namespace from page links.
- **`Depth()` does not check the MAC.** It can't, since the MAC is keyed on the parent path; a forged depth can only inflate the forger's own stats.
- **A quarter of links get 1–3 fake segments (neutral words, years 1900–2025, small numbers).** That's the realism §5.1 asks for, with no real-looking names.
- **Page size is kept in range by construction: target 2,400–7,000 B, hard stop at 8,192 B.** Tested over 500 paths (2.4–7.1 KB).
- **Titles and link text use only generic phrases plus lowercase corpus words.** Character names, places and brands can never reach a title; there are no bylines, dates or "news" framing.
- **Corpus cleanup when loading:** it skips `[...]` headers, `CHAPTER` lines and all-caps lines, and strips `_`/`*` markup. Gutenberg formatting doesn't leak into pages.
- **Maze pages carry `<meta name="robots" content="noindex,nofollow">` and a tiny inline stylesheet.** The whole prefix is disallowed anyway; pages still have no JS, images or external refs.
- **Drip: the first chunk goes out immediately, then one chunk per jittered interval; the last wait is cut short to hit `max_duration` exactly, then the remainder is flushed.** The client sees bytes at once, and the cutoff is on time.
- **Jitter is ±30% (hard-coded default; `config.drip` has no jitter key).** It matches §5.2.
- **Per-IP limit keys IPv6 by /64; IPv4-mapped IPv6 is treated as IPv4.** One host usually owns a /64 and could rotate addresses to dodge the cap.
- **Unknown ASN (0) skips the per-ASN cap.** Without an ASN table every client would share one bucket.
- **The egress counter resets only when the UTC date moves forward.** A clock stepping backwards can't wipe the daily total.
- **The load test sends each connection from an X-Forwarded-For address in 198.18.0.0/15 (RFC 2544 benchmarking range).** Per-IP caps then behave as they would for real distinct clients behind Caddy.

## Logstore / attribution (teammate)

- **Googlebot is verified by rDNS against `googlebot.com` only.** Google also lists google.com and googleusercontent.com, but GCP customers get `*.googleusercontent.com` PTRs, so accepting it would let any cloud tenant pass as Googlebot.
- **Google-Extended and Applebot-Extended are kept with `verify: none`.** They are robots.txt product tokens, not fetchers, so any client sending them is "unverifiable" and never shown as confirmed.
- **CCBot is verified by Common Crawl's JSON range list rather than rDNS.** Their rDNS covers IPv4 only.
- **UA patterns are case-insensitive (the loader prepends `(?i)`).** Vendors are inconsistent about casing.
- **DNS timeouts and SERVFAIL are "indeterminate", never "spoofed".** Only NXDOMAIN or a clean mismatch counts as failed verification, so resolver trouble can't brand a real crawler a liar. A new pair is stored as `unverifiable` (the conservative label), backdated so it's retried after 1 h.
- **A range list that was never fetched or has no cache is indeterminate; a download that parses to zero prefixes is rejected.** A missing list can't prove spoofing, and an HTML error page never replaces a good list.
- **Range lists are cached as one normalised text file per URL (`ranges-<sha256[:8]>.txt`, `# fetched:` header).** Writes are atomic, and staleness follows the injected clock.
- **Observe dedupe uses 16 sharded maps keyed by maphash(ip, ua), 10 min TTL, 65,536-entry cap.** The hot path is allocation-free; workers dedupe again against the identity TTL.
- **ReverifyStale re-verifies stale identities that still have raw requests, and classifies unclassified pairs that have violations.** Only violators are published, which saves DNS on old data.
- **Writer: a failed batch is counted in `Errors` and dropped, not retried.** Memory stays bounded if SQLite is unavailable.
- **Rollup commits one transaction per UTC day.** Transactions stay bounded; a session continuing across midnight isn't double counted.
- **PruneIdentities never deletes identities still referenced by raw rows or aggregates.** Rolled-up history keeps its labels.
- **A cached identity is re-classified as soon as crawlers.yaml gives its user agent a different org, whatever its age.** Otherwise a newly added crawler (ShapBot) stays "anonymous" on the wall for up to `identity_ttl`. Both the live classifier and `lawn verify-refresh` compare the stored `claimed_org` with the current match. As with stale rows, only pairs with raw requests are redone, and rolled-up history keeps its label.
- **`config.Validate()` is exported, and `app.New` calls it.** A hand-built `Config` (e.g. `config.Default()`) previously left `Proxies` unparsed, which silently ignored X-Forwarded-For. The integration test caught it.
- **`lawn gen-robots` loads the config before printing.** Deploy uses it as a pre-swap sanity check, so it now also proves the config parses.
- **`lawn verify-refresh` force-refetches every range list (`RefreshAll`).** It's the daily timer's job; the in-process loop only refetches stale lists.
- **`GOMEMLIMIT=400MiB` in `lawn.service`.** A 6000-connection run against the 5000 cap peaked at 390 MiB RSS; a soft heap target keeps GC ahead of the 500 MB budget.
- **The homepage reuses the shame partials (`style`, `footer`).** The whole site has one stylesheet, and every page carries the same robots.txt footer.

## Shame builder (teammate)

- **`unverifiable` gets its own clearly labelled table, "Claimed, unverifiable", between Hall of Liars and Top ASNs.** It's shown, but never next to or as confirmed rows.
- **A missing identity row, an unknown status, or a claimed status with no org is displayed as `anonymous`.** This fails safe: never shown as confirmed, never /32.
- **ASN groups are keyed by ASN number and labelled "AS<n> <org>"; ASN 0/NULL becomes "unknown ASN".** Numbers are unambiguous.
- **Top ASNs has one row per ASN across all statuses, with a badge for each status present.** Every row still carries its labels.
- **Hall of Liars groups by (claimed org, ASN).** That's §8's "claimed org and actual ASN org" at ASN granularity.
- **Anonymous clients have no page of their own; they're described on their ASN's page.** This avoids per-client pages for eyeball networks.
- **feed.json has one entry per (status, claimed org, ASN); `asn` is null when unknown.** It's the finest grain every section is built from.
- **Blocklist = every verified offender's /32 or /128, plus /24 or /48 of spoofed (claimed org, ASN) groups with ≥ `blocklist_min_violations` all-time violations.** A threshold ≤ 0 is treated as 1; anonymous and unverifiable are never listed.
- **The 24h/7d/30d windows use raw rows only; all-time adds `daily_aggregates`.** Retention (90 d) exceeds the largest window.
- **Sessions are counted only when they contain at least one violation.** The leaderboard is about violations.
- **Pages are kept under 50 KB by shrinking row caps step by step (top 50 per section down to 1).** A "shown N of M" note appears, and the full data stays in feed.json; the largest page in a 1,204-page stress fixture is 48 KB.
- **Sample paths are shown only if they match `/lawn/[A-Za-z0-9/_.-]{,120}`; UA strings are truncated to 80–200 chars.** Otherwise a client could publish arbitrary text on the wall by crafting a URL or UA.
- **Shame pages carry `noindex`; links are relative except in blocklist.txt.** The wall is for humans, and "no external URLs" is grep-testable.
- **Swap: rename the old tree aside, rename the new one in, delete the old; restore on failure.** There's a sub-millisecond window with no `shame/`; true atomic exchange would need `x/sys` renameat2.

## Infra / deploy (teammate)

- **One idempotent `deploy/host-setup.sh` runs from cloud-init and on every deploy.** A fresh box and a long-lived box converge, and a non-Vultr Debian/Ubuntu host works with `make deploy DEPLOY_HOST=… LAWN_DOMAIN=…`.
- **Cloud-init writes the `deploy/` files verbatim (`file()` + `indent()`) and then runs host-setup.** There's no shell escaping inside the template, and the files are byte-identical to the repo.
- **`/etc/lawn/env` is written 0600 by cloud-init, then chowned root:lawn 0640 by host-setup; it's never overwritten.** `write_files` runs before the user exists. On non-OpenTofu hosts only, host-setup generates a secret if the file is missing.
- **Caddyfile uses `{$LAWN_DOMAIN}` from `/etc/lawn/caddy.env` via a drop-in.** One Caddyfile everywhere.
- **Caddy: `flush_interval -1`, no `encode`, no access log, no write timeout, HTTP/3 off.** Drips must stream unbuffered for 10 min; the app already logs everything; the firewall opens TCP only.
- **Firewall also allows ICMP from anywhere.** Ping and IPv6 path-MTU discovery need it.
- **The OS image is looked up by name ("Debian 12 x64 (bookworm)") with an `os_id` override; the plan defaults to `vc2-2c-2gb`.** This avoids hard-coded ids.
- **`lifecycle.ignore_changes = [user_data, os_id]`.** After first boot, deploys own the host; editing `deploy/` must not rebuild the box.
- **The DNS zone is created without `ip`, and explicit A/AAAA records (TTL 300) are made for apex and www.** No duplicate default records.
- **`.terraform.lock.hcl` is not committed.** The sandbox's local mirror only records linux_amd64 hashes, which would break `tofu init` on macOS.
- **Deploy is a tarball over one ssh connection; host keys use `accept-new`, or strict checking with `SSH_KNOWN_HOSTS`.** No rsync dependency.
- **`/etc/lawn/config.yaml` is created once and never overwritten; the latest example goes to `config.example.yaml` beside it.** Operator edits survive deploys; `crawlers.yaml` is always replaced.
- **The binary swap is install-to-temp + `mv`; the previous binary is kept as `lawn.prev` and restored if the health check fails.** Deploys are safe to re-run.
- **`lawn.service` hardening goes beyond the brief:** `MemoryHigh=900M`, `MemoryMax=1200M`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, and `IPAddressDeny=169.254.0.0/16`, which blocks the metadata endpoint that holds user-data and so the secret. `ConditionPathExists` on the binary and config keeps boot from loop-failing before the first deploy.
- **Backups: `VACUUM INTO` a temp file, `PRAGMA quick_check`, rename; keep the newest 7.** Re-running the same day is safe.
- **The ASN refresh requires ≥ 1 MB, `gzip -t`, and a 5-field first line, and skips unchanged files; then `try-reload-or-restart lawn`.** A bad download can never replace a good table.
- **unattended-upgrades covers security updates plus Caddy's repo, auto-rebooting at 04:30 UTC when needed.** A brief drip interruption is fine for a tarpit.
- **journald: 200 MB cap, 1 month retention; sysctls raise somaxconn/backlog to 8192 and widen the port range.** Sized for thousands of slow sockets on a 2 GB box.
- **CI calls the Makefile targets; actions are pinned to major tags; `deploy.yml` uses a `production` environment and runs `make test` first.** Local and CI behaviour stay identical.

## Integration follow-ups (lead)

- **Over-limit `/lawn/*` requests get a tiny static "lawn is full" page (≈80 B, no links, no render) instead of the full maze page.** §5.3 says "fast, small". In a 6000-vs-5000-cap load test this cut box CPU from 49% to 37.5% and bytes sent from 975 MB to 22 MB, while serving more shed requests.
- **HEAD on `/lawn/*` no longer renders the page, so it carries no Content-Length.** HEAD is never dripped, and rendering only to count bytes wasted CPU.
- **The draft `deploy/README.md` was folded into the top-level README.** One place for setup/deploy/teardown docs.

## Final status: untested and open TODOs

### Verified in the build sandbox
- **Test suite.** `make test` (unit + integration, `-race`), `go vet`, `staticcheck`, gofmt, shellcheck, and `tofu fmt -check` + `tofu validate` are all clean. `tofu plan` was not run because no `VULTR_API_KEY` was set.
- **Integration test.** A fake crawler reads robots.txt and walks 50 maze pages. The test asserts:
  - the request rows, the depth reached (49) and the ASN;
  - all four identity statuses and the `read_the_rules` flag;
  - the leaderboard, org page, feed.json, blocklist and metrics;
  - that no non-verified IP appears on any page.
- **Real binary smoke test.** Every route answered. The drip delivered its first byte at 0.6 ms and then 16 B/s, and a client disconnect was detected. SIGHUP reload, `stats`, and graceful SIGTERM shutdown all worked.
- **Load test (4-vCPU sandbox, load generator on the same machine).**
  - 5000 drips: 191 MiB RSS, 5.6% box CPU.
  - 6000 connections against a 5000 cap: 393 MiB RSS, 37.5% box CPU, 0 errors, 0 5xx.
- **Deploy pieces checked offline.** Cloud-init renders to valid YAML, and `systemd-analyze verify` and `caddy validate` pass. `backup.sh` and `asn-refresh.sh` were run for real against local files.

### Untested
- **Nothing has run on a real host.** Untested there: `make infra`, `make deploy`, cloud-init on a Vultr Debian 12 box, `host-setup.sh`/`install.sh`, Caddy certificate issuance, and the hardened unit (`SystemCallFilter`, `MemoryDenyWriteExecute`) against the real binary.
- **The load test on the spec's 2 vCPU / 2 GB box.** The CPU figures above are from 4 vCPUs.
- **Real network sources.** Real DNS, real vendor IP-range downloads and the real iptoasn.com file were blocked from the sandbox. The parsers are tested with fixtures and a synthetic 500k-row ASN file.
- **The GitHub Actions workflows.** They pass `actionlint` but have not run on GitHub.
- **Swap gap.** The shame directory swap has a sub-millisecond window where `shame/` doesn't exist.

### TODOs
1. **Crawler verification with `verify: none`.** No official method was found for:
   - Anthropic (ClaudeBot, Claude-User, Claude-SearchBot): Anthropic says it publishes no IP ranges.
   - ByteDance (Bytespider): no official documentation.
   - Meta (meta-externalagent, meta-externalfetcher): no list URL or rDNS scheme on its crawler page.
   Hits from these UAs are published as "claimed, unverifiable".
2. **Open the vendor range URLs once by hand before deploy.** WebFetch to vendor sites was blocked, so every `verify` entry was confirmed through vendor-domain web search results rather than a direct read of the page. The URLs are the OpenAI ×3, Common Crawl, and Perplexity ×2 `ip_ranges` lists (Perplexity's docs name `www.perplexity.com`).
3. **Vultr details that couldn't be confirmed against official docs.**
   - The OS image name "Debian 12 x64 (bookworm)"; `os_id` in tfvars is the fallback.
   - That `vc2-2c-2gb` is 2 vCPU / 2 GB.
   - The user-data size limit; the rendered user-data is about 23 KB.
   - Whether the DNS zone adds its own NS/SOA records.
4. **Caddy apt repository.** The keyring and repo URLs come from search results quoting caddyserver.com/docs/install. The unattended-upgrades origin pattern for Caddy's repo is also unconfirmed; worst case, Caddy isn't auto-upgraded.
5. **The deploy workflow can't reach SSH by default.** GitHub-hosted runners aren't in `admin_cidrs`; add their ranges or use a self-hosted runner.
6. **Backups stay on the box.** Copy them off-box if the history matters.
- **host-setup opens 80/443 in ufw when ufw is active, and otherwise leaves ufw alone.** Vultr's Debian/Ubuntu images ship with ufw enabled and SSH-only, which silently dropped ACME challenges on the first real deploy. ufw stays on as defense in depth behind the Vultr firewall group.

## Patching (follow-up)

- **unattended-upgrades lists Debian's security, point-release and `-updates` origins explicitly (plus Caddy's repo).** Vultr's image defaults can't silently narrow what gets patched.
- **needrestart runs in automatic mode (`$nrconf{restart} = 'a'`).** Services holding a replaced library are restarted right after the upgrade instead of waiting for a reboot. `lawn` and Caddy are static Go binaries, so they're unaffected.
- **Reboots:** unattended-upgrades' `Automatic-Reboot` fires at 04:30 UTC, even with users logged in. `lawn-reboot-check.timer` at 04:45 is a backstop that also reboots for a newer installed kernel, and refuses a second reboot for the same kernel so a bad bootloader default can't cause a daily reboot loop. The timer is not `Persistent`, so a missed run never reboots right after boot.
- **The `lawn` binary is patched through CI signals, not on the host.** `govulncheck` runs against go.mod's `toolchain` (what `make build-linux` uses) on every push and weekly on a schedule; Dependabot covers Go modules (daily, per the operator's config) and Actions (weekly). The host never builds Go.
- **`make patch-status`** gives a read-only, one-screen view: pending updates, running vs. installed kernel, reboot needed, recent unattended-upgrades runs, services needing restart, timers and failed units.
- **Stay on Debian 12 under LTS (security support until 2028-06-30); no move to Debian 13.** The operator's call. LTS fixes ship through `bookworm-security`, which unattended-upgrades already covers. Revisit before mid-2028.

## Depth and diagnostics (follow-up after launch)

- **Maze pages put their link block right after the `<h1>` (in a `<nav>`), and the drip sends everything through `</nav>` at once.** At 16 B/s the links used to arrive ~4 minutes into the page (median byte 3,682). Real crawlers time out long before that, so every bot stayed at depth 0. §5.2 says headers go out immediately; sending the ~1.6 KB lead too is a deliberate deviation, and the remaining ~3 KB of text still drips.
- **Adaptive drip budget (`drip.adaptive`, default on).** Deviates from §5.2's single fixed `max_duration`: a client never seen giving up still gets the full 10 minutes. Details:
  - **Budget:** once a client hangs up after *t*, its later responses are budgeted `adaptive_factor` × *t* (0.8), floored at 250 ms, so it gets complete pages and follows links.
  - **Probing:** each response it waits out raises the estimate by 2%, so a noisy low sample recovers and the budget creeps back toward the real timeout.
  - **Why:** a bot that times out at 30 s is held ~24 s per page across many pages, rather than 30 s once.
- **Adaptive key = (ASN, user agent), or (/24 or /48, user agent) when the ASN is unknown.** Crawlers rotate IPs within a network far more often than they change user agent.
  - Memory is bounded: UA truncated to 256 bytes, 100k entries, 24 h TTL.
  - Only clients seen giving up are tracked.
  - State is in memory only; a restart relearns within one page per client.
- **Migration 2 adds `end_reason`, `referer`, `accept`, `accept_language` and `accept_encoding` to `requests`.**
  - `end_reason` is NULL outside `/lawn/`. Dripped responses use the drip outcome (`complete` / `cutoff` / `client_gone` / `write_error`); undripped ones use `shed` / `egress_cap` / `head`.
  - Headers are truncated (512 / 256 / 128 / 128 bytes), used for analysis only, and never published, so §8 is unaffected.

## All visitors, well-behaved bots, new-bot detection (follow-up)

- **No egress cap (operator decision).** `limits.daily_egress_bytes`, the closed-for-the-day page and the `egress_cap` end reason are removed. Bytes are still counted for `/metrics`. An old config that sets the key still loads, since unknown keys are ignored.
- **No Vultr DDoS protection (operator decision).** Application connection caps are the only protection; accepted.
- **Every visitor is classified and gets a reverse-DNS lookup, not only violators.** Well-behaved bots need identity labels, and a PTR name (e.g. `crawl-1.newbot.example`) is often the first clue to a new crawler. The lookup is off the hot path (classifier workers) and cached for the identity TTL (7 d). A clean "no PTR" is stored as `''`; DNS failures are retried.
- **PTR names are stored unconfirmed in `hosts`.** They are a lead for a human, not a verification; forward-confirmed rDNS for known crawlers stays in `identities`. They are never published.
- **Migration 3 adds `header_names` (sorted client header names, proxy-added ones excluded, ≤ 512 B), `proto` and `tls` to `requests`.** Which headers a client sends, plus its HTTP and TLS versions, fingerprints the software. Header order would be better still, but Go's `http.Header` doesn't keep it.
- **Client HTTP and TLS versions come from Caddy (`header_up X-Lawn-Client-Proto`/`X-Lawn-Client-TLS`), read only from trusted peers.** The app sees HTTP/1.1 from Caddy. `header_up` overwrites any client value; verified against a real Caddy.
- **Caddy's proxy transport uses `compression off`.** Without it, Caddy adds `Accept-Encoding: gzip` for clients that sent none, which polluted the `accept_encoding` column added in migration 2. Found and fixed while verifying the placeholders.
- **`daily_visits` rolls up EVERY visitor per (day, ip, ua), in the same transaction as `daily_aggregates`.** Counts are requests, robots.txt fetches, bait-page views and violations. Compliant bots keep their history past the 90-day raw retention.
- **`lawn bots` is private; the public page shows only what §8 allows.** The CLI shows PTR names, IPs and header fingerprints for the operator.
- **"Bot-like" signals:** the UA names a bot or HTTP library, the client fetched robots.txt, entered /lawn/, sent no Accept-Language (on rows where headers were captured), or has a crawler-looking PTR. `--all` lifts the filter.
- **Product token = the UA's self-declared bot/library name.** Browser-looking UAs with bot signals are grouped by ASN, which is how headless scrapers show up.
- **"New" = the group's earliest UA was first seen (raw requests or `daily_visits`) within the last 7 days.**
- **Anthropic's three crawlers now verify against `https://claude.com/crawling/bots.json`.** Anthropic's support article (re-checked 2026-09-27) publishes this list and says a source IP on it means the crawler is Anthropic's. It replaces the earlier `verify: none` TODOs, and was confirmed by fetching the list itself (26 IPv4 prefixes, Google-style JSON).

## Well-behaved crawlers page (teammate)

- **Eligibility: at least one GET of `/robots.txt` and zero `/lawn/` history anywhere (raw rows, `daily_visits.violations`, `daily_aggregates`).** One violation ever puts a client on the wall, never on both lists; clients that never fetched robots.txt aren't listed, because we can't tell whether they followed it.
- **Only GET counts as reading robots.txt or seeing the bait, in raw rows, in the rollup and in `lawn bots`.** HEAD has no body, and other methods get a 405. The lead aligned the rollup and `lawn bots` to GET-only too, so every source counts the same way.
- **Query-string variants (`/robots.txt?…`, `/?…`, `/sitemap.xml?…`) count.** The server serves the same page for them.
- **Grouping mirrors the wall:**
  - verified and unverifiable by claimed org, each in its own clearly labelled section;
  - anonymous by ASN;
  - spoofed compliant clients under their ASN with the failed claim stated, never credited to the named org.
- **IPs go through `DisplayCIDR` plus the `publishable` check.** Only verified crawlers show /32 or /128; everything else is /24 or /48 at most.
- **`well-behaved.json` has one entry per (status, claimed org, ASN), like `feed.json`, and adds `claimed_org`.** The page shows groups. Well-behaved clients never enter `blocklist.txt`.
- **Rows are ordered most recently seen first; the 24h/7d/30d windows use raw rows, and all-time adds `daily_visits`.** Same rules as the wall.
- **Collection is a single streaming scan: a flat UNION ALL over requests, `daily_visits` and `daily_aggregates`, ordered by (ip, ua).** Memory is bounded to one client pair at a time. The lead added `idx_req_ip_ua_ts` to migration 3 (not yet deployed anywhere) so the scan and the rollup walk rows in index order. The whole scan costs about 1.3× the old one on a 1M-row test.
- **`lawn stats` gains a "Well-behaved" section that shows network labels only.**

## Second-report follow-ups

- **User-initiated fetchers:** `crawlers.yaml` gains `user_triggered` and `robots_exempt` (the second requires the first).
  - **Exempt:** ChatGPT-User (OpenAI's crawler page: "robots.txt rules may not apply"; the primary page was unreachable from the sandbox, so it is quoted via press coverage, with a TODO to re-check) and Perplexity-User.
  - **Not exempt:** Claude-User is user-triggered, but Anthropic states it honours robots.txt.
  - **On the wall:** a VERIFIED exempt fetcher's `/lawn/` hits get their own "User-initiated fetchers" section, excluded from Top ASNs, read-the-rules and the blocklist, and shown only as /24 or /48. They still count in totals and `feed.json` because the time was really held.
  - **Spoofed claims:** they stay in the Hall of Liars.
  - **Why:** presenting a person's one-off request as a crawler ignoring the rules is the easiest claim to dispute.
- **The log keeps the path plus query parameter NAMES only (`/x?q=secret&a=1` → `/x?a&q`).** The Referer likewise keeps scheme, host, path and parameter names, with no values, userinfo or fragment. Values can carry tokens or personal data, and nothing needs them.
- **Per-prefix limits:** there is now a /24 (IPv4) or /48 (IPv6) level in the concurrency limiter (`limits.max_conns_per_prefix`, default 50) and a per-prefix token bucket for new `/lawn/` requests (`limits.prefix_rate` 10/s, `prefix_burst` 100). Over either limit, the request gets the existing tiny "lawn is full" page, logged with `end_reason` `shed` or `rate_limited`, never a 5xx.
  - **Why prefixes:** rotating addresses inside one network, or firing many short requests, used to slip past the per-IP cap.
  - **Why not 5/s:** an adaptively dripped crawler with 20 parallel connections on ~4 s pages already makes ~5 req/s, and a tighter limit would clip the depth #9 was for. 10/s still stops floods.
  - **Implementation:** stdlib only (no `x/time/rate`), with memory bounded at 100k prefixes. `0` turns either limit off; the load-test script does, because it simulates thousands of clients from a few /24s.
- **Parent tracking (frontier amplification):** child links now embed a 4-byte id of the page that linked them (the first 4 bytes of HMAC(secret, path || "\x01id")); entry links carry none.
  - **Logged:** `page_id` and `parent_id` columns (migration 4, partial index on `page_id`), NULL outside `/lawn/`. An id of 0 is stored as NULL; the 1-in-2^32 collision is ignored.
  - **Measured:** `lawn bots` matches each child to an earlier fetch of its parent by the same user agent, across IPs because distributed crawlers split work between addresses. It counts how many of those started before the parent response ended (`OPEN`). Parents that retention has rolled up leave children unmatched, so run it on recent windows.
  - **Compatibility:** child URLs grow by about 7 characters. Old child URLs (MAC only) and entry URLs still decode and render the same page, with no parent.
  - **Why ids and not full paths:** a 4-byte id keeps URLs short and rows small, and the HMAC means clients cannot forge a matching id.

## Depth, operator traffic and visitor detail (follow-up)

- **Maze pages no longer say `nofollow`.** They carry `<meta name="robots" content="noindex">` and `X-Robots-Tag: noindex`. This supersedes the build-time choice above ("noindex,nofollow").
  - **Why:** robots.txt is the rule the maze enforces. A crawler that ignores it but honours page-level nofollow stopped at depth 0, which defeats the tarpit without making anything fairer. Only clients already in a disallowed path ever see these pages.
  - **Kept:** `noindex`, so no search engine lists maze pages. The homepage bait links keep `rel="nofollow"` (SPEC.md section 3).
  - **What the data showed first:** in the first week every maze visitor was a one-hop link checker. These fetch `/`, then each of the six hidden links once, with no Referer, and never parse the pages. nofollow was not the cause for them, but it is the one thing on our side that would stop a real crawler.
- **Operator networks (`exclude_cidrs`) are filtered when reports are read, not tagged when requests are written.**
  - **Applies to history:** adding a network also hides its past rows, including rollups (`daily_visits`, `daily_aggregates`), with no migration or backfill. Removing it brings them back.
  - **"Still logged":** the rows stay in the database; `lawn visitors --operators` shows them marked.
  - **Scope:** the shame collector (wall, well-behaved page, feed, blocklist, `lawn stats`), `lawn bots` and `lawn visitors` all skip them. The server does not treat them differently, so the maze still behaves normally when the operator tests it.
  - **Reload:** SIGHUP re-reads only this key from `config.yaml`; the next shame build applies it.
  - **Not auto-filled from SSH `admin_cidrs`:** that list can hold shared addresses (airline or café Wi-Fi), and excluding those would hide other people. `/0` is rejected.
  - **Known gap:** `lawn bots` still computes a user agent's all-time first sighting over every IP, so an operator using the same UA earlier can make a group look less new.
- **Unlogged maze preview on the admin listener.** It serves `GET /lawn/...` straight from the generator: no drip, limits, log row or classification. It is reachable only through an SSH tunnel, because `admin_listen` is localhost-only and Caddy proxies only the public listener. The index at `/` lists the sitemap entries.
- **Country per request.** Migration 5 adds `requests.country`: the two-letter code of the IP's range from the iptoasn.com file the ASN lookup already loads. That file's "None" and "Unknown" values are stored as NULL.
  - **Hot path:** codes are interned at load, so the lookup still does not allocate, and the country is found in the same binary search as the ASN.
  - **Private:** it appears in `lawn bots` details and `lawn visitors` and is never published.
- **`lawn visitors`:** a private per-request view; `lawn bots` stays the grouped one.
  - **Order:** newest first, or oldest first when `--ip` names a single address (that client's timeline).
  - **Filters:** user agent (case-insensitive, with `%` and `_` taken literally), path prefix, AS number, IP or CIDR (checked in Go, since SQLite cannot test prefixes), and `--lawn`.
  - **Output:** full IPs, because it is the operator's own log (section 8 governs publication). The default limit is 100.

## Tor onion mirror (follow-up)

- **Single onion service (operator decision).** `HiddenServiceNonAnonymousMode` plus `HiddenServiceSingleHopMode`, with `SocksPort 0` as tor(1) requires. The clearnet site already reveals the server, so 6-hop anonymity would protect nothing and cost latency and Tor network capacity. Visitors keep their anonymity.
- **Tor from deb.torproject.org, not Debian's package.** The Tor Project recommends its repository because distribution packages lag and the network retires old versions.
  - **Key pinning:** the key is fetched from the Tor Project's published URL and must carry fingerprint `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`, or setup stops. `deb.torproject.org-keyring` keeps it current after that. Unattended upgrades cover `site=deb.torproject.org`.
  - **How it was checked:** torproject.org was unreachable from the build sandbox. The fingerprint and URL were confirmed via search results citing support.torproject.org/apt/tor-deb-repo/, and the torrc options against tor.1.txt from a Tor release tag.
  - **Known issue:** a signature problem with this key under apt ≥ 3 affects Debian 13, not this Debian 12 host.
- **Circuits instead of IPs.** `HiddenServiceExportCircuitID haproxy` plus Caddy's `proxy_protocol` listener wrapper (`fallback_policy require`, 127.0.0.1:8081 only) turn each circuit into `fc00:dead:beef:4dad::<id>` in X-Forwarded-For. The app stores that as the IP. Otherwise every onion visitor would be "127.0.0.1": one client, sharing one per-IP cap and one session. This was tested with Caddy 2.10.2 and a hand-written PROXY header.
- **Onion traffic uses a reserved pseudo-ASN, AS4294967295 (RFC 7300), named "Tor onion service".**
  - **Why:** every existing path (per-network limits, drip budgets, wall grouping, `lawn bots`, `lawn visitors`) groups it correctly with no special cases. The number is reserved, so it can never be a real network.
  - **Labels:** `logstore.NetworkLabel` prints just the name, and JSON publishes `asn: null` with the name.
  - **Never published:** circuit addresses are never shown. `DisplayCIDR` returns nothing for them, and `publishable` rejects any prefix overlapping `fc00:dead:beef:4dad::/96`, whatever the status.
- **Crawler claims over Tor are "claimed, unverifiable", never "spoofed".** With no source address, rDNS and IP ranges can neither confirm nor refute a claim, and "spoofed" would be an unfounded accusation. No reverse-DNS lookups are made for circuits.
- **Onion address plumbing.** host-setup waits for tor's `hostname` file, checks it is a v3 address and writes `LAWN_ONION_ADDRESS` into `/etc/lawn/env`.
  - **What the app does with it:** sends `Onion-Location` on clearnet HTML pages (home, wall), links the mirror from the home page, and serves onion visitors a sitemap with onion links. Nothing else changes, since maze links are root-relative.
  - **Not on the maze:** `Onion-Location` stays off maze responses, to keep the hot path free of allocations.
- **Key backup is off-box and manual (`make onion-backup`).** The nightly backup runs as `lawn` with no access to tor's directory, and an on-box copy wouldn't survive losing the box, which is the case that matters.

## More protocols: plain HTTP, HTTP/3, Gopher, Gemini (follow-up)

- **Port 80 goes through the app, not Caddy's automatic redirect.** Before this, plain-HTTP requests never reached the log, so crawlers that start from `http://` URLs, never follow redirects, or scan bare IPs were invisible.
  - **What the app does:** it serves `/robots.txt`, `/lawn/` and `/healthz` over plain HTTP exactly as over HTTPS, so the rule applies everywhere and http-only crawlers are trapped too. Everything else gets a 301 to `base_url`.
  - **What stays:** the `www` HTTPS redirect.
  - **The onion mirror is plain HTTP by design,** so it is never redirected.
  - **Detection:** Caddy's own `X-Forwarded-Proto` header, trusted only from the proxy. The upgrade happens only when it explicitly says `http`, so direct and local requests are never redirected.
  - **Caddy detail:** the domain and `www` need their own `http://` site block. Combined with the catch-all, Caddy drops their host match and re-adds its own 308 redirects; found by running the Caddyfile locally.
  - **ACME:** Caddy answers HTTP-01 challenges before routes, and TLS-ALPN-01 on 443 is unaffected. The local test could not exercise a live challenge.
- **Scheme column (migration 6):** `https`, `http`, `gopher` or `gemini`. `proto` keeps the version, and HTTP/3 shows as `HTTP/3.0`. `lawn visitors` shows both as VIA, with onion traffic as `onion`.
- **HTTP/3 (operator decision).** Caddy `protocols h1 h2 h3`, UDP 443 in the Vultr firewall and ufw, and quic-go's recommended 7.5 MB UDP buffer maxima. Checked locally: Caddy sends `alt-svc: h3=":443"`.
- **Gopher and Gemini are served by `lawn` itself** (`internal/smallweb`), not a separate daemon.
  - **Why in-process:** they share the maze generator, drip, limits, adaptive budgets, log writer, classifier and ASN lookup, so they behave and report exactly like HTTP.
  - **Ports:** 70 and 1965, open in the Vultr firewall and ufw. `lawn.service` gains `CAP_NET_BIND_SERVICE` (bounding and ambient) for port 70, and nothing else.
- **One maze in every format.** The renderer takes a `Format` (HTML, gemtext, gopher menu). Every format consumes the page's random sequence identically, so a path has the same title, links, anchors and text everywhere.
  - **HTML unchanged:** HTML output was checked byte-identical against 68 pre-refactor page hashes, still at 0 allocations. The new formats don't allocate either.
  - **Gopher:** menus wrap text at 70 columns in info lines.
  - **Gemini:** a paragraph that would read as gemtext markup gets a leading space.
- **Small-web requests are logged as HTTP-like fetches.** Method `GET`, and the path is the selector or URL path, so the existing robots, bait and violation reports count them with no changes.
  - **Queries:** Gopher searches and Gemini queries are user input, so only their presence is kept (`/path?`), as with HTTP query values.
  - **Not requests:** connections that send nothing, and failed TLS handshakes on 1965, are port scans and are not logged.
- **A write failure means the client left.** On a bare connection there is no request context to signal a hang-up, so a failed drip write is treated as `client_gone`. That feeds the adaptive budget exactly as for HTTP.
- **Gemini certificate:** self-signed ECDSA P-256 for `base_url`'s host, valid 20 years, created on first start in `gemini_cert_dir`, and never replaced automatically (a corrupt one is an error). Gemini clients pin certificates on first use, so replacing it would lock returning clients out. `make keys-backup` saves it with the onion key.
- **Configuration:** `gopher_listen` (`:70`) and `gemini_listen` (`:1965`) default on, so existing operator-owned `config.yaml` files get them without editing. `"off"` disables either. `make run` and the load test use unprivileged ports or turn them off.
- **Gemini proxy requests** (other URL schemes) get `53`; any host is served, like the port-80 catch-all. The homepage links both mirrors through `template.URL`, since html/template only allows http(s) and mailto links; the URLs come from config, never from input.

## ShapBot (Parallel) (follow-up)

- **Added as a known crawler** with `ip_ranges` from `https://docs.parallel.ai/resources/shapbot.json`, the list Parallel's crawler page links ("For the complete list of ShapBot IPs, see shapbot.json"). docs.parallel.ai is blocked from the build sandbox, so the operator fetched the file directly (2026-09-30). It uses the Google-style `prefixes`/`ipv4Prefix` format the range parser already reads: ten IPv4 /32s, no IPv6.

## More verified crawlers from vendor lists (follow-up)

- **Aggregators find lists; vendors remain the source.** Public projects that track official crawler IP lists were used to find vendor lists we didn't use yet: ipverse/bot-ip-blocks (CC0, with UA patterns and an "authoritative" flag), ondrejnov/bot-ips and ramhee98/ai-crawler-ipranges (MIT).
  - **Runtime:** the server still fetches only each vendor's own URL. An aggregator's copy of the addresses, if stale or tampered with, would call real crawlers spoofers or pass fakes.
  - **Rejected lists:** the ASN-derived lists some aggregators carry for Meta and Yandex are not used. Anything hosted in those networks would pass as the crawler.
  - **Checking:** each entry was checked against the vendor's own page (web search restricted to the vendor's domain; direct fetches were blocked from the build sandbox).
  - **User agents:** the aggregators' user-agent-to-family mappings were not trusted. ipverse files FeedFetcher-Google under special-case crawlers, while Google puts it in the user-triggered lists.
- **Added entries:**

  | Entry | Verification | Notes |
  |---|---|---|
  | Google special-case crawlers | IP lists | |
  | Google user-triggered fetchers | IP lists | user-triggered and robots-exempt, per Google's own wording |
  | DuckAssistBot, DuckDuckBot | IP lists | |
  | MistralAI-User | IP list | user-triggered, not exempt |
  | MistralAI-Index | IP list | |
  | SeznamBot | IP list | |
  | Kagibot | rDNS `kagibot.org` | |
  | AhrefsBot, AhrefsSiteAudit | rDNS `ahrefs.com`/`ahrefs.net` | |
  | SEBot-WA | rDNS `sr-srv.net` | |
  | SERankingBacklinksBot | rDNS `seranking.com` | |

  SEO bots are included at the operator's request, under the same rules.
- **Google's non-Googlebot agents are verified against the union of Google's five lists** (`verify.urls`, new): special-crawlers, user-triggered-fetchers, user-triggered-fetchers-google, user-triggered-agents and common-crawlers.
  - **Why the union:** Google's per-family tables could not be read in full from the sandbox. With the union, a user agent filed under the wrong family can't produce a false "spoofed".
  - **Rules:** an address in any list verifies. It is spoofed only when every list is known and none contains it; a missing list leaves it undecided.
  - **Not reverse DNS:** `googleusercontent.com` includes customers' Google Cloud machines.
- **Seznam uses its list, not reverse DNS.** Seznam's page says its addresses have reverse DNS but not under which domain. A wrong guess would publicly call the real SeznamBot a spoofer; a wrong or missing list only leaves it unverifiable.
- **Mistral's and Seznam's lists** were found through ramhee98's registry and ondrejnov's source list, because Mistral's and Seznam's pages were not fully visible from the sandbox. The operator fetched all three files directly (2026-09-30): each is a Google-style `ipv4Prefix` list served from the vendor's own domain.
- **`make crawlers-check`** (`tools/crawlerscheck`) compares `crawlers.yaml` with the ipverse and ondrejnov catalogues. It lists vendor lists we don't use and user agents no entry matches, and marks lists that aren't vendor-published and services our entries already cover. It only reports leads; nothing is added without the vendor's documentation.

## Crawlers from the first `make crawlers-check` run

- **Added.** Each check was confirmed via search restricted to the vendor's domain, because the vendors' pages are blocked from the sandbox.

  | Agent | Verified by | Source |
  |---|---|---|
  | GoogleOther (and -Image, -Video), Storebot-Google, Google-InspectionTool | rDNS `googlebot.com`, as Googlebot | Google's common crawlers page |
  | adidxbot, msnbot, BingPreview | added to the Bingbot entry: rDNS `search.msn.com` | Microsoft names the four bots and one check |
  | YandexBot and ten sibling robots | rDNS `yandex.ru`/`yandex.net`/`yandex.com` | Yandex's "check that a robot belongs to Yandex" page |
  | facebookexternalhit, FacebookBot | none (TODO) | Meta publishes only its ASN |
  | MicrosoftPreview | none (TODO) | only third-party pages describe it |

- **Yandex's robots are named one by one, not matched as `Yandex*`.** A catch-all would also match Yandex's apps and browser, whose users would then be called spoofers.
- **Left out on purpose:**
  - **Chrome-Lighthouse:** Lighthouse also runs in anyone's Chrome DevTools and CI, so checking it against Google's lists would call those developers spoofers.
  - **DuplexWeb-Google:** Google shut the service down.
  - Both are listed in `crawlerscheck`'s `declined` map so they stop coming up as leads.
- **Google Publisher Center is `GoogleProducer`**, added to the user-triggered fetchers. The operator read the tokens off Google's user-triggered fetchers page (2026-09-30), which names `GoogleProducer` and `Google-Agent`. The catalogues' "GoogleAgent-Mariner" is not on it, so it is declined; `Google-Agent` was already matched.
- **`make crawlers-check` now prints real leads first**, then an "already covered or unusable" section. Settled means one of:
  - an entry already matches the list's user agents or its catalogue name (ondrejnov names lists after the bot);
  - the catalogue lists a shortened token our pattern contains (`NotebookLM`);
  - the list isn't vendor-published;
  - the user agent was declined above.

## Scrapers that claim to be browsers: JA4, browser consistency, timing, hosting (follow-up)
- **Our own scoring, not a forked bot-detection project.** Existing tools are built for other jobs:
  - Anubis and go-away challenge visitors, which would keep scrapers out of the tarpit.
  - CrowdSec is a whole blocking engine.
  - BotD needs JavaScript, and the site has none.

  Every anonymous group on the wall already ignored robots.txt. The only question is person or software, and the stored logs answer it after the fact. So `lawn bots` gained named signals with weights. Their ideas come from the robot-detection literature (Tan & Kumar 2002; Doran & Gokhale's survey). The report stays private, and the publication rules are unchanged.
- **JA4 only, implemented from the specification.** FoxIO's JA4 (TLS client) is BSD-3; the rest of JA4+ (JA4H, JA4S, …) is under the FoxIO License and is not used.
  - `caddy/ja4` is an independent implementation of `technical_details/JA4.md`, with the license kept alongside.
  - It reproduces both of the spec's worked examples (`t13d1516h2_8daaf6152771_e5627efa2ab1` and the no-signature-algorithms `…_6d807ffa2a79`).
  - In the sandbox it matched an independent library (`github.com/GergelyGombai/ja4plus`) exactly on curl (HTTP/1.1 and h2), Python and Chromium handshakes.
- **Fingerprinting happens in Caddy, the TLS endpoint.**
  - A listener wrapper placed before `tls` copies the bytes of each TCP connection's ClientHello as the handshake reads them, then stops.
  - The `ja4` directive uses `Server.RegisterConnContext` to find the connection. It replaces any client-supplied `X-Lawn-Client-JA4` and removes it when there is none.
  - The plain-HTTP sites strip that header too. The app accepts it only from the trusted proxy and only in JA4's exact shape, into `requests.ja4` (migration 7).
  - QUIC doesn't pass through listener wrappers, so HTTP/3 requests carry no JA4. Browsers move to HTTP/3 via `Alt-Svc`, so a browser's later requests often have none. The signals only use the fingerprints present.
- **`caddy/` is its own Go module with its own `main.go`**, instead of an xcaddy build. That keeps Caddy's large dependency tree out of the app's `go.mod`, and lets `go.sum` and Dependabot pin and update Caddy (v2.11.6). `make test`, `make vet` and `make vulncheck` cover both modules.
- **Installed the way Caddy documents for custom builds on Debian.**
  - `dpkg-divert` moves the package's binary to `caddy.default`, and `update-alternatives` selects `caddy.custom`.
  - The package keeps its unit and user, and its upgrades no longer replace the running binary.
  - The trade-off: Caddy security fixes now arrive by redeploying, after Dependabot or govulncheck flags them, instead of through unattended upgrades.
  - Caddy restarts when its binary changes. A reload would keep the old binary.
  - On a host's first boot, cloud-init still installs only the packaged Caddy. No Caddyfile is installed until the first deploy, which brings the custom binary.
- **Hosting networks from X4BNet's datacenter ASN list (MIT)**, not its IP list.
  - Every request already has an ASN, and the ASN list is small (about 950 lines).
  - It is downloaded at runtime by the weekly ASN unit (`hosting-refresh.sh`, failure tolerated) and never committed.
  - It is supporting evidence only, because VPN users sit on hosting networks.
- **Signals and thresholds.** A person clicking through the maze waits for each dripping page, so the behaviour thresholds sit well beyond that:
  - 30 maze pages in a minute;
  - 20 or more gaps with a coefficient of variation under 0.25;
  - depth 10;
  - following most of a page's links (5 or more) before it finished.
- **The browser checks are judged on HTTPS only.** Browsers send `Sec-Fetch-*` only to secure origins, and only HTTPS offers h2. The `Sec-Fetch-*` minimum versions are Chrome 76, Edge 79, Firefox 90 and Safari 16.4. iOS wrapper browsers (CriOS, FxiOS, …) are not judged, because they don't name their WebKit version.
- **"TLS like a library"** compares a browser-claiming client's JA4 with the JA4s that clients naming an HTTP library sent in the same window. Headless browsers are not libraries (they share real browsers' TLS), so they never mark a real Chrome.
- **Weights:**
  - 3: no browser does this;
  - 2: rare for a person;
  - 1: supporting.

  `hosting-network` and `browser-ua-no-favicon` never list a client on their own. No page declares an icon, so browsers fetch `/favicon.ico` themselves, but they cache it.
- **Untested:**
  - the divert/alternatives install and the custom Caddy on the real host;
  - JA4 behind real-world middleboxes.
- **Published on the wall as "Observed traits" (operator request).** Each group page lists the signals as plain facts ("claimed a browser user agent, but its TLS handshake did not offer HTTP/2…"), each with how many of the group's clients (address + user agent) showed it. The page also gives the fastest pace one client reached and the top five JA4 fingerprints.
  - **Section 8 still holds:**
    - only facts, no claims about intent;
    - each section carries a note that a trait is an observation, not a verdict on who or what a client is;
    - nothing is shown per address.
  - **Not published:**
    - the score, because a weighted sum is a judgment, not a fact;
    - reverse-DNS-based signals, because each is a lookup of one address;
    - the signals the wall already shows another way (UA names a bot, robots.txt, entered `/lawn/`).
  - **feed.json is unchanged.** Section 8 fixes its fields.
  - **Wall pages link to the homepage methodology, not to outside sites.** Wall pages carry no external links (existing rule). The methodology explains JA4 and each trait, and links to the JA4 spec and X4BNet.
  - **Recomputed at most hourly.** Traits scan every raw row (aggregates, frontier, timing), which is too much for every 5-minute rebuild on the 2 GB box. Builds in between reuse the last result; `lawn build-shame` computes fresh.
- **Existing logs are judged too.** Signals are computed from the raw log at report time, so the first run after deploy covers the last 90 days. JA4 exists only from this deploy on. Rows from before the `scheme` column (migration 6) count as HTTPS when they carry TLS details: back then only Caddy's HTTPS site reached the app, and plain HTTP (port 80, the onion mirror) never had TLS details.
