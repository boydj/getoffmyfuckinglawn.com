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
