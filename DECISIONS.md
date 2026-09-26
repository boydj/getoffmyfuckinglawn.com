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
