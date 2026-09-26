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
