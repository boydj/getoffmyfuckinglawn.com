# CLAUDE.md

## Project
getoffmyfuckinglawn.com: AI-scraper tarpit + wall of shame. SPEC.md is the source of truth for what to build. DECISIONS.md logs every choice the spec didn't dictate.

## Autonomy
- Never stop to ask questions. Decide, log the decision in DECISIONS.md with a one-line rationale, keep going.
- If SPEC.md is wrong, fix the implementation sensibly and note the deviation in DECISIONS.md. Don't edit SPEC.md.
- Never run `make infra`, `make deploy`, `make destroy`, or any `tofu apply`/`destroy`. `tofu validate` and `tofu plan` are fine.

## Commands
- `make test` — unit + integration tests; must pass before every commit
- `go vet ./... && staticcheck ./...` — must be clean
- `tofu -chdir=infra validate`

## Code rules
- Go, stdlib first. Hot path: no blocking on SQLite or DNS, minimal allocations.
- Every package gets tests. Use fakes for DNS, clock, and network; no real network in unit tests.
- Config via config.yaml with env overrides. No secrets, .tfstate, ASN data, or *.db files in git.
- Small, focused commits with descriptive messages. One commit minimum per milestone.

## Hard rules
- Section 8 publication rules in SPEC.md are fixed. Never publish individual IPs outside verified corporate crawlers.
- Never fabricate crawler verification URLs or IP ranges. Official vendor docs only; otherwise `verify: none` + TODO.
- Maze content must never impersonate real people, brands, or news.

## Done
A milestone is done when tests, vet, and staticcheck pass and it's committed. The project is done when section 15's done criteria are met (short of actually applying), README covers setup/deploy/teardown, and a final summary lists what's untested and every TODO.
