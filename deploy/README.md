# Deploying getoffmyfuckinglawn.com

This is a draft for the top-level README. Everything here goes through `make`.

## What gets built

- **`infra/` (OpenTofu, Vultr provider)** creates one dedicated Debian 12 instance: `vc2-2c-2gb` (2 vCPU / 2 GB) in `ewr` by default, with IPv6. It also creates a firewall group (SSH only from your CIDRs; 80/443 and ICMP from anywhere), your SSH key, and a Vultr DNS zone with A and AAAA records for the apex and `www`. It generates `LAWN_SECRET` once with `random_password`.
- **cloud-init** runs on first boot. It writes the systemd units, scripts and Caddyfile from `deploy/`, puts the secret in `/etc/lawn/env`, and runs `deploy/host-setup.sh`. That script installs Caddy from its official apt repo plus sqlite3, and turns on unattended-upgrades (with auto-reboot at 04:30 UTC when needed). It also creates the `lawn` user and directories, sets journald caps and socket sysctls, enables the timers, and downloads the ASN dataset.
- **`make deploy`** builds a static linux/amd64 binary and sends it over SSH together with the templates, corpus, `crawlers.yaml` and the `deploy/` files. It runs `deploy/install.sh` on the host, which re-runs `host-setup.sh` (idempotent), swaps the binary in atomically, restarts `lawn` and health-checks it.

Host layout:

| Path | What |
|---|---|
| `/usr/local/bin/lawn` (`lawn.prev`) | binary (and the previous one, for rollback) |
| `/etc/lawn/config.yaml` | live config: created on the first deploy, then yours to edit |
| `/etc/lawn/config.example.yaml` | the latest example, kept so you can diff it against the live config |
| `/etc/lawn/crawlers.yaml` | crawler list (replaced on every deploy) |
| `/etc/lawn/env` | `LAWN_SECRET=...` (0640 root:lawn). Written once and never overwritten |
| `/etc/lawn/caddy.env` | `LAWN_DOMAIN=...` for the Caddyfile |
| `/opt/lawn/{corpus,templates}` | app files (WorkingDirectory) |
| `/var/lib/lawn/` | `lawn.db`, `ip2asn-combined.tsv.gz`, `public/`, `ranges/`, `backups/` |
| `/usr/local/lib/lawn/` | `host-setup.sh`, `asn-refresh.sh`, `backup.sh`, Caddyfile source |

The app listens on `127.0.0.1:8080` (the site) and `127.0.0.1:9090` (`/metrics`, `/healthz`). Caddy terminates TLS and proxies the domain to `:8080` unbuffered (`flush_interval -1`, no compression). It redirects `www` to the apex and writes no access logs of its own.

## First-time setup

Prerequisites on your machine: OpenTofu ≥ 1.8, Go (the version in `go.mod`), `make`, `ssh`, `tar`, and a Vultr account with an API key (Account → API; allow your IP in the key's access control).

1. Create the infra config and export the API key:

   ```sh
   cp infra/terraform.tfvars.example infra/terraform.tfvars
   $EDITOR infra/terraform.tfvars        # ssh_public_key_path, admin_cidrs
   export VULTR_API_KEY=...               # never put it in a file in the repo
   ```

2. Create the server, firewall, SSH key and DNS zone:

   ```sh
   make plan     # optional: review
   make infra    # tofu init + apply
   ```

   Outputs: `ipv4`, `ipv6`, `nameservers`, `ssh`. Cloud-init needs a couple of minutes to finish. You can watch it with `make ssh`, then `cloud-init status --wait`.

3. **At your registrar, set the domain's nameservers to `ns1.vultr.com` and `ns2.vultr.com`.** This is the only manual step. Caddy gets Let's Encrypt/ZeroSSL certificates automatically once DNS resolves to the box. If you want it to retry right away after the NS change has propagated, run `systemctl restart caddy` on the host.

4. Ship the app:

   ```sh
   make deploy
   ```

   `DEPLOY_HOST` and `LAWN_DOMAIN` default to the OpenTofu outputs. The deploy fails, and rolls back to `lawn.prev` when there is one, if `http://127.0.0.1:8080/healthz` isn't answering within 30 s. Before certificates exist, it only warns if the check through Caddy (HTTPS) fails.

5. Verify:

   ```sh
   curl -sI https://getoffmyfuckinglawn.com/            # 200 via Caddy
   curl -s  https://getoffmyfuckinglawn.com/robots.txt   # Disallow: /lawn/
   curl -sN https://getoffmyfuckinglawn.com/lawn/x | head -c 64   # arrives ~16 bytes/s
   make ssh   # then: systemctl status lawn caddy; systemctl list-timers 'lawn-*'
   ```

The leaderboard appears at `/shame/` after the first rebuild (every 5 min).

### Deploying to a host that isn't managed by OpenTofu

`deploy/` works on any fresh Debian 12 or Ubuntu 22.04+ box you can SSH into as root, or as a user with passwordless sudo:

```sh
make deploy DEPLOY_HOST=203.0.113.10 LAWN_DOMAIN=example.com [DEPLOY_USER=admin SSH_KEY=~/.ssh/id_ed25519]
```

On such a host, `host-setup.sh` generates `LAWN_SECRET` itself if `/etc/lawn/env` is missing. You also have to firewall SSH yourself.

## Routine deploys

```sh
make deploy
```

Deploys are safe to re-run. Here is what a deploy does to each file:

- Binary, templates, corpus, `crawlers.yaml`, units, timers, scripts and the Caddyfile are replaced.
- `config.yaml` is never overwritten. When the example's top-level keys change, the deploy prints a note; compare with `diff -u /etc/lawn/config.yaml /etc/lawn/config.example.yaml`.
- `/etc/lawn/env` (the secret) is never touched. Changing the secret changes every maze URL.

A restart drops the connections currently being dripped; crawlers come back on their own.

**From GitHub Actions:** the `deploy` workflow is run by hand from the Actions tab. It needs these repository or `production`-environment secrets:

- `SSH_PRIVATE_KEY`: a key whose public half is in root's `authorized_keys`.
- `DEPLOY_HOST`
- Ideally `SSH_KNOWN_HOSTS`: the output of `ssh-keyscan <ip>`, captured once from a trusted network.

Without `SSH_KNOWN_HOSTS`, the workflow trusts whatever host key it sees and emits a warning. SSH is restricted to `admin_cidrs`, and GitHub's runner IPs are not in that list by default. You need to add the relevant ranges to `admin_cidrs` or use a self-hosted runner.

## Logs and operations

```sh
make logs                                   # journalctl -u lawn -f on the host
make ssh
lawn stats -config /etc/lawn/config.yaml --since 24h     # top offenders
systemctl reload lawn                       # re-read ASN table + crawlers.yaml
systemctl start lawn-asn-refresh            # refresh ASN data now
systemctl start lawn-verify-refresh         # re-verify identities now
journalctl -u caddy -n 100                  # TLS / proxy problems
```

Timers:

- `lawn-asn-refresh.timer`: weekly iptoasn.com download. The file is validated (gzip, size, format) and swapped in atomically, then lawn is reloaded.
- `lawn-verify-refresh.timer`: daily `lawn verify-refresh`.
- `lawn-backup.timer`: nightly `VACUUM INTO` backups, keeping the newest 7.

Journald is capped at 200 MB and kept for at most a month. `/metrics` is only on `127.0.0.1:9090`, so reach it with `ssh -L 9090:127.0.0.1:9090 root@<ip>`.

## Backups and restore

Nightly backups go to `/var/lib/lawn/backups/lawn-YYYY-MM-DD.db`, and each one passes a `PRAGMA quick_check`. **They live on the same box**, so copy them off if you care about them:

```sh
scp root@<ip>:/var/lib/lawn/backups/lawn-2026-09-26.db .
```

Restore:

```sh
systemctl stop lawn
cd /var/lib/lawn
mv lawn.db lawn.db.broken; rm -f lawn.db-wal lawn.db-shm
install -o lawn -g lawn -m 0640 backups/lawn-2026-09-26.db lawn.db
systemctl start lawn
```

A backup taken right now: `systemctl start lawn-backup`.

## Teardown

```sh
make destroy
```

This deletes the instance (with its database and on-box backups), the firewall group, the SSH key and the **Vultr DNS zone with all its records**. Copy the backups off first. Afterwards, point the domain's nameservers somewhere else at the registrar, or it will stay delegated to Vultr with no zone. Local state (`infra/terraform.tfstate`, which also holds `LAWN_SECRET`) stays behind until you delete it.

## Cost and isolation

- `vc2-2c-2gb` cost about $15/month at the time of writing, with its included bandwidth measured in TB; check Vultr's current pricing. Vultr DNS is free. Automatic backups are off, since the box makes its own nightly SQLite backups.
- The maze's egress is capped by `limits.daily_egress_bytes` (5 GiB/day by default, about 150 GB/month), which stays well under the plan's transfer allowance.
- The box exists to attract abusive traffic, so it runs nothing else and has its own IP:
  - Don't co-host other services on it, and don't reuse its IP.
  - Only 80/443 (and ICMP) are open to the world; SSH is limited to `admin_cidrs`, and password SSH is off.
  - `lawn` runs as an unprivileged, heavily sandboxed systemd service with no capabilities, a read-only filesystem except `/var/lib/lawn`, and no access to the cloud metadata service (169.254.0.0/16), which holds the user-data and the secret.
- The secret is in the OpenTofu state and the instance's user-data. Treat `terraform.tfstate` as sensitive.
