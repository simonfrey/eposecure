# exposure-scanner

Finds everything you expose to the internet and scans it from the outside, like an attacker would.
Discovery covers cloud inventories (GCP, AWS, Azure, … via [cloudlist]) and DNS. Scanning uses
ProjectDiscovery's [naabu], [httpx] and [nuclei] as Go libraries, plus a CVE lookup for detected
software versions, ranked by whether they are exploited in the wild (CISA KEV, EPSS). Results go
to Postgres. Grafana shows the dashboard and sends Slack alerts.

```
cloudlist (gcp, aws, …) ─┐
gcp_asset_search        ─┼─→ assets → IPs ─→ naabu → udp → httpx → banner → nuclei → cve_lookup → exploit_intel
dns (subfinder + dnsx)  ─┤                                   │
static_list             ─┘                                   ▼
                                       Postgres (runs, assets, endpoints, findings, events + views)
                                                             │
                                       Grafana: dashboard (login) + alert rules → Slack
```

Run it **outside** your cloud: firewall rules often allow the provider's own ranges (health
checks, IAP), so a scan from inside shows more than the internet sees.

## Quick start

```sh
cp .env.example .env                # set passwords, Slack webhook, cloud credentials
cp config.example.yaml config.yaml  # pick discovery modules and scanners
docker compose up -d
```

Grafana is at http://localhost:3000 (user `admin`, password `GF_SECURITY_ADMIN_PASSWORD`). The
scanner starts a run immediately, then repeats every `SCAN_INTERVAL_HOURS` (default 24).
To trigger a run by hand: `docker compose run --rm scanner run-once`.

## How a run works

1. All discovery modules run in parallel and return assets (provider, account, kind, name, target).
2. Targets are normalized, deduplicated and filtered by `exclude`. Hostnames are resolved, so
   each IP is port-scanned once. Every open port is then reported per hostname behind that IP, so
   HTTP probes and nuclei reach services routed by name (SNI, Host header). An IP that is only
   reached through a hostname, like a shared CDN or Cloud Run frontend, is never probed by IP.
   Hostnames that no longer resolve but still have a CNAME are not port-scanned. They go to
   nuclei's takeover templates instead.
3. Scanners run in config order, each building on the previous one: naabu finds open ports
   (TCP connect, no root), udp finds a few UDP services, httpx adds HTTP status, title,
   technologies and versioned CPEs, banner identifies non-HTTP services (SSH, Redis, MySQL, …),
   nuclei adds template findings, cve_lookup adds known CVEs per CPE from the [NVD API], and
   exploit_intel marks CVEs listed in [CISA KEV] and adds their [EPSS] score.
4. TCP ports open last run but missing now get a direct re-check. If they still accept
   connections they are kept, with their previous findings, so one dropped packet does not cause
   a "closed" alert followed by a "new" one. UDP ports have no such check.
5. Drift guard: if a discovery module suddenly returns nothing, or open endpoints drop by more
   than `max_endpoint_drop_pct` (default 50), the run fails instead of reporting mass closures.
   That is usually expired credentials or network trouble. If the drop is real, store it once with
   `docker compose run --rm scanner run-once --accept-drift`.
6. The result is compared with the previous successful run, which produces events
   (`new_endpoint`, `closed_endpoint`, `new_finding`, `resolved_finding`, `new_asset`, `removed_asset`,
   and `risk_changed` when a known finding changes severity, becomes exploited or its EPSS moves by 0.1).
7. Everything is stored in one transaction.

Only one run executes at a time (Postgres advisory lock), so a manual `run-once` next to `serve`
is safe: it is refused while a scan is running. A run killed mid-way (restart, crash) is marked
`failed` with error `interrupted` when the next run starts.

If any module fails, the whole run is marked `failed` and no diff happens. A partial inventory
would otherwise show up as falsely "closed" endpoints. What the run gathered until then is still
stored under its `run_id` for inspection (e.g. `SELECT * FROM endpoints WHERE run_id = <id>`), but
views, dashboard and alerts only ever read successful runs. The failure triggers the
`scan-stale-or-failed` alert. A run that takes longer than `RUN_TIMEOUT_HOURS` (default 6) is
aborted and fails the same way.

## Where results live

Postgres database `exposure`. Raw per-run tables: `runs`, `assets`, `endpoints`, `findings`,
`events`. The views are the stable interface for Grafana or anything else:

| View | Content |
|---|---|
| `v_latest_run` | latest successful run |
| `v_run_stats` | counts per run (assets, endpoints, findings by severity) |
| `v_run_deltas` | per run: change vs previous run, `progress_pct` vs baseline |
| `v_current_endpoints` / `v_current_findings` | latest state, joined with provider/account/resource, `first_seen` and `age_days`; endpoints carry `protocol` and `service`; findings also carry `exploited`, `epss`, `tags`, `accepted` |
| `v_events` / `v_latest_events` | changes between runs |
| `accepted` (table) | findings accepted by hand, see Triage |
| `cve_cache` (table) | NVD answers per CPE, reused for `cache_ttl_hours` |

Baseline: the first successful run, or `BASELINE_RUN_ID` from `.env`.

```sh
docker compose exec postgres psql -U exposure -c 'SELECT * FROM v_run_deltas ORDER BY run_id DESC LIMIT 5'
```

## Watching a run

A run can take hours. While it goes, the scanner logs a `progress` line every
`PROGRESS_LOG_SECONDS` (default 30) and writes the same numbers to Postgres every 10 seconds:

```
progress run=12 overall=41.3% eta=1h12m0s phase=nuclei step=6/7 phase_done=37.0% units=48100/130000 phase_eta=58m10s targets=12/130 ips=2/29 active="https://a.example.com 87/1000, ..."
target done phase=naabu target=203.0.113.7 ip=203.0.113.7 domain=example.com targets=3/29
```

A phase is discovery, resolve or one scanner (a scanner configured twice is `nuclei#2`). Each
phase counts its own units of work per target: names (resolve), IPs (naabu), probes per host:port
(httpx, banner, udp), templates per URL or host:port (nuclei), CPEs (cve_lookup). `overall`
weighs each phase by how long it took in the previous successful run, and `eta` is unknown until
there is one. nuclei targets can stop just short of their total (templates that do not apply to
that kind of target); the phase end sets them to done.

| View | Zoom level |
|---|---|
| `v_scan_status` | latest run: status, current phase, `overall_pct`, `eta`, `remaining`, `stale` (no update for 5 min) |
| `v_scan_phases` | per phase: done/total, state, duration vs the previous run, targets done |
| `v_scan_domains` | per phase and domain (asset account: DNS root domain or cloud project) |
| `v_scan_ips` | per phase and IP, with the hostnames behind it |
| `v_scan_targets` | per phase and target (IP, host:port, URL); raw rows are in `run_targets` |

```sh
docker compose exec postgres psql -U exposure -c "SELECT ip, hosts, state, pct, targets_done, targets FROM v_scan_ips WHERE phase = 'nuclei'"
```

The dashboard has the same in its collapsed "Current run" row, filtered by the `Run phase` variable.
Failed runs keep their progress rows, so they also show where a run stopped.

## Alerts (Slack, via Grafana)

| Rule | When |
|---|---|
| Scan report | every successful run: endpoint count, change vs last run, progress vs baseline, findings |
| New public endpoints | a host:port that was not open in the previous run |
| Closed public endpoints | a host:port that is no longer open |
| Actively exploited vulnerabilities | a new finding whose CVE is in CISA KEV |
| Finding risk increased | a known finding is now in CISA KEV, or was raised to high/critical |
| New assets | discovery found a resource that was not there in the previous run |
| New findings | a new medium/high/critical nuclei or CVE finding (not exploited) |
| New exposures | a new info/low finding tagged panel, exposure, misconfig, default-login, takeover or ssl |
| Findings overdue | weekly: exploited, critical or high open > 30 days, medium > 90 days |
| Scan failed or stale | the last run failed (including the drift guard), or no success for 36 h |

The first run reports everything as new. Accepted findings never alert. Rules live in
`grafana/provisioning/alerting/rules.yaml`.

## Triage

- **New endpoint**: find the owner from `account` and `resource` in the alert. Is it supposed to be
  public? If not, close it with a firewall rule or ingress setting, or remove the public IP. The next
  run reports it as closed. If it is intentional, accept it, or add it to `exclude` if it must never
  be scanned.
- **New finding**: open the dashboard's *Current findings* table. It is ordered by real-world
  risk: actively exploited first, then severity, then EPSS (the probability of exploitation in the
  next 30 days). Each `template_id` links to its details: the NVD entry for CVEs, the
  ProjectDiscovery template library for nuclei findings. For CVE findings, check whether the
  detected version (from the banner) is really what is running, since distros backport fixes.
  Patch or restrict access. Fixed findings show up as `resolved_finding` on the next run.
- **Exposure** (admin panel, leaked `.git` or `.env`, default login): these should almost never be
  public. Restrict access first, then rotate anything the leaked file contained.
- **Takeover** (dangling CNAME): the name points at a cloud resource that no longer exists, so
  anyone may be able to claim it and serve content under your domain. Delete the DNS record.
- **UDP findings** (open DNS resolver, SNMP `public`, SSDP, TFTP): these services should not answer
  the internet. They leak information and can be abused for amplification attacks. Firewall them.
- **Accept a finding** that is a false positive or a known risk. It stays on the dashboard (toggle
  *Show accepted*) but stops alerting. Leave `until` empty to accept it forever:
  ```sh
  docker compose exec postgres psql -U exposure -c "INSERT INTO accepted VALUES
    ('CVE-2021-23017', 'https://www.example.com', 'resolver not used', '2027-01-31')"
  ```
- **Scan failed**: `docker compose logs scanner`, or `SELECT id, error FROM runs ORDER BY id DESC LIMIT 5`.
  Common causes are expired credentials, API quota, or the NVD API being down (retried 3 times; CPEs seen before fall back to the cache).
  A drift guard error names the module or the drop. The rejected run's data is stored, so you can
  compare it with the last successful run. Fix the cause, or run once with
  `--accept-drift` if the change is real.

## Configuration

`config.yaml` lists modules in order. Each entry has `use: <module>` plus that module's own
options. `${VAR}` is replaced with environment variables from `.env`. See `config.example.yaml`
for all options.

| Discovery | |
|---|---|
| `cloudlist` | any [cloudlist] provider; the `providers` blocks are passed through unchanged |
| `gcp_asset_search` | Cloud Asset Inventory search across the org for every public IP and Cloud Run / Functions / App Engine URL; `asset_types` to narrow |
| `dns` | subfinder passive subdomain enumeration (incl. certificate transparency) for `root_domains`; keeps names that resolve, and names with a dangling CNAME as takeover candidates |
| `static_list` | fixed `targets`: IPs, CIDRs (up to `max_ips`, default 4096) or hostnames |

| Scanner | |
|---|---|
| `naabu` | port scan, `top_ports` plus `extra_ports` (default: cloud service ports outside the top 1000), `rate` |
| `udp` | DNS, TFTP, NTP, SNMP and SSDP on the listed `ports` (off when empty); only replies count as open |
| `httpx` | HTTP probe, tech detection; `follow_host_redirects` (default on) follows redirects on the same host only |
| `banner` | service on non-HTTP ports; versioned CPEs only for exact upstream versions (distro builds with backports are skipped) |
| `nuclei` | templates by `severities`, `tags`, `exclude_tags` (default `dos`, `fuzz`, `intrusive`), `exclude_ids`, `rate_limit`, `concurrency`; `takeover_candidates` adds dangling CNAMEs as targets; templates auto-update into the `scanner-home` volume. Use it twice: once for vulnerabilities, once for exposures at any severity (see `config.example.yaml`) |
| `cve_lookup` | NVD CVEs for detected versions, `min_severity`, optional `api_key` (10× faster), `cache_ttl_hours` (default 20; stale entries are used if NVD is down) |
| `exploit_intel` | marks CVE findings in [CISA KEV] and adds [EPSS]; put it last |

Rates default to conservative values so they don't trip Cloud Armor or production rate limits.

### Adding a cloud provider

Add a block under `cloudlist.providers` and its credentials to `.env`. No code changes:

```yaml
- provider: aws
  id: aws-prod
  aws_access_key: ${AWS_ACCESS_KEY_ID}
  aws_secret_key: ${AWS_SECRET_ACCESS_KEY}
```

### Adding a module

1. Create a package under `internal/discovery/` or `internal/scanners/` with
   `New(config.Options) (*T, error)` and the `Discoverer` or `Scanner` methods
   (`internal/registry/registry.go`).
2. Add one line to the map in `registry.go`.
3. Use it in `config.yaml`.

## GCP setup

`gcp/main.tf` creates a read-only service account with org-level `cloudasset.viewer`,
`organizationViewer`, `folderViewer` and `browser`, and puts a key into Secret Manager. An org
admin applies it by hand. The Terraform state contains the key, so keep it somewhere safe.

```sh
cd gcp && terraform init && terraform apply -var org_id=… -var project_id=…
gcloud secrets versions access latest --secret exposure-scanner-key | jq -c .
# put the output in .env as GCP_SERVICE_ACCOUNT_KEY='…' (single quotes)
```

Rotate the key every 90 days: `terraform apply -replace=google_service_account_key.scanner`,
update `.env`, then `docker compose up -d scanner`.

## Acceptance test

1. Create a test VM with a public IP and something listening on port 8080, allowed by firewall.
2. `docker compose run --rm scanner run-once`. Expect a *New public endpoints* alert for `<ip>:8080`.
3. Remove the firewall rule and run again. Expect *Closed public endpoints*. If the test VM is
   most of what you expose, the drift guard fails this run; repeat it with `run-once --accept-drift`.

## Operating notes

- Check your hosting provider's acceptable-use policy on port scanning, and tell them in advance
  if needed. Some (e.g. Hetzner) send abuse notices even for scans of your own IPs.
- Never allowlist the scanner's IP in your firewalls, or the results stop reflecting the internet's view.
- The scanner only scans targets that come from discovery; nothing else is ever touched.

## Development

```sh
go test ./...
golangci-lint run ./...            # includes gosec, config in .golangci.yml
docker compose build
```

### Linting (for CI)

Lint with [golangci-lint] v2.15.0 (`.golangci.yml`), which runs the standard linters plus
[gosec], errorlint, bodyclose, noctx, revive and goimports. To suppress a gosec finding, write
`// #nosec G304 -- reason`; both golangci-lint and standalone gosec honor it.

Standalone gosec v2.29.0 also produces SARIF for GitHub code scanning. That release can't read
Go 1.27 export data yet (it partly fails type-checking with "export data version 5"), so use the
golangci-lint run as the gate until gosec ships a fix.

Suggested GitHub Actions steps:

```yaml
- uses: actions/setup-go@v6
  with: { go-version: "1.27.3" }
- run: go test ./...
- uses: golangci/golangci-lint-action@v9
  with: { version: v2.15.0 }
- run: go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -no-fail -fmt sarif -out gosec.sarif ./...
- uses: github/codeql-action/upload-sarif@v4
  with: { sarif_file: gosec.sarif }
```

[cloudlist]: https://github.com/projectdiscovery/cloudlist
[naabu]: https://github.com/projectdiscovery/naabu
[httpx]: https://github.com/projectdiscovery/httpx
[nuclei]: https://github.com/projectdiscovery/nuclei
[NVD API]: https://nvd.nist.gov/developers/vulnerabilities
[CISA KEV]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[EPSS]: https://www.first.org/epss/
[golangci-lint]: https://golangci-lint.run/
[gosec]: https://github.com/securego/gosec
