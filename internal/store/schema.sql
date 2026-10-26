-- Applied on every scanner start; must stay idempotent.
-- Tables hold raw per-run data. Views are the API for Grafana and any other consumer.

CREATE TABLE IF NOT EXISTS runs (
    id          bigserial PRIMARY KEY,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    status      text NOT NULL,  -- running | success | failed
    error       text
);

CREATE TABLE IF NOT EXISTS assets (
    run_id   bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    provider text, account text, kind text, name text, target text, source text
);

CREATE TABLE IF NOT EXISTS endpoints (
    run_id      bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host text, ip text, port int, url text, http_status int, title text,
    tech text[], cpe text[], scanner text
);

CREATE TABLE IF NOT EXISTS findings (
    run_id      bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    template_id text, name text, severity text, matched_at text, target text, scanner text,
    raw jsonb
);

CREATE TABLE IF NOT EXISTS events (
    run_id   bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    type text, target text, port int, severity text,
    provider text, account text, resource text, detail jsonb
);

CREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value text);

-- Findings someone has looked at and accepted, inserted by hand. They stay
-- visible on the dashboard but no longer alert. until = NULL means forever.
CREATE TABLE IF NOT EXISTS accepted (
    template_id text, matched_at text, reason text NOT NULL, until date,
    PRIMARY KEY (template_id, matched_at)
);

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS tags text[],
    ADD COLUMN IF NOT EXISTS exploited boolean NOT NULL DEFAULT false, -- in CISA KEV
    ADD COLUMN IF NOT EXISTS epss real;                                 -- exploit probability 0..1

ALTER TABLE endpoints
    ADD COLUMN IF NOT EXISTS service text,           -- ssh, redis, mysql, dns, ...
    ADD COLUMN IF NOT EXISTS protocol text NOT NULL DEFAULT 'tcp';

-- NVD answers cached per CPE so runs do not re-fetch every CVE list.
CREATE TABLE IF NOT EXISTS cve_cache (
    cpe        text PRIMARY KEY,
    cves       jsonb NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now()
);

-- Live progress, written every few seconds while a run is going (see
-- internal/progress). A phase is discovery, resolve or one scanner; a target
-- is what that phase works on: an IP, host:port, URL or hostname.
ALTER TABLE runs
    ADD COLUMN IF NOT EXISTS phase text,         -- phase currently running
    ADD COLUMN IF NOT EXISTS overall_pct real,
    ADD COLUMN IF NOT EXISTS eta timestamptz,    -- NULL until a previous run gives phase durations
    ADD COLUMN IF NOT EXISTS updated_at timestamptz;

CREATE TABLE IF NOT EXISTS run_phases (
    run_id bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    phase text NOT NULL, ord int NOT NULL,
    started_at timestamptz, finished_at timestamptz,
    done bigint NOT NULL, total bigint NOT NULL,
    PRIMARY KEY (run_id, phase)
);

CREATE TABLE IF NOT EXISTS run_targets (
    run_id bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    phase text NOT NULL, target text NOT NULL,
    host text, ip text, domain text,
    done int NOT NULL, total int NOT NULL,
    started_at timestamptz, finished_at timestamptz,
    PRIMARY KEY (run_id, phase, target)
);

CREATE INDEX IF NOT EXISTS assets_run_idx    ON assets (run_id);
CREATE INDEX IF NOT EXISTS endpoints_run_idx ON endpoints (run_id);
CREATE INDEX IF NOT EXISTS findings_run_idx  ON findings (run_id);
CREATE INDEX IF NOT EXISTS events_run_idx    ON events (run_id);
CREATE INDEX IF NOT EXISTS findings_key_idx  ON findings (template_id, matched_at, run_id);
CREATE INDEX IF NOT EXISTS endpoints_key_idx ON endpoints (host, port, run_id);
CREATE INDEX IF NOT EXISTS cve_cache_idx     ON cve_cache (fetched_at);

-- Views are recreated on every start so their columns can change freely.
DROP VIEW IF EXISTS v_latest_run, v_run_stats, v_baseline, v_run_deltas, v_current_endpoints,
    v_current_findings, v_events, v_latest_events, v_endpoint_ages, v_finding_ages,
    v_scan_status, v_scan_phases, v_scan_domains, v_scan_ips, v_scan_targets CASCADE;


-- Latest successful run.
CREATE VIEW v_latest_run AS
SELECT * FROM runs WHERE status = 'success' ORDER BY id DESC LIMIT 1;

-- Counts per successful run.
CREATE VIEW v_run_stats AS
SELECT r.id AS run_id, r.started_at, r.finished_at,
       (SELECT count(*) FROM assets a    WHERE a.run_id = r.id) AS assets,
       (SELECT count(*) FROM endpoints e WHERE e.run_id = r.id) AS endpoints,
       f.findings, f.critical, f.high, f.medium, f.exploited
FROM runs r
CROSS JOIN LATERAL (
    SELECT count(*) AS findings,
           count(*) FILTER (WHERE severity = 'critical') AS critical,
           count(*) FILTER (WHERE severity = 'high')     AS high,
           count(*) FILTER (WHERE severity = 'medium')   AS medium,
           count(*) FILTER (WHERE exploited)             AS exploited
    FROM findings WHERE run_id = r.id
) f
WHERE r.status = 'success';

-- Baseline for progress: settings.baseline_run_id, else the first successful run.
CREATE VIEW v_baseline AS
SELECT coalesce(
    (SELECT value::bigint FROM settings WHERE key = 'baseline_run_id'),
    (SELECT min(id) FROM runs WHERE status = 'success')
) AS run_id;

-- Per run: change vs previous run and progress toward zero vs baseline.
CREATE VIEW v_run_deltas AS
SELECT s.*,
       s.endpoints - lag(s.endpoints) OVER w AS endpoints_delta,
       s.findings  - lag(s.findings)  OVER w AS findings_delta,
       round(100.0 * (s.endpoints - lag(s.endpoints) OVER w) / nullif(lag(s.endpoints) OVER w, 0), 1)
           AS endpoints_delta_pct,
       b.endpoints AS baseline_endpoints,
       round(100.0 * (b.endpoints - s.endpoints) / nullif(b.endpoints, 0), 1) AS progress_pct
FROM v_run_stats s
LEFT JOIN v_run_stats b ON b.run_id = (SELECT run_id FROM v_baseline)
WINDOW w AS (ORDER BY s.run_id);

-- Since when an endpoint or finding of the latest run has been there without
-- a gap: the first run after the last successful run that did not have it.
CREATE VIEW v_endpoint_ages AS
WITH ok AS (SELECT id, finished_at FROM runs WHERE status = 'success')
SELECT c.host, c.port,
       (SELECT min(finished_at) FROM ok WHERE ok.id > coalesce((
            SELECT max(o.id) FROM ok o WHERE NOT EXISTS (
                SELECT 1 FROM endpoints x WHERE x.run_id = o.id AND x.host = c.host AND x.port = c.port)), 0)
       ) AS first_seen
FROM (SELECT DISTINCT host, port FROM endpoints WHERE run_id = (SELECT id FROM v_latest_run)) c;

CREATE VIEW v_finding_ages AS
WITH ok AS (SELECT id, finished_at FROM runs WHERE status = 'success')
SELECT c.template_id, c.matched_at,
       (SELECT min(finished_at) FROM ok WHERE ok.id > coalesce((
            SELECT max(o.id) FROM ok o WHERE NOT EXISTS (
                SELECT 1 FROM findings x WHERE x.run_id = o.id
                  AND x.template_id = c.template_id AND x.matched_at = c.matched_at)), 0)
       ) AS first_seen
FROM (SELECT DISTINCT template_id, matched_at FROM findings WHERE run_id = (SELECT id FROM v_latest_run)) c;

-- Current state, joined with the asset that produced each target.
CREATE VIEW v_current_endpoints AS
SELECT e.*, a.provider, a.account, a.name AS resource, a.source,
       g.first_seen, extract(day FROM now() - g.first_seen)::int AS age_days
FROM endpoints e
JOIN v_latest_run r ON e.run_id = r.id
LEFT JOIN v_endpoint_ages g ON g.host = e.host AND g.port = e.port
LEFT JOIN LATERAL (
    SELECT provider, account, name, source FROM assets
    WHERE run_id = e.run_id AND target = e.host LIMIT 1
) a ON true;

CREATE VIEW v_current_findings AS
SELECT f.run_id, f.template_id, f.name, f.severity, f.matched_at, f.target, f.scanner,
       a.provider, a.account, a.name AS resource,
       f.tags, f.exploited, f.epss,
       g.first_seen, extract(day FROM now() - g.first_seen)::int AS age_days,
       acc.reason IS NOT NULL AS accepted, acc.reason AS accepted_reason
FROM findings f
JOIN v_latest_run r ON f.run_id = r.id
LEFT JOIN v_finding_ages g ON g.template_id = f.template_id AND g.matched_at = f.matched_at
LEFT JOIN accepted acc ON acc.template_id = f.template_id AND acc.matched_at = f.matched_at
    AND (acc.until IS NULL OR acc.until >= current_date)
LEFT JOIN LATERAL (
    SELECT provider, account, name FROM assets
    WHERE run_id = f.run_id AND target = f.target LIMIT 1
) a ON true;

-- Events with the time of their run. Finding events carry accepted, so alert
-- rules can skip them. Not filtered on status: only successful runs have
-- events (failed runs keep partial data but are never diffed).
CREATE VIEW v_events AS
SELECT r.finished_at, ev.*,
       EXISTS (SELECT 1 FROM accepted acc
               WHERE acc.template_id = ev.detail->>'template_id' AND acc.matched_at = ev.detail->>'matched_at'
                 AND (acc.until IS NULL OR acc.until >= current_date)) AS accepted
FROM events ev JOIN runs r ON r.id = ev.run_id;

CREATE VIEW v_latest_events AS
SELECT ev.* FROM v_events ev JOIN v_latest_run r ON ev.run_id = r.id;

-- Progress of the latest run, running or not. Zoom levels: status (whole run)
-- -> phases -> domains -> IPs -> targets. stale = no update for 5 minutes
-- while "running", i.e. the scanner probably died.
CREATE VIEW v_scan_status AS
SELECT id AS run_id, status, started_at, finished_at, phase, overall_pct, eta, updated_at,
       coalesce(finished_at, now()) - started_at AS elapsed,
       CASE WHEN status = 'running' THEN eta - now() END AS remaining,
       status = 'running' AND updated_at < now() - interval '5 minutes' AS stale
FROM runs ORDER BY id DESC LIMIT 1;

-- Per phase of the latest run, with the duration of the previous successful
-- run to compare against.
CREATE VIEW v_scan_phases AS
SELECT p.run_id, p.ord, p.phase, p.done, p.total,
       round(100.0 * p.done / nullif(p.total, 0), 1) AS pct,
       CASE WHEN p.finished_at IS NOT NULL THEN 'done' WHEN p.started_at IS NULL THEN 'pending'
            WHEN r.status = 'running' THEN 'running' ELSE 'stopped' END AS state,
       p.started_at, p.finished_at,
       coalesce(p.finished_at, r.finished_at, now()) - p.started_at AS duration,
       prev.finished_at - prev.started_at AS previous_duration,
       (SELECT count(*) FROM run_targets t WHERE t.run_id = p.run_id AND t.phase = p.phase AND t.target <> '') AS targets,
       (SELECT count(*) FROM run_targets t WHERE t.run_id = p.run_id AND t.phase = p.phase AND t.target <> ''
            AND t.finished_at IS NOT NULL) AS targets_done
FROM run_phases p
JOIN runs r ON r.id = p.run_id
LEFT JOIN run_phases prev ON prev.phase = p.phase AND prev.run_id =
    (SELECT max(id) FROM runs WHERE status = 'success' AND id < p.run_id)
WHERE p.run_id = (SELECT run_id FROM v_scan_status);

-- Targets of the latest run; the raw rows the views below aggregate.
CREATE VIEW v_scan_targets AS
SELECT t.run_id, p.ord, t.phase, t.domain, t.ip, t.host, t.target, t.done, t.total,
       round(100.0 * t.done / nullif(t.total, 0), 1) AS pct,
       CASE WHEN t.finished_at IS NOT NULL THEN 'done' WHEN t.done = 0 THEN 'pending'
            WHEN r.status = 'running' THEN 'running' ELSE 'stopped' END AS state,
       t.started_at, t.finished_at, coalesce(t.finished_at, r.finished_at, now()) - t.started_at AS duration
FROM run_targets t
JOIN run_phases p ON p.run_id = t.run_id AND p.phase = t.phase
JOIN runs r ON r.id = t.run_id
WHERE t.run_id = (SELECT run_id FROM v_scan_status) AND t.target <> '';

CREATE VIEW v_scan_domains AS
SELECT run_id, ord, phase, coalesce(domain, '') AS domain,
       sum(done) AS done, sum(total) AS total, round(100.0 * sum(done) / nullif(sum(total), 0), 1) AS pct,
       count(DISTINCT ip) AS ips, count(*) AS targets, count(*) FILTER (WHERE state = 'done') AS targets_done
FROM v_scan_targets GROUP BY run_id, ord, phase, coalesce(domain, '');

CREATE VIEW v_scan_ips AS
SELECT run_id, ord, phase, coalesce(domain, '') AS domain, coalesce(ip, '') AS ip,
       string_agg(DISTINCT host, ', ') AS hosts,
       sum(done) AS done, sum(total) AS total, round(100.0 * sum(done) / nullif(sum(total), 0), 1) AS pct,
       count(*) AS targets, count(*) FILTER (WHERE state = 'done') AS targets_done,
       CASE WHEN bool_and(state = 'done') THEN 'done' WHEN bool_or(state = 'running') THEN 'running'
            WHEN bool_or(state = 'stopped') THEN 'stopped' ELSE 'pending' END AS state
FROM v_scan_targets GROUP BY run_id, ord, phase, coalesce(domain, ''), coalesce(ip, '');
