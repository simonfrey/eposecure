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

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS tags text[],
    ADD COLUMN IF NOT EXISTS exploited boolean NOT NULL DEFAULT false, -- in CISA KEV
    ADD COLUMN IF NOT EXISTS epss real;                                 -- exploit probability 0..1

CREATE INDEX IF NOT EXISTS assets_run_idx    ON assets (run_id);
CREATE INDEX IF NOT EXISTS endpoints_run_idx ON endpoints (run_id);
CREATE INDEX IF NOT EXISTS findings_run_idx  ON findings (run_id);
CREATE INDEX IF NOT EXISTS events_run_idx    ON events (run_id);

-- Views are recreated on every start so their columns can change freely.
DROP VIEW IF EXISTS v_latest_run, v_run_stats, v_baseline, v_run_deltas, v_current_endpoints,
    v_current_findings, v_events, v_latest_events CASCADE;

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

-- Current state, joined with the asset that produced each target.
CREATE VIEW v_current_endpoints AS
SELECT e.*, a.provider, a.account, a.name AS resource, a.source
FROM endpoints e
JOIN v_latest_run r ON e.run_id = r.id
LEFT JOIN LATERAL (
    SELECT provider, account, name, source FROM assets
    WHERE run_id = e.run_id AND target = e.host LIMIT 1
) a ON true;

CREATE VIEW v_current_findings AS
SELECT f.run_id, f.template_id, f.name, f.severity, f.matched_at, f.target, f.scanner,
       a.provider, a.account, a.name AS resource,
       f.tags, f.exploited, f.epss
FROM findings f
JOIN v_latest_run r ON f.run_id = r.id
LEFT JOIN LATERAL (
    SELECT provider, account, name FROM assets
    WHERE run_id = f.run_id AND target = f.target LIMIT 1
) a ON true;

-- Events with the time of their run.
CREATE VIEW v_events AS
SELECT r.finished_at, ev.*
FROM events ev JOIN runs r ON r.id = ev.run_id;

CREATE VIEW v_latest_events AS
SELECT ev.* FROM v_events ev JOIN v_latest_run r ON ev.run_id = r.id;
