// Package store persists runs in Postgres.
package store

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/simonfrey/exposure-scanner/internal/model"
)

//go:embed schema.sql
var schema string

type Store struct{ db *pgxpool.Pool }

// Open connects and applies the schema.
func Open(ctx context.Context, url string) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

// SetBaseline pins the run that progress is measured against. Empty clears it.
func (s *Store) SetBaseline(ctx context.Context, runID string) error {
	if runID == "" {
		_, err := s.db.Exec(ctx, `DELETE FROM settings WHERE key = 'baseline_run_id'`)
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO settings VALUES ('baseline_run_id', $1)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, runID)
	return err
}

// ErrRunInProgress is returned by StartRun while another process is scanning.
var ErrRunInProgress = errors.New("another run is in progress")

const runLock = 7_265_031 // arbitrary advisory lock key, one run at a time

// StartRun takes the run lock, marks runs left over from a crash as failed,
// and records a new running run. Call the returned release when the run is done.
func (s *Store) StartRun(ctx context.Context) (id int64, release func(), err error) {
	conn, err := s.db.Acquire(ctx) // session-level lock lives on this connection
	if err != nil {
		return 0, nil, err
	}
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, runLock).Scan(&locked); err != nil || !locked {
		conn.Release()
		if err == nil {
			err = ErrRunInProgress
		}
		return 0, nil, err
	}
	release = func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, runLock)
		conn.Release()
	}

	if _, err := conn.Exec(ctx, `UPDATE runs SET status = 'failed', finished_at = now(), error = 'interrupted'
		WHERE status = 'running'`); err != nil {
		release()
		return 0, nil, err
	}
	if err := conn.QueryRow(ctx, `INSERT INTO runs (status) VALUES ('running') RETURNING id`).Scan(&id); err != nil {
		release()
		return 0, nil, err
	}
	return id, release, nil
}

// FailRun marks a run as failed and keeps what it gathered for inspection.
// LastSnapshot and the views only read successful runs, so the partial data
// never becomes current state or feeds a diff. A failed run has no events.
func (s *Store) FailRun(ctx context.Context, id int64, runErr error, snap model.Snapshot) error {
	const fail = `UPDATE runs SET status = 'failed', finished_at = now(), error = $2 WHERE id = $1`
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := insertSnapshot(ctx, tx, id, snap, nil); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, fail, id, runErr.Error())
		return err
	})
	if err != nil { // the partial data is lost, but the run must still show as failed
		_, uerr := s.db.Exec(ctx, fail, id, runErr.Error())
		return errors.Join(fmt.Errorf("storing partial data: %w", err), uerr)
	}
	return nil
}

// FinishRun stores the snapshot and events and marks the run successful, atomically.
func (s *Store) FinishRun(ctx context.Context, id int64, snap model.Snapshot, events []model.Event) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if err := insertSnapshot(ctx, tx, id, snap, events); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE runs SET status = 'success', finished_at = now() WHERE id = $1`, id)
		return err
	})
}

func insertSnapshot(ctx context.Context, tx pgx.Tx, id int64, snap model.Snapshot, events []model.Event) error {
	inserts := []struct {
		table string
		cols  []string
		rows  [][]any
	}{
		{"assets", []string{"run_id", "provider", "account", "kind", "name", "target", "source"},
			rows(snap.Assets, func(a model.Asset) []any {
				return []any{id, a.Provider, a.Account, a.Kind, a.Name, a.Target, a.Source}
			})},
		{"endpoints", []string{"run_id", "host", "ip", "port", "url", "http_status", "title", "tech", "cpe", "scanner", "service", "protocol"},
			rows(snap.Endpoints, func(e model.Endpoint) []any {
				proto := e.Protocol
				if proto == "" {
					proto = "tcp"
				}
				return []any{id, e.Host, e.IP, e.Port, e.URL, e.HTTPStatus, e.Title, e.Tech, e.CPE, e.Scanner, e.Service, proto}
			})},
		{"findings", []string{"run_id", "template_id", "name", "severity", "matched_at", "target", "scanner",
			"tags", "exploited", "epss", "raw"},
			rows(snap.Findings, func(f model.Finding) []any {
				return []any{id, f.TemplateID, f.Name, f.Severity, f.MatchedAt, f.Target, f.Scanner,
					f.Tags, f.Exploited, f.EPSS, jsonb(f.Raw)}
			})},
		{"events", []string{"run_id", "type", "target", "port", "severity", "provider", "account", "resource", "detail"},
			rows(events, func(e model.Event) []any {
				return []any{id, e.Type, e.Target, nullIfZero(e.Port), e.Severity, e.Provider, e.Account, e.Resource, jsonb(e.Detail)}
			})},
	}
	for _, in := range inserts {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{in.table}, in.cols, pgx.CopyFromRows(in.rows)); err != nil {
			return err
		}
	}
	return nil
}

// LastSnapshot loads the most recent successful run. Returns an empty
// snapshot if there is none yet.
func (s *Store) LastSnapshot(ctx context.Context) (model.Snapshot, error) {
	var snap model.Snapshot
	var id int64
	err := s.db.QueryRow(ctx, `SELECT id FROM runs WHERE status = 'success' ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return snap, nil
	}
	if err != nil {
		return snap, err
	}

	snap.Assets, err = query(ctx, s.db, `SELECT provider, account, kind, name, target, source FROM assets WHERE run_id = $1`, id,
		func(r pgx.CollectableRow) (a model.Asset, err error) {
			err = r.Scan(&a.Provider, &a.Account, &a.Kind, &a.Name, &a.Target, &a.Source)
			return
		})
	if err != nil {
		return snap, err
	}
	snap.Endpoints, err = query(ctx, s.db, `SELECT host, ip, port, coalesce(url, ''), coalesce(http_status, 0),
		coalesce(title, ''), tech, cpe, coalesce(scanner, ''), coalesce(service, ''), coalesce(protocol, 'tcp')
		FROM endpoints WHERE run_id = $1`, id,
		func(r pgx.CollectableRow) (e model.Endpoint, err error) {
			err = r.Scan(&e.Host, &e.IP, &e.Port, &e.URL, &e.HTTPStatus, &e.Title, &e.Tech, &e.CPE,
				&e.Scanner, &e.Service, &e.Protocol)
			return
		})
	if err != nil {
		return snap, err
	}
	snap.Findings, err = query(ctx, s.db, `SELECT template_id, name, severity, matched_at, target, scanner,
		tags, exploited, coalesce(epss, 0) FROM findings WHERE run_id = $1`, id,
		func(r pgx.CollectableRow) (f model.Finding, err error) {
			err = r.Scan(&f.TemplateID, &f.Name, &f.Severity, &f.MatchedAt, &f.Target, &f.Scanner,
				&f.Tags, &f.Exploited, &f.EPSS)
			return
		})
	return snap, err
}

func query[T any](ctx context.Context, db *pgxpool.Pool, sql string, id int64, scan pgx.RowToFunc[T]) ([]T, error) {
	r, err := db.Query(ctx, sql, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(r, scan)
}

// CVECacheEntry is one CPE's cached NVD answer. Data is the raw JSON of the
// scanner's own result type, so the store stays scanner-agnostic.
type CVECacheEntry struct {
	Data      []byte
	FetchedAt time.Time
}

// GetCVECache loads cached NVD answers for the given CPEs. Missing CPEs are
// simply absent from the returned map.
func (s *Store) GetCVECache(ctx context.Context, cpes []string) (map[string]CVECacheEntry, error) {
	out := make(map[string]CVECacheEntry, len(cpes))
	if len(cpes) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `SELECT cpe, cves::text, fetched_at FROM cve_cache WHERE cpe = ANY($1)`, cpes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cpe, data string
		var e CVECacheEntry
		if err := rows.Scan(&cpe, &data, &e.FetchedAt); err != nil {
			return nil, err
		}
		e.Data = []byte(data)
		out[cpe] = e
	}
	return out, rows.Err()
}

// PutCVECache stores NVD answers per CPE, replacing any previous value.
func (s *Store) PutCVECache(ctx context.Context, entries map[string][]byte) error {
	for cpe, data := range entries {
		if _, err := s.db.Exec(ctx, `INSERT INTO cve_cache (cpe, cves, fetched_at) VALUES ($1, $2, now())
			ON CONFLICT (cpe) DO UPDATE SET cves = excluded.cves, fetched_at = now()`, cpe, json.RawMessage(data)); err != nil {
			return err
		}
	}
	return nil
}

func rows[T any](items []T, f func(T) []any) [][]any {
	out := make([][]any, len(items))
	for i, it := range items {
		out[i] = f(it)
	}
	return out
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func jsonb(v any) []byte {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return stripNUL(b)
}

// stripNUL replaces the escape \u0000 in JSON with \ufffd: Postgres jsonb
// rejects NUL, and raw responses of binary protocols (e.g. a nuclei network
// template against Redis) contain it. Escape pairs are walked so that an
// escaped backslash followed by "u0000" is left alone.
func stripNUL(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		if bytes.HasPrefix(b[i:], []byte(`\u0000`)) {
			out = append(out, `\ufffd`...)
			i += 5
			continue
		}
		out = append(out, b[i], b[i+1]) // any other escape pair, e.g. \\
		i++
	}
	return out
}
