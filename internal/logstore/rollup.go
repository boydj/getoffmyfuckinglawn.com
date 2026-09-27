package logstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const dayMs = int64(24 * time.Hour / time.Millisecond)

// RetentionCutoff returns the UTC midnight at or before now-keepDays. Raw
// rows with ts_start before it are eligible for rollup.
func RetentionCutoff(now time.Time, keepDays int) time.Time {
	t := now.UTC().AddDate(0, 0, -keepDays)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// dayAgg is one pending daily_aggregates row.
type dayAgg struct {
	ip, ua    string
	asn       sql.NullInt64
	asnOrg    sql.NullString
	pages     int64
	heldMs    int64
	bytes     int64
	maxDepth  sql.NullInt64
	sessions  int64
	readRules int64
	firstTs   int64
	lastTs    int64
	// firstEvent is the ts_start of the pair's first row of the day (any
	// path) and firstSess the first derived session; used to detect a
	// session continuing from the previous UTC day.
	firstEvent int64
	firstSess  Session
}

// Rollup implements SPEC.md section 9 retention: requests with ts_start
// before RetentionCutoff(now, keepDays) are aggregated per (UTC day, ip,
// user_agent) into daily_aggregates and deleted. Each UTC day is processed in
// its own transaction so a large backlog never becomes one huge transaction.
// robots_fetches older than the cutoff are deleted too. Running it again is a
// no-op; rows that arrive late for an already-rolled day are merged.
//
// Sessions are derived per day from all of the pair's rows that day
// (including /robots.txt so read_rules works). A session that continues from
// the previous day (its first row starts less than gapMs after the previous
// day's aggregate last_ts) is not counted again.
func (s *Store) Rollup(ctx context.Context, now time.Time, keepDays int, gapMs int64) (rolled int64, err error) {
	if keepDays <= 0 {
		return 0, errors.New("logstore: rollup: keepDays must be > 0")
	}
	if gapMs <= 0 {
		return 0, errors.New("logstore: rollup: gapMs must be > 0")
	}
	cutoff := RetentionCutoff(now, keepDays).UnixMilli()
	for {
		if err := ctx.Err(); err != nil {
			return rolled, err
		}
		minTs, ok, err := s.oldestRequest(ctx, cutoff)
		if err != nil {
			return rolled, err
		}
		if !ok {
			break
		}
		dayStart := floorDay(minTs)
		dayEnd := min(dayStart+dayMs, cutoff)
		n, err := s.rollupDay(ctx, dayStart, dayEnd, gapMs)
		rolled += n
		if err != nil {
			return rolled, err
		}
	}
	if err := s.deleteOldRobots(ctx, cutoff); err != nil {
		return rolled, err
	}
	return rolled, nil
}

func floorDay(ms int64) int64 {
	d := ms / dayMs * dayMs
	if ms < 0 && d != ms {
		d -= dayMs
	}
	return d
}

func dayString(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02") }

// oldestRequest finds min(ts_start) below cutoff. It queries each
// is_violation value separately so idx_req_violation(is_violation, ts_start)
// answers with an index seek instead of a table scan.
func (s *Store) oldestRequest(ctx context.Context, cutoff int64) (int64, bool, error) {
	var best int64
	found := false
	for _, v := range []int{0, 1} {
		var m sql.NullInt64
		if err := s.db.QueryRowContext(ctx,
			`SELECT MIN(ts_start) FROM requests WHERE is_violation = ? AND ts_start < ?`, v, cutoff).Scan(&m); err != nil {
			return 0, false, fmt.Errorf("logstore: rollup: oldest: %w", err)
		}
		if m.Valid && (!found || m.Int64 < best) {
			best, found = m.Int64, true
		}
	}
	return best, found, nil
}

func isRobotsPath(p string) bool {
	return p == "/robots.txt" || strings.HasPrefix(p, "/robots.txt?")
}

func (s *Store) rollupDay(ctx context.Context, dayStart, dayEnd, gapMs int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT ip, COALESCE(user_agent, ''), ts_start, ts_end, asn, asn_org, path, depth, is_violation, bytes_sent
	 FROM requests WHERE is_violation IN (0, 1) AND ts_start >= ? AND ts_start < ?
	 ORDER BY ip, user_agent, ts_start, id`, dayStart, dayEnd)
	if err != nil {
		return 0, fmt.Errorf("logstore: rollup: select: %w", err)
	}
	var (
		aggs   []*dayAgg
		cur    *dayAgg
		events []Event
	)
	finish := func() {
		if cur == nil {
			return
		}
		if cur.pages > 0 {
			sess := DeriveSessions(events, gapMs)
			for _, se := range sess {
				if se.Pages > 0 {
					cur.sessions++
					if se.ReadRules {
						cur.readRules++
					}
				}
			}
			cur.firstSess = sess[0]
			aggs = append(aggs, cur)
		}
		cur = nil
		events = events[:0]
	}
	for rows.Next() {
		var (
			ip, ua, path string
			tsStart      int64
			tsEnd, depth sql.NullInt64
			bytes, asn   sql.NullInt64
			asnOrg       sql.NullString
			isViol       int
		)
		if err := rows.Scan(&ip, &ua, &tsStart, &tsEnd, &asn, &asnOrg, &path, &depth, &isViol, &bytes); err != nil {
			rows.Close()
			return 0, fmt.Errorf("logstore: rollup: scan: %w", err)
		}
		if cur == nil || cur.ip != ip || cur.ua != ua {
			finish()
			cur = &dayAgg{ip: ip, ua: ua, firstEvent: tsStart}
		}
		ev := Event{TsStart: tsStart, TsEnd: tsEnd.Int64, IsViolation: isViol == 1, IsRobots: isRobotsPath(path),
			Depth: int(depth.Int64), Bytes: bytes.Int64}
		events = append(events, ev)
		if asn.Valid {
			cur.asn = asn
		}
		if asnOrg.Valid {
			cur.asnOrg = asnOrg
		}
		if !ev.IsViolation {
			continue
		}
		end := max(tsStart, tsEnd.Int64)
		if cur.pages == 0 || tsStart < cur.firstTs {
			cur.firstTs = tsStart
		}
		if end > cur.lastTs {
			cur.lastTs = end
		}
		cur.pages++
		cur.heldMs += HeldMs(tsStart, tsEnd.Int64)
		cur.bytes += bytes.Int64
		if depth.Valid && (!cur.maxDepth.Valid || depth.Int64 > cur.maxDepth.Int64) {
			cur.maxDepth = depth
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("logstore: rollup: rows: %w", err)
	}
	finish()
	rows.Close()

	day, prevDay := dayString(dayStart), dayString(dayStart-dayMs)
	prevSt, err := tx.PrepareContext(ctx, `SELECT last_ts FROM daily_aggregates WHERE day = ? AND ip = ? AND user_agent = ?`)
	if err != nil {
		return 0, err
	}
	defer prevSt.Close()
	upSt, err := tx.PrepareContext(ctx, `INSERT INTO daily_aggregates
	 (day, ip, user_agent, asn, asn_org, pages, held_ms, bytes_sent, max_depth, sessions, read_rules, first_ts, last_ts)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
	 ON CONFLICT(day, ip, user_agent) DO UPDATE SET
	   asn = COALESCE(excluded.asn, asn),
	   asn_org = COALESCE(excluded.asn_org, asn_org),
	   pages = pages + excluded.pages,
	   held_ms = held_ms + excluded.held_ms,
	   bytes_sent = bytes_sent + excluded.bytes_sent,
	   max_depth = CASE WHEN max_depth IS NULL THEN excluded.max_depth
	                    WHEN excluded.max_depth IS NULL THEN max_depth
	                    ELSE MAX(max_depth, excluded.max_depth) END,
	   sessions = sessions + excluded.sessions,
	   read_rules = read_rules + excluded.read_rules,
	   first_ts = MIN(first_ts, excluded.first_ts),
	   last_ts = MAX(last_ts, excluded.last_ts)`)
	if err != nil {
		return 0, err
	}
	defer upSt.Close()
	for _, a := range aggs {
		var prevLast int64
		err := prevSt.QueryRowContext(ctx, prevDay, a.ip, a.ua).Scan(&prevLast)
		switch {
		case err == sql.ErrNoRows:
		case err != nil:
			return 0, fmt.Errorf("logstore: rollup: prev day: %w", err)
		case a.firstEvent-prevLast < gapMs && a.firstSess.Pages > 0:
			// The first session began yesterday and was counted there.
			a.sessions--
			if a.firstSess.ReadRules {
				a.readRules--
			}
		}
		if _, err := upSt.ExecContext(ctx, day, a.ip, a.ua, a.asn, a.asnOrg, a.pages, a.heldMs, a.bytes,
			a.maxDepth, a.sessions, a.readRules, a.firstTs, a.lastTs); err != nil {
			return 0, fmt.Errorf("logstore: rollup: upsert: %w", err)
		}
	}

	// Every visitor, violator or not, keeps a per-day summary so compliant
	// bots and new-bot detection have history beyond raw retention.
	if _, err := tx.ExecContext(ctx, `INSERT INTO daily_visits
	 (day, ip, user_agent, asn, asn_org, requests, robots, bait_views, violations, first_ts, last_ts)
	 SELECT ?, ip, COALESCE(user_agent, ''), MAX(asn), MAX(asn_org), COUNT(*),
	   SUM(method = 'GET' AND (path = '/robots.txt' OR path LIKE '/robots.txt?%')),
	   SUM(method = 'GET' AND (path IN ('/', '/sitemap.xml') OR path LIKE '/?%' OR path LIKE '/sitemap.xml?%')),
	   SUM(is_violation),
	   MIN(ts_start), MAX(MAX(ts_start, COALESCE(ts_end, ts_start)))
	 FROM requests WHERE ts_start >= ? AND ts_start < ?
	 GROUP BY ip, COALESCE(user_agent, '')
	 ON CONFLICT(day, ip, user_agent) DO UPDATE SET
	   asn = COALESCE(excluded.asn, asn),
	   asn_org = COALESCE(excluded.asn_org, asn_org),
	   requests = requests + excluded.requests,
	   robots = robots + excluded.robots,
	   bait_views = bait_views + excluded.bait_views,
	   violations = violations + excluded.violations,
	   first_ts = MIN(first_ts, excluded.first_ts),
	   last_ts = MAX(last_ts, excluded.last_ts)`, day, dayStart, dayEnd); err != nil {
		return 0, fmt.Errorf("logstore: rollup: daily_visits: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM requests WHERE is_violation IN (0, 1) AND ts_start >= ? AND ts_start < ?`, dayStart, dayEnd)
	if err != nil {
		return 0, fmt.Errorf("logstore: rollup: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("logstore: rollup: commit: %w", err)
	}
	return n, nil
}

// robotsDeleteChunk bounds each robots_fetches delete transaction.
const robotsDeleteChunk = 10000

func (s *Store) deleteOldRobots(ctx context.Context, cutoff int64) error {
	for {
		res, err := s.db.ExecContext(ctx, `DELETE FROM robots_fetches WHERE rowid IN
		 (SELECT rowid FROM robots_fetches WHERE ts < ? LIMIT ?)`, cutoff, robotsDeleteChunk)
		if err != nil {
			return fmt.Errorf("logstore: rollup: robots: %w", err)
		}
		if n, _ := res.RowsAffected(); n < robotsDeleteChunk {
			return nil
		}
	}
}

// PruneIdentities deletes cached classifications checked before olderThan
// whose (ip, user_agent) no longer appears in requests or daily_aggregates.
// Identities still referenced by history are kept so the shame builder can
// keep labelling rolled-up rows. It returns the number of rows deleted.
func (s *Store) PruneIdentities(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM identities WHERE checked_at < ?
	 AND NOT EXISTS (SELECT 1 FROM requests r WHERE r.ip = identities.ip AND COALESCE(r.user_agent, '') = identities.user_agent)
	 AND NOT EXISTS (SELECT 1 FROM daily_aggregates d WHERE d.ip = identities.ip AND d.user_agent = identities.user_agent)`,
		olderThan.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("logstore: prune identities: %w", err)
	}
	return res.RowsAffected()
}
