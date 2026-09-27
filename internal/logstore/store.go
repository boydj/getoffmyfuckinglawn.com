// Package logstore owns the SQLite schema, migrations, and the batched
// asynchronous writer. Request handlers never touch SQLite directly.
package logstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Identity status values (SPEC.md section 7.2).
const (
	StatusVerified     = "verified"
	StatusSpoofed      = "spoofed"
	StatusUnverifiable = "unverifiable"
	StatusAnonymous    = "anonymous"
)

// Verification methods stored in identities.method.
const (
	MethodRDNS    = "rdns"
	MethodIPRange = "ip_range"
	MethodNone    = "none"
)

// Request is one row of the requests table. Timestamps are unix ms.
type Request struct {
	TsStart     int64
	TsEnd       int64 // 0 = NULL
	IP          string
	ASN         uint32 // 0 = NULL (unknown)
	ASNOrg      string // "" = NULL
	UserAgent   string
	Method      string
	Path        string
	Depth       int // < 0 = NULL (outside /lawn/)
	IsViolation bool
	BytesSent   int64
	Dripped     bool
	Status      int
	// Added by migration 2. "" = NULL.
	EndReason      string // how a /lawn/ response ended (see schema.go)
	Referer        string
	Accept         string
	AcceptLanguage string
	AcceptEncoding string
	// Added by migration 3. "" = NULL.
	HeaderNames string // sorted client header names, comma-separated
	Proto       string // client HTTP version (from the proxy)
	TLS         string // "version cipher alpn" (from the proxy)
	// Added by migration 4. 0 = NULL.
	PageID   uint32 // maze page id (maze.Generator.IDs)
	ParentID uint32 // id of the page whose link led here
}

// Host is one row of hosts: reverse DNS for an IP.
type Host struct {
	IP        string
	PTR       string // "" = no PTR record
	CheckedAt int64  // unix ms
}

// RobotsFetch is one row of robots_fetches.
type RobotsFetch struct {
	IP        string
	UserAgent string
	Ts        int64 // unix ms
}

// Identity is one row of identities.
type Identity struct {
	IP         string
	UserAgent  string
	ClaimedOrg string // "" = NULL
	Status     string
	Method     string
	CheckedAt  int64 // unix ms
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path in WAL mode and
// applies migrations. Use ":memory:" only for single-connection tests;
// prefer a temp file.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	if strings.Contains(path, "?") {
		dsn = "file:" + path
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("logstore: open: %w", err)
	}
	// SQLite allows one writer; readers go through WAL. A small pool keeps
	// shame builds from starving the writer.
	db.SetMaxOpenConns(4)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the handle for read-side packages (shame, stats).
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	var v int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("logstore: user_version: %w", err)
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("logstore: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int64, isNull bool) any {
	if isNull {
		return nil
	}
	return v
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// InsertRequests writes rows synchronously in one transaction. The async
// Writer uses this; tests and tools may call it directly.
func (s *Store) InsertRequests(ctx context.Context, rows []Request) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO requests
	 (ts_start, ts_end, ip, asn, asn_org, user_agent, method, path, depth, is_violation, bytes_sent, dripped, status,
	  end_reason, referer, accept, accept_language, accept_encoding, header_names, proto, tls,
	  page_id, parent_id)
	 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for i := range rows {
		r := &rows[i]
		if _, err := st.ExecContext(ctx, r.TsStart, nullInt(r.TsEnd, r.TsEnd == 0), r.IP,
			nullInt(int64(r.ASN), r.ASN == 0), nullStr(r.ASNOrg), r.UserAgent, r.Method, r.Path,
			nullInt(int64(r.Depth), r.Depth < 0), b2i(r.IsViolation), r.BytesSent, b2i(r.Dripped), r.Status,
			nullStr(r.EndReason), nullStr(r.Referer), nullStr(r.Accept), nullStr(r.AcceptLanguage), nullStr(r.AcceptEncoding),
			nullStr(r.HeaderNames), nullStr(r.Proto), nullStr(r.TLS),
			nullInt(int64(r.PageID), r.PageID == 0), nullInt(int64(r.ParentID), r.ParentID == 0)); err != nil {
			return fmt.Errorf("logstore: insert request: %w", err)
		}
	}
	return tx.Commit()
}

// InsertRobotsFetches writes robots.txt fetches synchronously.
func (s *Store) InsertRobotsFetches(ctx context.Context, rows []RobotsFetch) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO robots_fetches (ip, user_agent, ts) VALUES (?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.ExecContext(ctx, r.IP, r.UserAgent, r.Ts); err != nil {
			return fmt.Errorf("logstore: insert robots: %w", err)
		}
	}
	return tx.Commit()
}

// UpsertIdentity stores a classification result.
func (s *Store) UpsertIdentity(ctx context.Context, id Identity) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO identities (ip, user_agent, claimed_org, status, method, checked_at)
	 VALUES (?,?,?,?,?,?)
	 ON CONFLICT(ip, user_agent) DO UPDATE SET claimed_org=excluded.claimed_org, status=excluded.status,
	   method=excluded.method, checked_at=excluded.checked_at`,
		id.IP, id.UserAgent, nullStr(id.ClaimedOrg), id.Status, nullStr(id.Method), id.CheckedAt)
	if err != nil {
		return fmt.Errorf("logstore: upsert identity: %w", err)
	}
	return nil
}

// GetIdentity returns the cached identity, or ok=false if none.
func (s *Store) GetIdentity(ctx context.Context, ip, ua string) (Identity, bool, error) {
	var id Identity
	var org, method sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT ip, user_agent, claimed_org, status, method, checked_at
	 FROM identities WHERE ip = ? AND user_agent = ?`, ip, ua).
		Scan(&id.IP, &id.UserAgent, &org, &id.Status, &method, &id.CheckedAt)
	if err == sql.ErrNoRows {
		return id, false, nil
	}
	if err != nil {
		return id, false, fmt.Errorf("logstore: get identity: %w", err)
	}
	id.ClaimedOrg, id.Method = org.String, method.String
	return id, true, nil
}

// GetHost returns the cached reverse-DNS row for ip, or ok=false.
func (s *Store) GetHost(ctx context.Context, ip string) (Host, bool, error) {
	var h Host
	err := s.db.QueryRowContext(ctx, `SELECT ip, ptr, checked_at FROM hosts WHERE ip = ?`, ip).Scan(&h.IP, &h.PTR, &h.CheckedAt)
	if err == sql.ErrNoRows {
		return h, false, nil
	}
	if err != nil {
		return h, false, fmt.Errorf("logstore: get host: %w", err)
	}
	return h, true, nil
}

// UpsertHost stores a reverse-DNS result.
func (s *Store) UpsertHost(ctx context.Context, h Host) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO hosts (ip, ptr, checked_at) VALUES (?,?,?)
	 ON CONFLICT(ip) DO UPDATE SET ptr=excluded.ptr, checked_at=excluded.checked_at`, h.IP, h.PTR, h.CheckedAt)
	if err != nil {
		return fmt.Errorf("logstore: upsert host: %w", err)
	}
	return nil
}
