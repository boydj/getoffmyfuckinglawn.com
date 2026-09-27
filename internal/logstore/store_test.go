package logstore

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// A database created before migration 2 (as in production) must upgrade in
// place, keep its rows, and accept the new columns.
func TestMigrationUpgradesV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO requests (ts_start, ip, path, is_violation, dripped) VALUES (1, '203.0.113.1', '/lawn/old', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v1 db: %v", err)
	}
	defer s.Close()
	var v int
	if err := s.DB().QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != len(migrations) {
		t.Fatalf("user_version %d (%v), want %d", v, err, len(migrations))
	}
	err = s.InsertRequests(context.Background(), []Request{{
		TsStart: 2, TsEnd: 3, IP: "203.0.113.2", Path: "/lawn/new", IsViolation: true, Depth: 1,
		EndReason: "client_gone", Referer: "https://example.test/sitemap.xml",
		Accept: "text/html", AcceptLanguage: "en", AcceptEncoding: "gzip",
	}})
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ reason, ref, acc, lang, enc sql.NullString }
	get := func(p string) row {
		var r row
		if err := s.DB().QueryRow(`SELECT end_reason, referer, accept, accept_language, accept_encoding FROM requests WHERE path = ?`, p).
			Scan(&r.reason, &r.ref, &r.acc, &r.lang, &r.enc); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if old := get("/lawn/old"); old.reason.Valid || old.ref.Valid || old.acc.Valid {
		t.Errorf("pre-migration row should have NULLs: %+v", old)
	}
	if n := get("/lawn/new"); n.reason.String != "client_gone" || n.ref.String != "https://example.test/sitemap.xml" ||
		n.acc.String != "text/html" || n.lang.String != "en" || n.enc.String != "gzip" {
		t.Errorf("new columns: %+v", n)
	}
	// Reopening is a no-op.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}
