package logstore

// migrations are applied in order; the index+1 is stored in PRAGMA
// user_version. Never edit an applied migration — append a new one.
var migrations = []string{
	// 1: SPEC.md section 6 schema plus daily_aggregates (section 9 retention).
	`
CREATE TABLE requests (
  id            INTEGER PRIMARY KEY,
  ts_start      INTEGER NOT NULL,
  ts_end        INTEGER,
  ip            TEXT NOT NULL,
  asn           INTEGER,
  asn_org       TEXT,
  user_agent    TEXT,
  method        TEXT,
  path          TEXT NOT NULL,
  depth         INTEGER,
  is_violation  INTEGER NOT NULL,
  bytes_sent    INTEGER,
  dripped       INTEGER NOT NULL,
  status        INTEGER
);
CREATE INDEX idx_req_ip_ts ON requests(ip, ts_start);
CREATE INDEX idx_req_violation ON requests(is_violation, ts_start);

CREATE TABLE robots_fetches (
  ip TEXT NOT NULL, user_agent TEXT, ts INTEGER NOT NULL
);
CREATE INDEX idx_robots_ip_ts ON robots_fetches(ip, ts);

CREATE TABLE identities (
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  claimed_org TEXT,
  status TEXT NOT NULL,
  method TEXT,
  checked_at INTEGER NOT NULL,
  PRIMARY KEY (ip, user_agent)
);

-- One row per (UTC day, ip, user_agent) for violations rolled out of
-- requests by retention. Keyed by ip+ua so identity joins still work.
CREATE TABLE daily_aggregates (
  day           TEXT NOT NULL,        -- YYYY-MM-DD (UTC)
  ip            TEXT NOT NULL,
  user_agent    TEXT NOT NULL,
  asn           INTEGER,
  asn_org       TEXT,
  pages         INTEGER NOT NULL,     -- violation requests
  held_ms       INTEGER NOT NULL,     -- sum(ts_end - ts_start) over violations
  bytes_sent    INTEGER NOT NULL,
  max_depth     INTEGER,
  sessions      INTEGER NOT NULL,     -- sessions with >=1 violation that started this day
  read_rules    INTEGER NOT NULL,     -- sessions flagged read_the_rules
  first_ts      INTEGER NOT NULL,     -- unix ms
  last_ts       INTEGER NOT NULL,     -- unix ms
  PRIMARY KEY (day, ip, user_agent)
);
`,
	// 2: why each request ended, and request headers that help tell real
	// crawlers from scripts. Stored for analysis only; never published.
	`
ALTER TABLE requests ADD COLUMN end_reason TEXT;       -- complete|cutoff|client_gone|write_error|shed|egress_cap|head; NULL outside /lawn/
ALTER TABLE requests ADD COLUMN referer TEXT;
ALTER TABLE requests ADD COLUMN accept TEXT;
ALTER TABLE requests ADD COLUMN accept_language TEXT;
ALTER TABLE requests ADD COLUMN accept_encoding TEXT;
`,
}
