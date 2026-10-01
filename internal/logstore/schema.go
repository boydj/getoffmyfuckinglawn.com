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
ALTER TABLE requests ADD COLUMN end_reason TEXT;       -- complete|cutoff|client_gone|write_error|shed|head (egress_cap in older rows); NULL outside /lawn/
ALTER TABLE requests ADD COLUMN referer TEXT;
ALTER TABLE requests ADD COLUMN accept TEXT;
ALTER TABLE requests ADD COLUMN accept_language TEXT;
ALTER TABLE requests ADD COLUMN accept_encoding TEXT;
`,
	// 3: data for spotting new bots and reporting well-behaved ones. All
	// private: nothing here is published beyond what section 8 allows.
	`
ALTER TABLE requests ADD COLUMN header_names TEXT;  -- sorted names of client-sent headers (proxy-added ones excluded)
ALTER TABLE requests ADD COLUMN proto TEXT;         -- client HTTP version as seen by Caddy, e.g. HTTP/2.0
ALTER TABLE requests ADD COLUMN tls TEXT;           -- "version cipher alpn" as seen by Caddy
CREATE INDEX idx_req_ts ON requests(ts_start);
-- Per-client scans (shame, rollup) walk rows in (ip, user_agent) order.
CREATE INDEX idx_req_ip_ua_ts ON requests(ip, user_agent, ts_start);

-- Reverse DNS for every visiting IP (not forward-confirmed; that is
-- identities' job for known crawlers). ptr '' = no PTR record.
CREATE TABLE hosts (
  ip         TEXT PRIMARY KEY,
  ptr        TEXT NOT NULL,
  checked_at INTEGER NOT NULL   -- unix ms
);

-- One row per (UTC day, ip, user_agent) for EVERY visitor rolled out of
-- requests by retention, so compliant bots keep their history too.
CREATE TABLE daily_visits (
  day         TEXT NOT NULL,
  ip          TEXT NOT NULL,
  user_agent  TEXT NOT NULL,
  asn         INTEGER,
  asn_org     TEXT,
  requests    INTEGER NOT NULL,
  robots      INTEGER NOT NULL,   -- /robots.txt fetches
  bait_views  INTEGER NOT NULL,   -- fetches of pages carrying bait links (/, /sitemap.xml)
  violations  INTEGER NOT NULL,   -- /lawn/ requests
  first_ts    INTEGER NOT NULL,
  last_ts     INTEGER NOT NULL,
  PRIMARY KEY (day, ip, user_agent)
);
`,
	// 4: maze page identity, so analysis can tell whether a client fetches
	// a page's children while that page is still dripping (frontier
	// amplification). Both are 32-bit ids derived from the page's HMAC;
	// NULL outside /lawn/ and, for parent_id, on entry pages.
	`
ALTER TABLE requests ADD COLUMN page_id INTEGER;
ALTER TABLE requests ADD COLUMN parent_id INTEGER;
CREATE INDEX idx_req_page ON requests(page_id) WHERE page_id IS NOT NULL;
`,
	// 5: country of the client's IP range, from the iptoasn.com file the
	// ASN lookup already uses. Private analysis only; never published.
	`
ALTER TABLE requests ADD COLUMN country TEXT;
`,
	// 6: which protocol a request arrived by: https, http (port 80 or the
	// onion mirror), gopher or gemini. proto keeps the version detail.
	`
ALTER TABLE requests ADD COLUMN scheme TEXT;
`,
	// 7: the JA4 fingerprint of the client's TLS ClientHello, from lawn's
	// Caddy build (HTTPS over TCP only). Private analysis only.
	`
ALTER TABLE requests ADD COLUMN ja4 TEXT;
`,
}
