package visitors

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/logstore"
)

var now = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func fixture(t *testing.T) *logstore.Store {
	t.Helper()
	s, err := logstore.Open(filepath.Join(t.TempDir(), "lawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	at := func(ago time.Duration) int64 { return now.Add(-ago).UnixMilli() }
	rows := []logstore.Request{
		{TsStart: at(3 * time.Hour), TsEnd: at(3 * time.Hour), IP: "198.51.100.9", ASN: 64501, ASNOrg: "HOSTING-AS", Country: "NL",
			UserAgent: "GreedyBot/1.0", Method: "GET", Path: "/", Depth: -1, Status: 200},
		{TsStart: at(2 * time.Hour), TsEnd: at(2*time.Hour) + 4500, IP: "198.51.100.9", ASN: 64501, ASNOrg: "HOSTING-AS", Country: "NL",
			UserAgent: "GreedyBot/1.0", Method: "GET", Path: "/lawn/abc", Depth: 0, IsViolation: true, Status: 200,
			EndReason: "client_gone", Referer: "https://lawn.example/", BytesSent: 1519, Dripped: true},
		{TsStart: at(time.Hour), IP: "203.0.113.5", ASN: 64502, ASNOrg: "EYEBALL", UserAgent: "Mozilla/5.0 Safari",
			Method: "GET", Path: "/shame/", Depth: -1, Status: 200},
		{TsStart: at(30 * time.Minute), IP: "192.0.2.7", ASN: 64503, UserAgent: "scanner_50%", Method: "GET",
			Path: "/.env", Depth: -1, Status: 404},
		{TsStart: at(48 * time.Hour), IP: "198.51.100.10", ASN: 64501, UserAgent: "OldBot", Method: "GET", Path: "/", Depth: -1, Status: 200},
	}
	rows[1].Scheme, rows[1].Proto = "https", "HTTP/2.0"
	rows[2].Scheme, rows[2].Proto = "https", "HTTP/3.0"
	rows[3].Scheme, rows[3].Proto = "gopher", "gopher"
	if err := s.InsertRequests(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	return s
}

func list(t *testing.T, o Options) *Result {
	t.Helper()
	o.Now = func() time.Time { return now }
	r, err := List(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func paths(r *Result) string {
	var p []string
	for _, v := range r.Visits {
		p = append(p, v.Path)
	}
	return strings.Join(p, " ")
}

func TestList(t *testing.T) {
	s := fixture(t)
	db := s.DB()
	day := 24 * time.Hour
	for _, c := range []struct {
		name string
		o    Options
		want string
	}{
		{"window, newest first", Options{DB: db, Since: day}, "/.env /shame/ /lawn/abc /"},
		{"everything", Options{DB: db}, "/.env /shame/ /lawn/abc / /"},
		{"one IP is a timeline", Options{DB: db, IP: "198.51.100.9"}, "/ /lawn/abc"},
		{"CIDR", Options{DB: db, IP: "198.51.100.0/24", Since: day}, "/lawn/abc /"},
		{"ASN with prefix", Options{DB: db, ASN: "as64501"}, "/lawn/abc / /"},
		{"UA substring, case-insensitive", Options{DB: db, UA: "greedy"}, "/lawn/abc /"},
		{"LIKE wildcards are literal", Options{DB: db, UA: "_50%"}, "/.env"},
		{"path prefix", Options{DB: db, Path: "/.e"}, "/.env"},
		{"lawn only", Options{DB: db, LawnOnly: true}, "/lawn/abc"},
		{"limit", Options{DB: db, Limit: 2}, "/.env /shame/"},
		{"scheme", Options{DB: db, Scheme: "GOPHER"}, "/.env"},
	} {
		if got := paths(list(t, c.o)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if r := list(t, Options{DB: db, Limit: 2}); !r.More {
		t.Error("limit should report more")
	}
	for _, bad := range []Options{{DB: db, IP: "nope"}, {DB: db, ASN: "ASX"}} {
		bad.Now = func() time.Time { return now }
		if _, err := List(context.Background(), bad); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
}

func TestOperatorsHiddenAndMarked(t *testing.T) {
	s := fixture(t)
	ex := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	r := list(t, Options{DB: s.DB(), Exclude: ex, Limit: 1})
	if paths(r) != "/.env" || r.Hidden != 1 || !r.More {
		t.Fatalf("hidden: %q hidden=%d more=%v", paths(r), r.Hidden, r.More)
	}
	r = list(t, Options{DB: s.DB(), Exclude: ex, Operators: true})
	var out bytes.Buffer
	Write(&out, r)
	if !strings.Contains(out.String(), "*203.0.113.5") || r.Hidden != 0 {
		t.Errorf("operator rows must be shown and marked:\n%s", out.String())
	}
}

func TestWrite(t *testing.T) {
	s := fixture(t)
	var out bytes.Buffer
	Write(&out, list(t, Options{DB: s.DB(), IP: "198.51.100.9"}))
	txt := out.String()
	for _, want := range []string{"TIME (UTC)", "09-28 10:00:00", "NL", "AS64501 HOSTING-AS", "GET /lawn/abc",
		"client_gone", "4.5", "1519", "https://lawn.example/", "GreedyBot/1.0", "2 visits, oldest first.", "https h2"} {
		if !strings.Contains(txt, want) {
			t.Errorf("output missing %q:\n%s", want, txt)
		}
	}
	out.Reset()
	Write(&out, &Result{})
	if !strings.Contains(out.String(), "No matching visits.") {
		t.Errorf("empty: %q", out.String())
	}
}

func TestVia(t *testing.T) {
	for _, c := range []struct {
		v    Visit
		want string
	}{
		{Visit{Scheme: "https", Proto: "HTTP/2.0"}, "https h2"},
		{Visit{Scheme: "https", Proto: "HTTP/3.0"}, "https h3"},
		{Visit{Scheme: "http", Proto: "HTTP/1.1"}, "http 1.1"},
		{Visit{Scheme: "gemini", Proto: "gemini"}, "gemini"},
		{Visit{Scheme: "http", Proto: "HTTP/1.1", ASN: int64(logstore.OnionASN)}, "onion"},
		{Visit{Proto: "HTTP/1.1"}, "1.1"},
		{Visit{}, "-"},
	} {
		if got := via(c.v); got != c.want {
			t.Errorf("%+v: %q want %q", c.v, got, c.want)
		}
	}
}
