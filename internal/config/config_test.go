package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaultsValid(t *testing.T) {
	c, err := Load("", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Drip.Interval != time.Second || c.Session.Gap != 10*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if len(c.Proxies) != 1 || c.Proxies[0].String() != "127.0.0.1/32" {
		t.Fatalf("proxies: %v", c.Proxies)
	}
	if c.RequireSecret() == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestLoadFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	yaml := `
listen: "0.0.0.0:1234"
trusted_proxies: ["10.0.0.1", "::1/128"]
exclude_cidrs: ["198.51.100.7", "2001:db8:5::/48"]
drip: { chunk_bytes: 32, interval: 250ms, max_duration: 2m }
limits: { max_conns_global: 10, max_conns_per_asn: 5, max_conns_per_ip: 2, daily_egress_bytes: 1000 } # removed key: must be ignored
`
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, env(map[string]string{
		"LAWN_SECRET":  "0123456789abcdef0123",
		"LAWN_DB_PATH": "/tmp/x.db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:1234" || c.DBPath != "/tmp/x.db" {
		t.Fatalf("got %+v", c)
	}
	if !c.Drip.Adaptive || c.Drip.AdaptiveFactor != 0.8 {
		t.Fatalf("adaptive defaults lost: %+v", c.Drip)
	}
	if c.Drip.ChunkBytes != 32 || c.Drip.Interval != 250*time.Millisecond || c.Drip.MaxDuration != 2*time.Minute {
		t.Fatalf("drip: %+v", c.Drip)
	}
	if c.Limits.MaxConnsPerIP != 2 || c.Limits.MaxConnsPerPrefix != 50 || c.Limits.PrefixRate != 10 || c.Limits.PrefixBurst != 100 {
		t.Fatalf("limits: %+v", c.Limits)
	}
	// Unset keys keep defaults.
	if c.Shame.BlocklistMinViolations != 50 {
		t.Fatalf("shame defaults lost: %+v", c.Shame)
	}
	if len(c.Proxies) != 2 || c.Proxies[0].String() != "10.0.0.1/32" || c.Proxies[1].String() != "::1/128" {
		t.Fatalf("proxies: %v", c.Proxies)
	}
	// Loopback (the host itself) is always appended.
	if len(c.Exclude) != 4 || c.Exclude[0].String() != "198.51.100.7/32" || c.Exclude[1].String() != "2001:db8:5::/48" ||
		c.Exclude[2].String() != "127.0.0.0/8" || c.Exclude[3].String() != "::1/128" {
		t.Fatalf("exclude: %v", c.Exclude)
	}
	if err := c.RequireSecret(); err != nil {
		t.Fatal(err)
	}
	good := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
	if c, err := Load(p, env(map[string]string{"LAWN_ONION_ADDRESS": good})); err != nil || c.OnionAddress != good {
		t.Fatalf("onion address from env: %q %v", c.OnionAddress, err)
	}
	// The env var replaces the file's list.
	c, err = Load(p, env(map[string]string{"LAWN_EXCLUDE_CIDRS": "203.0.113.0/24, 192.0.2.9"}))
	if err != nil || len(c.Exclude) != 4 || c.Exclude[0].String() != "203.0.113.0/24" || c.Exclude[1].String() != "192.0.2.9/32" {
		t.Fatalf("exclude from env: %v %v", c.Exclude, err)
	}
}

func TestInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("trusted_proxies: [\"nope\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("expected error for bad proxy")
	}
	if err := os.WriteFile(p, []byte("drip: { adaptive_factor: 1.5 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("expected error for adaptive_factor > 1")
	}
	if err := os.WriteFile(p, []byte("limits: { prefix_rate: -1 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("expected error for negative prefix_rate")
	}
	for _, bad := range []string{`exclude_cidrs: ["0.0.0.0/0"]`, `exclude_cidrs: ["nope"]`,
		`onion_address: "example.onion"`, `onion_address: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwx.onion"`} {
		if err := os.WriteFile(p, []byte(bad+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, env(nil)); err == nil {
			t.Fatalf("expected error for %s", bad)
		}
	}
	if err := os.WriteFile(p, []byte("drip: { chunk_bytes: 0 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("expected error for chunk_bytes 0")
	}
}

func TestSmallWebListeners(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.GopherListen != ":70" || c.GeminiListen != ":1965" || c.Host() != "getoffmyfuckinglawn.com" {
		t.Fatalf("defaults: %q %q %q", c.GopherListen, c.GeminiListen, c.Host())
	}
	if p, err := c.GopherPort(); err != nil || p != 70 {
		t.Fatalf("gopher port %d %v", p, err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("gopher_listen: \"off\"\ngemini_listen: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, env(nil))
	if err != nil || c.GopherListen != "" || c.GeminiListen != "" {
		t.Fatalf("off: %q %q %v", c.GopherListen, c.GeminiListen, err)
	}
	c, err = Load("", env(map[string]string{"LAWN_GOPHER_LISTEN": "127.0.0.1:7070", "LAWN_GEMINI_LISTEN": "off"}))
	if err != nil || c.GopherListen != "127.0.0.1:7070" || c.GeminiListen != "" {
		t.Fatalf("env: %q %q %v", c.GopherListen, c.GeminiListen, err)
	}
	for _, bad := range []string{"gopher_listen: \"70\"", "gopher_listen: \":notaport\"", "gemini_listen: \"nohostport\"",
		"gemini_cert_dir: \"\"", "base_url: \"not a url\""} {
		if err := os.WriteFile(p, []byte(bad+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p, env(nil)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
}
