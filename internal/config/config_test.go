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
	if c.Limits.MaxConnsPerIP != 2 {
		t.Fatalf("limits: %+v", c.Limits)
	}
	// Unset keys keep defaults.
	if c.Shame.BlocklistMinViolations != 50 {
		t.Fatalf("shame defaults lost: %+v", c.Shame)
	}
	if len(c.Proxies) != 2 || c.Proxies[0].String() != "10.0.0.1/32" || c.Proxies[1].String() != "::1/128" {
		t.Fatalf("proxies: %v", c.Proxies)
	}
	if err := c.RequireSecret(); err != nil {
		t.Fatal(err)
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
	if err := os.WriteFile(p, []byte("drip: { chunk_bytes: 0 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, env(nil)); err == nil {
		t.Fatal("expected error for chunk_bytes 0")
	}
}
