// Package config loads config.yaml and applies environment overrides.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Drip controls the slow writer.
type Drip struct {
	ChunkBytes  int           `yaml:"chunk_bytes"`
	Interval    time.Duration `yaml:"interval"`
	MaxDuration time.Duration `yaml:"max_duration"`
	// Adaptive learns how long each client (ASN or /24 + user agent) waits
	// before giving up, and finishes its later pages just before that, so
	// crawlers with short timeouts get whole pages and follow links.
	Adaptive bool `yaml:"adaptive"`
	// AdaptiveFactor scales the observed give-up time into the next budget.
	AdaptiveFactor float64 `yaml:"adaptive_factor"`
}

// Limits are the self-protection caps.
type Limits struct {
	MaxConnsGlobal int `yaml:"max_conns_global"`
	MaxConnsPerASN int `yaml:"max_conns_per_asn"`
	MaxConnsPerIP  int `yaml:"max_conns_per_ip"`
	// MaxConnsPerPrefix caps drips per /24 (IPv4) or /48 (IPv6); 0 = off.
	MaxConnsPerPrefix int `yaml:"max_conns_per_prefix"`
	// PrefixRate / PrefixBurst: token bucket of new /lawn/ requests per
	// /24 or /48 (per second, burst); PrefixRate 0 = off.
	PrefixRate  float64 `yaml:"prefix_rate"`
	PrefixBurst int     `yaml:"prefix_burst"`
}

// Session controls report-time session derivation.
type Session struct {
	Gap time.Duration `yaml:"gap"`
}

// Shame controls the static leaderboard builder.
type Shame struct {
	RebuildInterval        time.Duration `yaml:"rebuild_interval"`
	BlocklistMinViolations int           `yaml:"blocklist_min_violations"`
}

// Retention controls raw-row rollups.
type Retention struct {
	RawRequestsDays int `yaml:"raw_requests_days"`
}

// Attrib controls crawler verification.
type Attrib struct {
	IdentityTTL   time.Duration `yaml:"identity_ttl"`
	DNSTimeout    time.Duration `yaml:"dns_timeout"`
	RangesRefresh time.Duration `yaml:"ranges_refresh"`
	RangesCache   string        `yaml:"ranges_cache_dir"`
	QueueSize     int           `yaml:"queue_size"`
	Workers       int           `yaml:"workers"`
}

// Log controls the async SQLite writer.
type Log struct {
	BufferSize    int           `yaml:"buffer_size"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// Config is the full service configuration.
type Config struct {
	Listen          string    `yaml:"listen"`
	AdminListen     string    `yaml:"admin_listen"`
	BaseURL         string    `yaml:"base_url"`
	OnionAddress    string    `yaml:"onion_address"`
	TrustedProxies  []string  `yaml:"trusted_proxies"`
	ExcludeCIDRs    []string  `yaml:"exclude_cidrs"`
	ServerSecretEnv string    `yaml:"server_secret_env"`
	DBPath          string    `yaml:"db_path"`
	ASNDBPath       string    `yaml:"asn_db_path"`
	PublicDir       string    `yaml:"public_dir"`
	CorpusDir       string    `yaml:"corpus_dir"`
	CrawlersFile    string    `yaml:"crawlers_file"`
	TemplatesDir    string    `yaml:"templates_dir"`
	Drip            Drip      `yaml:"drip"`
	Limits          Limits    `yaml:"limits"`
	Session         Session   `yaml:"session"`
	Shame           Shame     `yaml:"shame"`
	Retention       Retention `yaml:"retention"`
	Attrib          Attrib    `yaml:"attrib"`
	Log             Log       `yaml:"log"`

	// Secret is resolved from the env var named by ServerSecretEnv. Never
	// read from the YAML file.
	Secret []byte `yaml:"-"`
	// Proxies is TrustedProxies parsed.
	Proxies []netip.Prefix `yaml:"-"`
	// Exclude is ExcludeCIDRs parsed: the operator's own networks, kept out
	// of the wall, the well-behaved page and private reports.
	Exclude []netip.Prefix `yaml:"-"`
}

// Default returns the spec defaults (SPEC.md section 9).
func Default() Config {
	return Config{
		Listen:          "127.0.0.1:8080",
		AdminListen:     "127.0.0.1:9090",
		BaseURL:         "https://getoffmyfuckinglawn.com",
		TrustedProxies:  []string{"127.0.0.1/32"},
		ServerSecretEnv: "LAWN_SECRET",
		DBPath:          "/var/lib/lawn/lawn.db",
		ASNDBPath:       "/var/lib/lawn/ip2asn-combined.tsv.gz",
		PublicDir:       "/var/lib/lawn/public",
		CorpusDir:       "./corpus",
		CrawlersFile:    "./config/crawlers.yaml",
		Drip:            Drip{ChunkBytes: 16, Interval: time.Second, MaxDuration: 10 * time.Minute, Adaptive: true, AdaptiveFactor: 0.8},
		Limits:          Limits{MaxConnsGlobal: 5000, MaxConnsPerASN: 200, MaxConnsPerIP: 20, MaxConnsPerPrefix: 50, PrefixRate: 10, PrefixBurst: 100},
		Session:         Session{Gap: 10 * time.Minute},
		Shame:           Shame{RebuildInterval: 5 * time.Minute, BlocklistMinViolations: 50},
		Retention:       Retention{RawRequestsDays: 90},
		Attrib: Attrib{
			IdentityTTL:   7 * 24 * time.Hour,
			DNSTimeout:    2 * time.Second,
			RangesRefresh: 24 * time.Hour,
			RangesCache:   "/var/lib/lawn/ranges",
			QueueSize:     4096,
			Workers:       4,
		},
		Log: Log{BufferSize: 65536, BatchSize: 512, FlushInterval: time.Second},
	}
}

// envOverrides maps env var names to config fields. The secret is handled
// separately via ServerSecretEnv.
var envOverrides = []struct {
	name string
	dst  func(*Config) *string
}{
	{"LAWN_LISTEN", func(c *Config) *string { return &c.Listen }},
	{"LAWN_ADMIN_LISTEN", func(c *Config) *string { return &c.AdminListen }},
	{"LAWN_BASE_URL", func(c *Config) *string { return &c.BaseURL }},
	{"LAWN_ONION_ADDRESS", func(c *Config) *string { return &c.OnionAddress }},
	{"LAWN_DB_PATH", func(c *Config) *string { return &c.DBPath }},
	{"LAWN_ASN_DB_PATH", func(c *Config) *string { return &c.ASNDBPath }},
	{"LAWN_PUBLIC_DIR", func(c *Config) *string { return &c.PublicDir }},
	{"LAWN_CORPUS_DIR", func(c *Config) *string { return &c.CorpusDir }},
	{"LAWN_CRAWLERS_FILE", func(c *Config) *string { return &c.CrawlersFile }},
	{"LAWN_TEMPLATES_DIR", func(c *Config) *string { return &c.TemplatesDir }},
	{"LAWN_RANGES_CACHE_DIR", func(c *Config) *string { return &c.Attrib.RangesCache }},
}

// Load reads path (if non-empty) over the defaults, applies env overrides
// using getenv, and validates. Pass os.Getenv in production.
func Load(path string, getenv func(string) string) (Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return c, fmt.Errorf("config: %w", err)
		}
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	for _, o := range envOverrides {
		if v := getenv(o.name); v != "" {
			*o.dst(&c) = v
		}
	}
	if v := getenv("LAWN_TRUSTED_PROXIES"); v != "" {
		c.TrustedProxies = strings.Split(v, ",")
	}
	if v := getenv("LAWN_EXCLUDE_CIDRS"); v != "" {
		c.ExcludeCIDRs = strings.Split(v, ",")
	}
	if c.ServerSecretEnv != "" {
		if s := getenv(c.ServerSecretEnv); s != "" {
			c.Secret = []byte(s)
		}
	}
	return c, c.Validate()
}

// onionRE matches a v3 onion service hostname, as tor writes it to the
// service directory's hostname file.
var onionRE = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

// parsePrefixes parses CIDRs or bare addresses (as /32 or /128).
func parsePrefixes(key string, in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return nil, fmt.Errorf("config: %s: %q: %w", key, p, err)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

// Validate parses TrustedProxies into Proxies and ExcludeCIDRs into
// Exclude, and checks invariants. Load calls it; call it yourself after
// building a Config by hand.
func (c *Config) Validate() error {
	var err error
	if c.Proxies, err = parsePrefixes("trusted_proxies", c.TrustedProxies); err != nil {
		return err
	}
	if c.Exclude, err = parsePrefixes("exclude_cidrs", c.ExcludeCIDRs); err != nil {
		return err
	}
	if c.OnionAddress != "" && !onionRE.MatchString(c.OnionAddress) {
		return fmt.Errorf("config: onion_address %q is not a v3 onion hostname (56 base32 characters + .onion)", c.OnionAddress)
	}
	for _, p := range c.Exclude {
		if p.Bits() == 0 {
			return fmt.Errorf("config: exclude_cidrs: %s would hide every visitor", p)
		}
	}
	var errs []error
	if c.Drip.ChunkBytes <= 0 {
		errs = append(errs, errors.New("drip.chunk_bytes must be > 0"))
	}
	if c.Drip.Interval < 0 || c.Drip.MaxDuration < 0 {
		errs = append(errs, errors.New("drip durations must be >= 0"))
	}
	if c.Drip.AdaptiveFactor <= 0 || c.Drip.AdaptiveFactor > 1 {
		errs = append(errs, errors.New("drip.adaptive_factor must be in (0, 1]"))
	}
	if c.Limits.MaxConnsGlobal <= 0 || c.Limits.MaxConnsPerASN <= 0 || c.Limits.MaxConnsPerIP <= 0 {
		errs = append(errs, errors.New("limits.max_conns_* must be > 0"))
	}
	if c.Limits.MaxConnsPerPrefix < 0 || c.Limits.PrefixRate < 0 || c.Limits.PrefixBurst < 0 {
		errs = append(errs, errors.New("limits.max_conns_per_prefix, prefix_rate and prefix_burst must be >= 0 (0 = off)"))
	}
	if c.Session.Gap <= 0 {
		errs = append(errs, errors.New("session.gap must be > 0"))
	}
	if c.Shame.RebuildInterval <= 0 {
		errs = append(errs, errors.New("shame.rebuild_interval must be > 0"))
	}
	if c.Retention.RawRequestsDays <= 0 {
		errs = append(errs, errors.New("retention.raw_requests_days must be > 0"))
	}
	if c.Log.BufferSize <= 0 || c.Log.BatchSize <= 0 || c.Log.FlushInterval <= 0 {
		errs = append(errs, errors.New("log.* must be > 0"))
	}
	if c.Attrib.QueueSize <= 0 || c.Attrib.Workers <= 0 {
		errs = append(errs, errors.New("attrib.queue_size and attrib.workers must be > 0"))
	}
	return errors.Join(errs...)
}

// RequireSecret errors if no server secret is configured. Only commands that
// generate maze pages need it.
func (c *Config) RequireSecret() error {
	if len(c.Secret) < 16 {
		return fmt.Errorf("config: env %s must hold a secret of at least 16 bytes", c.ServerSecretEnv)
	}
	return nil
}
