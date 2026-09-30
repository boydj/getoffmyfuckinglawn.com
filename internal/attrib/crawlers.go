package attrib

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Verification methods accepted in crawlers.yaml.
const (
	VerifyRDNS     = "rdns"
	VerifyIPRanges = "ip_ranges"
	VerifyNone     = "none"
)

// VerifySpec is a crawler's verification method (SPEC.md section 7.1).
type VerifySpec struct {
	Method  string   `yaml:"method"`  // rdns | ip_ranges | none
	Domains []string `yaml:"domains"` // rdns: PTR must be one of these or a subdomain
	URL     string   `yaml:"url"`     // ip_ranges: vendor JSON or text list
	URLs    []string `yaml:"urls"`    // ip_ranges: several lists; an address in any one verifies
	CIDRs   []string `yaml:"cidrs"`   // ip_ranges: static prefixes
}

// Lists returns every vendor list URL the spec names (url, then urls).
func (v VerifySpec) Lists() []string {
	if v.URL == "" {
		return v.URLs
	}
	return append([]string{v.URL}, v.URLs...)
}

// UnmarshalYAML accepts either a mapping or a bare method string
// (`verify: none`).
func (v *VerifySpec) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		v.Method = n.Value
		return nil
	}
	type plain VerifySpec
	return n.Decode((*plain)(v))
}

// Crawler is one known crawler.
type Crawler struct {
	Org      string
	Name     string
	Patterns []*regexp.Regexp
	Verify   VerifySpec
	// UserTriggered: the vendor documents this agent as fetching a page
	// because a person asked it to (not crawling on its own).
	UserTriggered bool
	// RobotsExempt: the vendor states robots.txt may not apply to it. Its
	// verified /lawn/ hits are reported separately, not as violations.
	RobotsExempt bool

	static prefixSet // parsed Verify.CIDRs
}

type crawlerYAML struct {
	Org           string     `yaml:"org"`
	Name          string     `yaml:"name"`
	UAPatterns    []string   `yaml:"ua_patterns"`
	Verify        VerifySpec `yaml:"verify"`
	UserTriggered bool       `yaml:"user_triggered"`
	RobotsExempt  bool       `yaml:"robots_exempt"`
}

// LoadCrawlers reads and validates a crawlers.yaml file.
func LoadCrawlers(path string) ([]Crawler, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attrib: crawlers: %w", err)
	}
	cs, err := ParseCrawlers(b)
	if err != nil {
		return nil, fmt.Errorf("attrib: crawlers: %s: %w", path, err)
	}
	return cs, nil
}

// ParseCrawlers parses crawlers.yaml content. UA patterns are Go regexps
// matched case-insensitively ((?i) is prepended).
func ParseCrawlers(b []byte) ([]Crawler, error) {
	var raw []crawlerYAML
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]Crawler, 0, len(raw))
	var errs []error
	for i, r := range raw {
		c, err := buildCrawler(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d (%s): %w", i, r.Name, err))
			continue
		}
		out = append(out, c)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func buildCrawler(r crawlerYAML) (Crawler, error) {
	c := Crawler{Org: strings.TrimSpace(r.Org), Name: strings.TrimSpace(r.Name), Verify: r.Verify,
		UserTriggered: r.UserTriggered, RobotsExempt: r.RobotsExempt}
	if c.RobotsExempt && !c.UserTriggered {
		return c, errors.New("robots_exempt requires user_triggered (only user-initiated fetchers are exempt)")
	}
	if c.Org == "" || c.Name == "" {
		return c, errors.New("org and name are required")
	}
	if len(r.UAPatterns) == 0 {
		return c, errors.New("ua_patterns is empty")
	}
	for _, p := range r.UAPatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return c, fmt.Errorf("ua_patterns: %w", err)
		}
		c.Patterns = append(c.Patterns, re)
	}
	v := &c.Verify
	v.Method = strings.ToLower(strings.TrimSpace(v.Method))
	switch v.Method {
	case VerifyRDNS:
		if len(v.Domains) == 0 {
			return c, errors.New("verify rdns needs domains")
		}
		for i, d := range v.Domains {
			d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" || strings.ContainsAny(d, " /*") {
				return c, fmt.Errorf("verify rdns: bad domain %q", v.Domains[i])
			}
			v.Domains[i] = d
		}
	case VerifyIPRanges:
		if len(v.Lists()) == 0 && len(v.CIDRs) == 0 {
			return c, errors.New("verify ip_ranges needs url, urls or cidrs")
		}
		for _, l := range v.Lists() {
			u, err := url.Parse(l)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return c, fmt.Errorf("verify ip_ranges: bad url %q", l)
			}
		}
		var pfx []netip.Prefix
		for _, s := range v.CIDRs {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return c, fmt.Errorf("verify ip_ranges: %w", err)
			}
			pfx = append(pfx, p)
		}
		c.static = newPrefixSet(pfx)
	case VerifyNone, "":
		v.Method = VerifyNone
	default:
		return c, fmt.Errorf("unknown verify method %q", v.Method)
	}
	return c, nil
}

// MatchUA returns the first crawler with a pattern matching ua, or nil.
// Order matters: crawlers.yaml lists specific tokens before generic ones.
func MatchUA(crawlers []Crawler, ua string) *Crawler {
	if ua == "" {
		return nil
	}
	for i := range crawlers {
		for _, re := range crawlers[i].Patterns {
			if re.MatchString(ua) {
				return &crawlers[i]
			}
		}
	}
	return nil
}

// RangeURLs returns the distinct ip_ranges URLs referenced by crawlers.
func RangeURLs(crawlers []Crawler) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range crawlers {
		if c.Verify.Method != VerifyIPRanges {
			continue
		}
		for _, l := range c.Verify.Lists() {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// RobotsExemptUA reports whether ua claims a crawler whose vendor says
// robots.txt may not apply to it. It says nothing about whether the claim
// is true: callers must also require a verified identity.
func RobotsExemptUA(crawlers []Crawler, ua string) bool {
	c := MatchUA(crawlers, ua)
	return c != nil && c.RobotsExempt
}
