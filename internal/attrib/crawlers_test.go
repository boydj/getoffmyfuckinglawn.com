package attrib

import (
	"strings"
	"testing"
)

func TestSeedCrawlersFile(t *testing.T) {
	cs, err := LoadCrawlers("../../config/crawlers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]*Crawler{}
	for i := range cs {
		c := &cs[i]
		if names[c.Name] != nil {
			t.Errorf("duplicate name %s", c.Name)
		}
		names[c.Name] = c
		if c.Verify.URL != "" && !strings.HasPrefix(c.Verify.URL, "https://") {
			t.Errorf("%s: non-https url %s", c.Name, c.Verify.URL)
		}
	}
	for _, n := range []string{"GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-User", "Claude-SearchBot",
		"CCBot", "PerplexityBot", "Perplexity-User", "Bytespider", "Amazonbot", "Applebot", "Applebot-Extended",
		"Google-Extended", "Googlebot", "Bingbot", "meta-externalagent", "meta-externalfetcher"} {
		if names[n] == nil {
			t.Errorf("missing seed crawler %s", n)
		}
	}
	// Real-world UA strings route to the specific entry, not a generic one.
	for ua, want := range map[string]string{
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot":        "ChatGPT-User",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot": "OAI-SearchBot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)":           "GPTBot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":          "ClaudeBot",
		"Claude-User/1.0": "Claude-User",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)": "Googlebot",
		"Googlebot-Image/1.0":             "Googlebot",
		"Mozilla/5.0 (Applebot-Extended)": "Applebot-Extended",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)": "Applebot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36":                      "Bingbot",
		"meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)":                                                                             "meta-externalagent",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)":                                           "Perplexity-User",
		"CCBot/2.0 (https://commoncrawl.org/faq/)": "CCBot",
	} {
		got := MatchUA(cs, ua)
		if got == nil || got.Name != want {
			t.Errorf("MatchUA(%q) = %v, want %s", ua, got, want)
		}
	}
	for _, ua := range []string{"", "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0", "curl/8.5.0", "NotGPTBotter"} {
		if got := MatchUA(cs, ua); got != nil {
			t.Errorf("MatchUA(%q) = %s, want nil", ua, got.Name)
		}
	}
}

func TestParseCrawlersShapes(t *testing.T) {
	cs, err := ParseCrawlers([]byte(`
- org: A
  name: BareNone
  ua_patterns: [barenone]
  verify: none
- org: B
  name: NoVerify
  ua_patterns: [noverify]
- org: C
  name: Static
  ua_patterns: [static]
  verify: {method: ip_ranges, cidrs: ["192.0.2.0/24", "2001:db8::/32"]}
- org: D
  name: RDNS
  ua_patterns: [rdns]
  verify: {method: RDNS, domains: [".Example.COM."]}
- org: E
  name: URL
  ua_patterns: [url]
  verify: {method: ip_ranges, url: "https://vendor.example/list.json"}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cs[0].Verify.Method != VerifyNone || cs[1].Verify.Method != VerifyNone {
		t.Errorf("none forms: %+v %+v", cs[0].Verify, cs[1].Verify)
	}
	if len(cs[2].static) != 2 {
		t.Errorf("static set: %v", cs[2].static)
	}
	if cs[3].Verify.Method != VerifyRDNS || cs[3].Verify.Domains[0] != "example.com" {
		t.Errorf("rdns normalised: %+v", cs[3].Verify)
	}
	if MatchUA(cs, "XX STATIC yy").Name != "Static" {
		t.Error("case-insensitive match")
	}
	if got := RangeURLs(append(cs, cs[4])); len(got) != 1 || got[0] != "https://vendor.example/list.json" {
		t.Errorf("RangeURLs %v", got)
	}
}

func TestParseCrawlersErrors(t *testing.T) {
	for name, y := range map[string]string{
		"unknown method": `[{org: A, name: a, ua_patterns: [a], verify: {method: magic}}]`,
		"rdns no domain": `[{org: A, name: a, ua_patterns: [a], verify: {method: rdns}}]`,
		"ranges empty":   `[{org: A, name: a, ua_patterns: [a], verify: {method: ip_ranges}}]`,
		"bad cidr":       `[{org: A, name: a, ua_patterns: [a], verify: {method: ip_ranges, cidrs: [nope]}}]`,
		"bad url":        `[{org: A, name: a, ua_patterns: [a], verify: {method: ip_ranges, url: "ftp://x"}}]`,
		"bad regexp":     `[{org: A, name: a, ua_patterns: ["("]}]`,
		"no patterns":    `[{org: A, name: a}]`,
		"no org":         `[{name: a, ua_patterns: [a]}]`,
		"not a list":     `org: A`,
	} {
		if _, err := ParseCrawlers([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := LoadCrawlers("/nonexistent/crawlers.yaml"); err == nil {
		t.Error("missing file accepted")
	}
}

func TestUserTriggeredAndExempt(t *testing.T) {
	cs, err := ParseCrawlers([]byte(`
- org: A
  name: Fetcher-User
  ua_patterns: ['Fetcher-User']
  verify: none
  user_triggered: true
  robots_exempt: true
- org: A
  name: Crawler
  ua_patterns: ['CrawlerBot']
  verify: none
`))
	if err != nil {
		t.Fatal(err)
	}
	if !RobotsExemptUA(cs, "x Fetcher-User/1.0") || RobotsExemptUA(cs, "CrawlerBot/2") || RobotsExemptUA(cs, "curl/8") {
		t.Error("RobotsExemptUA")
	}
	if _, err := ParseCrawlers([]byte(`
- org: A
  name: B
  ua_patterns: ['B']
  verify: none
  robots_exempt: true
`)); err == nil {
		t.Error("robots_exempt without user_triggered must be rejected")
	}
}

func TestRepoCrawlersExemptions(t *testing.T) {
	cs, err := LoadCrawlers("../../config/crawlers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for ua, want := range map[string]bool{
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot":                   true,
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)": true,
		"Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)":                                                       false, // honours robots.txt
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot":                      false,
	} {
		if got := RobotsExemptUA(cs, ua); got != want {
			t.Errorf("%s: exempt=%v want %v", ua, got, want)
		}
	}
}
