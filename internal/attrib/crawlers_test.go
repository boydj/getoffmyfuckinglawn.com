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

func TestRepoCrawlersShapBot(t *testing.T) {
	cs, err := LoadCrawlers("../../config/crawlers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := MatchUA(cs, "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ShapBot/0.1.0")
	if c == nil || c.Name != "ShapBot" || c.Org != "Parallel Web Systems" || c.Verify.Method != VerifyIPRanges ||
		c.Verify.URL != "https://docs.parallel.ai/resources/shapbot.json" || c.UserTriggered || c.RobotsExempt {
		t.Fatalf("ShapBot: %+v", c)
	}
}

// Real user agents from the vendors' pages match the right entry; Googlebot
// is not captured by the broader Google entries.
func TestRepoCrawlersAdded(t *testing.T) {
	cs, err := LoadCrawlers("../../config/crawlers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for ua, want := range map[string]struct {
		name, method          string
		userTriggered, exempt bool
	}{
		"AdsBot-Google (+http://www.google.com/adsbot.html)": {"Google special-case crawlers", VerifyIPRanges, false, false},
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0 Mobile Safari/537.36 (compatible; AdsBot-Google-Mobile; +http://www.google.com/mobile/adsbot.html)": {"Google special-case crawlers", VerifyIPRanges, false, false},
		"FeedFetcher-Google; (+http://www.google.com/feedfetcher.html)":                                                         {"Google user-triggered fetchers", VerifyIPRanges, true, true},
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                              {"Googlebot", VerifyRDNS, false, false},
		"DuckAssistBot/1.2; (+http://duckduckgo.com/duckassistbot.html)":                                                        {"DuckAssistBot", VerifyIPRanges, false, false},
		"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)":                                                            {"DuckDuckBot", VerifyIPRanges, false, false},
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; MistralAI-User/1.0; +https://docs.mistral.ai/robots)":   {"MistralAI-User", VerifyIPRanges, true, false},
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; MistralAI-Index/1.0; +https://docs.mistral.ai/robots)":  {"MistralAI-Index", VerifyIPRanges, false, false},
		"Mozilla/5.0 (compatible; SeznamBot/4.0; +http://napoveda.seznam.cz/seznambot-intro/)":                                  {"SeznamBot", VerifyIPRanges, false, false},
		"Mozilla/5.0 (compatible; Kagibot/1.0; +https://kagi.com/bot)":                                                          {"Kagibot", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)":                                                    {"AhrefsBot", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; AhrefsSiteAudit/6.1; +http://ahrefs.com/robot/site-audit)":                                    {"AhrefsSiteAudit", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; SERankingBacklinksBot/1.0; +https://seranking.com/backlinks-crawler)":                         {"SERankingBacklinksBot", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; SEBot-WA/1.0)":                                                                                {"SEBot-WA", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; GoogleOther)":                                                                                 {"Google common crawlers", VerifyRDNS, false, false},
		"GoogleOther-Image/1.0":                                                                                                 {"Google common crawlers", VerifyRDNS, false, false},
		"Mozilla/5.0 (X11; Linux x86_64; Storebot-Google/1.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0 Safari/537.36": {"Google common crawlers", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)":                                                                  {"Google common crawlers", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":                                               {"Bingbot", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)":                                              {"Bingbot", VerifyRDNS, false, false},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) BingPreview/1.0b":                     {"Bingbot", VerifyRDNS, false, false},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0 Safari/537.36 Edg/112.0 MicrosoftPreview/2.0 +https://aka.ms/MicrosoftPreview":                       {"MicrosoftPreview", VerifyNone, false, false},
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)":                                                                                                                         {"facebookexternalhit", VerifyNone, false, false},
		"Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/webmasters/facebookbot/)":                                                                                  {"FacebookBot", VerifyNone, false, false},
		"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)":                                                                                                                                  {"YandexBot", VerifyRDNS, false, false},
		"Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)":                                                                                                                               {"YandexBot", VerifyRDNS, false, false},
		"Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B411 Safari/600.1.4 (compatible; YandexMobileBot/3.0; +http://yandex.com/bots)": {"YandexBot", VerifyRDNS, false, false},
	} {
		c := MatchUA(cs, ua)
		if c == nil || c.Name != want.name || c.Verify.Method != want.method || c.UserTriggered != want.userTriggered || c.RobotsExempt != want.exempt {
			t.Errorf("%.60s: got %+v", ua, c)
		}
	}
	// Yandex's apps and browser are not Yandex's robots.
	for _, ua := range []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 YaBrowser/24.1.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 YandexSearch/24.10 Mobile Safari/537.36",
	} {
		if c := MatchUA(cs, ua); c != nil {
			t.Errorf("%.60s matched %q", ua, c.Name)
		}
	}
	// The Google entries use every Google list, and every list is fetched.
	google := MatchUA(cs, "FeedFetcher-Google")
	if n := len(google.Verify.Lists()); n != 5 {
		t.Errorf("Google lists: %d", n)
	}
	urls := map[string]bool{}
	for _, u := range RangeURLs(cs) {
		urls[u] = true
	}
	for _, u := range google.Verify.Lists() {
		if !urls[u] {
			t.Errorf("%s not refreshed", u)
		}
	}
}
