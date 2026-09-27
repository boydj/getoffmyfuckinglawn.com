// Package bots builds the private `lawn bots` report: every bot-like
// client, compliant or not, grouped by the product name in its user agent,
// with the evidence needed to recognise a new crawler (contact URL, reverse
// DNS, networks, header fingerprint, first seen). Nothing here is
// published; the public pages are built by package shame.
package bots

import (
	"regexp"
	"strings"
)

var (
	// A product token that names itself a bot, e.g. "FooBot/1.2",
	// "bar-crawler", "Baz Spider".
	botToken = regexp.MustCompile(`(?i)\b([a-z][a-z0-9._-]*?(?:bot|crawler|crawl|spider|scraper|fetcher|slurp|archiver|indexer|agent|preview|checker|monitor|scanner|reader)[a-z0-9._-]*)\b`)
	// Generic HTTP libraries and tools, e.g. "python-requests/2.31".
	libToken    = regexp.MustCompile(`(?i)^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|java|okhttp|apache-httpclient|node-fetch|axios|undici|libwww-perl|ruby|php|guzzle|httpie|scrapy|colly|headlesschrome|phantomjs)\b`)
	contactURL  = regexp.MustCompile(`\+?(https?://[^\s;)"]+)`)
	contactMail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	// "compatible;" is browser boilerplate, not a product.
	notProducts = map[string]bool{"compatible": true, "mozilla": true, "applewebkit": true, "khtml": true, "gecko": true, "like": true}
)

// Token returns the product name a client calls itself, or "" when the UA
// looks like an ordinary browser. The second result is true when the UA
// explicitly names a bot/crawler or an HTTP library.
func Token(ua string) (string, bool) {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "(empty user agent)", true
	}
	if m := libToken.FindStringSubmatch(ua); m != nil {
		return strings.ToLower(m[1]), true
	}
	for _, m := range botToken.FindAllStringSubmatch(ua, -1) {
		t := strings.Trim(m[1], "._-")
		if t == "" || notProducts[strings.ToLower(t)] {
			continue
		}
		// URLs inside the UA ("+https://example.com/bot.html") are
		// contact info, not the product name.
		if i := strings.Index(ua, m[1]); i > 0 && strings.ContainsAny(ua[max(0, i-1):i], "/.") {
			continue
		}
		return t, true
	}
	if !strings.HasPrefix(ua, "Mozilla/") {
		// Some other product: use its first token without the version.
		f := strings.FieldsFunc(ua, func(r rune) bool { return r == ' ' || r == '/' || r == ';' || r == '(' })
		if len(f) > 0 {
			return f[0], true
		}
	}
	return "", false
}

// Contact returns the URL or e-mail address a crawler advertises in its UA.
func Contact(ua string) string {
	if m := contactURL.FindStringSubmatch(ua); m != nil {
		return strings.TrimRight(m[1], ".,")
	}
	return strings.TrimLeft(contactMail.FindString(ua), "+")
}

// Domain returns the last two labels of a PTR name ("crawl-1.foo.example.com"
// -> "example.com"), which is usually the operator.
func Domain(ptr string) string {
	ptr = strings.TrimSuffix(ptr, ".")
	if ptr == "" {
		return ""
	}
	labels := strings.Split(ptr, ".")
	if len(labels) <= 2 {
		return ptr
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// crawlerishPTR reports whether a PTR name itself suggests a crawler.
var crawlerishPTR = regexp.MustCompile(`(?i)(crawl|bot|spider|scrap|fetch)`)
