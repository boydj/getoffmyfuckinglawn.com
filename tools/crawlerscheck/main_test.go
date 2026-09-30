package main

import (
	"testing"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
)

func TestCheck(t *testing.T) {
	cs, err := attrib.ParseCrawlers([]byte(`
- org: A
  name: ABot
  ua_patterns: ['\bABot\b']
  verify: {method: ip_ranges, url: "https://www.a.example/abot.json"}
- org: D
  name: D-LongBot
  ua_patterns: ['\bD-LongBot\b']
  verify: {method: rdns, domains: [d.example]}
`))
	if err != nil {
		t.Fatal(err)
	}
	ipverse := []byte(`{"services": {
	  "A":    {"source_url": "http://a.example/abot.json", "user_agent_patterns": ["*ABot*"], "ip_list_authoritative": true},
	  "B":    {"source_url": "https://b.example/b.json", "user_agent_patterns": ["*BBot*"], "ip_list_authoritative": true},
	  "Meta": {"source_url": "https://raw.githubusercontent.com/x/as/32934.json", "user_agent_patterns": [], "ip_list_authoritative": false},
	  "A2":   {"source_url": "https://a.example/other.json", "user_agent_patterns": ["*ABot*"], "ip_list_authoritative": true},
	  "D":    {"source_url": "", "user_agent_patterns": ["LongBot"], "ip_list_authoritative": true}
	}}`)
	ondrejnov := []byte(`{"abot": "https://a.example/abot.json", "cbot": "https://c.example/c.json",
	  "d": "https://d.example/d.json", "abot-v2": "https://a.example/v2.json"}`)
	got, err := Check(cs, ipverse, ondrejnov)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		// Leads first.
		{Kind: "list", What: "https://b.example/b.json", Service: "B", From: "ipverse"},
		{Kind: "list", What: "https://c.example/c.json", Service: "cbot", From: "ondrejnov"},
		{Kind: "ua", What: "BBot", Service: "B", From: "ipverse"},
		// Then what needs nothing.
		{Kind: "list", What: "https://a.example/other.json", Service: "A2", From: "ipverse", Note: `its user agents already match "ABot" (ip_ranges)`, Settled: true},
		{Kind: "list", What: "https://a.example/v2.json", Service: "abot-v2", From: "ondrejnov", Note: `its name matches "ABot" (ip_ranges)`, Settled: true},
		{Kind: "list", What: "https://d.example/d.json", Service: "d", From: "ondrejnov", Note: `its name matches "D-LongBot" (rdns)`, Settled: true},
		{Kind: "list", What: "https://raw.githubusercontent.com/x/as/32934.json", Service: "Meta", From: "ipverse",
			Note: "not vendor-published (e.g. a whole ASN): do not use for verification", Settled: true},
		{Kind: "ua", What: "LongBot", Service: "D", From: "ipverse", Note: `a longer form of it is matched by "D-LongBot"`, Settled: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("finding %d: got %+v want %+v", i, got[i], want[i])
		}
	}
	if _, err := Check(cs, []byte("junk"), nil); err == nil {
		t.Error("bad catalogue must be an error")
	}
}

func TestCheckDeclined(t *testing.T) {
	ipverse := []byte(`{"services": {"G": {"user_agent_patterns": ["Chrome-Lighthouse"]}}}`)
	got, err := Check(nil, ipverse, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Settled || got[0].Note != declined["Chrome-Lighthouse"] {
		t.Errorf("findings: %+v", got)
	}
}

// The repo's own crawlers.yaml loads and covers what it claims to.
func TestRepoCoversAggregatedLists(t *testing.T) {
	cs, err := attrib.LoadCrawlers("../../config/crawlers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ondrejnov := []byte(`{"duckduckbot": "https://duckduckgo.com/duckduckbot.json",
	  "google-special": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
	  "perplexitybot": "https://www.perplexity.ai/perplexitybot.json"}`)
	got, err := Check(cs, nil, ondrejnov)
	if err != nil {
		t.Fatal(err)
	}
	// perplexity.ai vs our perplexity.com: a different host, still reported,
	// but as settled because PerplexityBot is already verified.
	if len(got) != 1 || got[0].Service != "perplexitybot" || !got[0].Settled {
		t.Errorf("findings: %+v", got)
	}
}
