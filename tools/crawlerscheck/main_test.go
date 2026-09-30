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
`))
	if err != nil {
		t.Fatal(err)
	}
	ipverse := []byte(`{"services": {
	  "A":    {"source_url": "http://a.example/abot.json", "user_agent_patterns": ["*ABot*"], "ip_list_authoritative": true},
	  "B":    {"source_url": "https://b.example/b.json", "user_agent_patterns": ["*BBot*"], "ip_list_authoritative": true},
	  "Meta": {"source_url": "https://raw.githubusercontent.com/x/as/32934.json", "user_agent_patterns": [], "ip_list_authoritative": false},
	  "A2":   {"source_url": "https://a.example/other.json", "user_agent_patterns": ["*ABot*"], "ip_list_authoritative": true}
	}}`)
	ondrejnov := []byte(`{"abot": "https://a.example/abot.json", "cbot": "https://c.example/c.json"}`)
	got, err := Check(cs, ipverse, ondrejnov)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		{Kind: "list", What: "https://a.example/other.json", Service: "A2", From: "ipverse", Note: `its user agents already match "ABot" (ip_ranges)`},
		{Kind: "list", What: "https://b.example/b.json", Service: "B", From: "ipverse"},
		{Kind: "list", What: "https://c.example/c.json", Service: "cbot", From: "ondrejnov"},
		{Kind: "list", What: "https://raw.githubusercontent.com/x/as/32934.json", Service: "Meta", From: "ipverse",
			Note: "not vendor-published (e.g. a whole ASN): do not use for verification"},
		{Kind: "ua", What: "BBot", Service: "B", From: "ipverse"},
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
	// perplexity.ai vs our perplexity.com: a different host, reported so a
	// human can decide (both are Perplexity's).
	if len(got) != 1 || got[0].Service != "perplexitybot" {
		t.Errorf("findings: %+v", got)
	}
}
