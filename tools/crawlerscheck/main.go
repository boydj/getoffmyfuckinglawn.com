// Command crawlerscheck compares config/crawlers.yaml with public
// catalogues of crawler IP lists, to spot vendor lists and user agents
// that crawlers.yaml does not cover yet. It only reports: a finding is a
// lead to check against the vendor's own documentation, never something
// to copy in as is (see the rules at the top of crawlers.yaml).
//
//	go run ./tools/crawlerscheck [-crawlers config/crawlers.yaml]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/attrib"
)

// Catalogues. ipverse is CC0; ondrejnov has no license, so only the URLs
// it points at are read (facts, not copied into the repo).
const (
	ipverseURL   = "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json"
	ondrejnovURL = "https://raw.githubusercontent.com/ondrejnov/bot-ips/main/sources.json"
)

// declined lists catalogue user agents deliberately left out of
// crawlers.yaml, with the reason (see DECISIONS.md).
var declined = map[string]string{
	"Chrome-Lighthouse": "left out: Lighthouse also runs in anyone's DevTools and CI",
	"DuplexWeb-Google":  "left out: Google shut Duplex on the web down",
}

type ipverseDoc struct {
	Services map[string]struct {
		SourceURL     string   `json:"source_url"`
		UserAgents    []string `json:"user_agent_patterns"`
		Authoritative bool     `json:"ip_list_authoritative"`
	} `json:"services"`
}

// Finding is one thing crawlers.yaml does not cover.
type Finding struct {
	Kind    string // "list" (a vendor IP list we don't use) or "ua" (a user agent no entry matches)
	What    string // the URL or the user agent
	Service string // catalogue name
	From    string // catalogue
	Note    string
	// Settled: nothing to add. The list or user agent is already covered
	// by an entry, or the list is unusable. Kept for reference, printed
	// after the leads.
	Settled bool
}

// Check compares crawlers with the two catalogues (either may be nil).
func Check(crawlers []attrib.Crawler, ipverse, ondrejnov []byte) ([]Finding, error) {
	used := map[string]bool{}
	for _, u := range attrib.RangeURLs(crawlers) {
		used[normURL(u)] = true
	}
	var out []Finding
	if ipverse != nil {
		var doc ipverseDoc
		if err := json.Unmarshal(ipverse, &doc); err != nil {
			return nil, fmt.Errorf("ipverse: %w", err)
		}
		for name, s := range doc.Services {
			if s.SourceURL != "" && !used[normURL(s.SourceURL)] {
				f := Finding{Kind: "list", What: s.SourceURL, Service: name, From: "ipverse"}
				switch {
				case !s.Authoritative || strings.Contains(s.SourceURL, "githubusercontent.com"):
					f.Note, f.Settled = "not vendor-published (e.g. a whole ASN): do not use for verification", true
				default:
					if c := coveredBy(crawlers, s.UserAgents); c != nil {
						f.Note, f.Settled = fmt.Sprintf("its user agents already match %q (%s)", c.Name, c.Verify.Method), true
					}
				}
				out = append(out, f)
			}
			for _, p := range s.UserAgents {
				ua := strings.Trim(p, "*")
				if ua == "" || attrib.MatchUA(crawlers, ua) != nil {
					continue
				}
				f := Finding{Kind: "ua", What: ua, Service: name, From: "ipverse"}
				if why, ok := declined[ua]; ok {
					f.Note, f.Settled = why, true
				} else if c := mentionedBy(crawlers, ua); c != nil {
					// e.g. the catalogue's "NotebookLM" for our Google-NotebookLM.
					f.Note, f.Settled = fmt.Sprintf("a longer form of it is matched by %q", c.Name), true
				}
				out = append(out, f)
			}
		}
	}
	if ondrejnov != nil {
		var src map[string]string
		if err := json.Unmarshal(ondrejnov, &src); err != nil {
			return nil, fmt.Errorf("ondrejnov: %w", err)
		}
		for name, u := range src {
			if used[normURL(u)] {
				continue
			}
			f := Finding{Kind: "list", What: u, Service: name, From: "ondrejnov"}
			if c := namedBy(crawlers, name); c != nil {
				f.Note, f.Settled = fmt.Sprintf("its name matches %q (%s)", c.Name, c.Verify.Method), true
			}
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Settled != b.Settled {
			return !a.Settled
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.What != b.What {
			return a.What < b.What
		}
		return a.From < b.From
	})
	return out, nil
}

// coveredBy returns the entry that every one of uas matches, or nil.
func coveredBy(crawlers []attrib.Crawler, uas []string) *attrib.Crawler {
	var first *attrib.Crawler
	for _, p := range uas {
		c := attrib.MatchUA(crawlers, strings.Trim(p, "*"))
		if c == nil {
			return nil
		}
		if first == nil {
			first = c
		}
	}
	return first
}

// mentionedBy returns the first entry with a pattern that contains ua
// (case-insensitively): a catalogue that lists a shortened token.
func mentionedBy(crawlers []attrib.Crawler, ua string) *attrib.Crawler {
	ua = strings.ToLower(ua)
	for i := range crawlers {
		for _, re := range crawlers[i].Patterns {
			if strings.Contains(strings.ToLower(re.String()), ua) {
				return &crawlers[i]
			}
		}
	}
	return nil
}

// namedBy returns the entry a catalogue service name refers to: one whose
// name or org equals it, or whose patterns match it (ondrejnov names its
// lists after the bot, e.g. "bingbot", "perplexity-user", "ahrefs").
func namedBy(crawlers []attrib.Crawler, name string) *attrib.Crawler {
	for i := range crawlers {
		if strings.EqualFold(crawlers[i].Name, name) || strings.EqualFold(crawlers[i].Org, name) {
			return &crawlers[i]
		}
	}
	return attrib.MatchUA(crawlers, name)
}

// normURL makes http/https and www. variants of one list compare equal.
func normURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	host := strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	return host + u.EscapedPath() + "?" + u.RawQuery
}

func fetch(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func main() {
	path := flag.String("crawlers", "config/crawlers.yaml", "crawlers.yaml to check")
	flag.Parse()
	crawlers, err := attrib.LoadCrawlers(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	get := func(u string) []byte {
		b, err := fetch(ctx, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping catalogue: %v\n", err)
			return nil
		}
		return b
	}
	findings, err := Check(crawlers, get(ipverseURL), get(ondrejnovURL))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(findings) == 0 {
		fmt.Println("crawlers.yaml covers every list and user agent in the catalogues.")
		return
	}
	settled := false
	for i, f := range findings {
		switch {
		case i == 0 && !f.Settled:
			fmt.Println("Leads to check against each vendor's own documentation before adding anything:")
		case f.Settled && !settled:
			if i == 0 {
				fmt.Println("No leads.")
			}
			fmt.Println("\nAlready covered or unusable (for reference):")
			settled = true
		}
		label := map[string]string{"list": "IP list not used", "ua": "user agent not matched"}[f.Kind]
		fmt.Printf("  %-22s %-70s %s (%s)", label, f.What, f.Service, f.From)
		if f.Note != "" {
			fmt.Printf(" - %s", f.Note)
		}
		fmt.Println()
	}
}
