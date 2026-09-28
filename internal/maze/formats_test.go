package maze

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

type link struct{ path, anchor string }

var (
	htmlLinkRE   = regexp.MustCompile(`<li><a href="(/lawn/[^"]+)">([^<]+)</a></li>`)
	geminiLinkRE = regexp.MustCompile(`(?m)^=> (/lawn/\S+) (.+)$`)
)

func htmlLinks(page string) []link {
	var out []link
	for _, m := range htmlLinkRE.FindAllStringSubmatch(page, -1) {
		out = append(out, link{m[1], m[2]})
	}
	return out
}

// The same path renders the same page in every format: same title, same
// links with the same anchors, links inside the lead.
func TestFormatsSamePage(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	for _, p := range append(g.EntryURLs(20), "/lawn/", "/lawn/1999/notes/abc") {
		var h, gm, gp bytes.Buffer
		g.Render(&h, p)
		gmLead := g.RenderAs(&gm, p, FormatGemini, "", 0)
		gpLead := g.RenderAs(&gp, p, FormatGopher, "lawn.example", 70)
		want := htmlLinks(h.String())
		if len(want) < minLinks {
			t.Fatalf("%s: %d html links", p, len(want))
		}
		title := h.String()[strings.Index(h.String(), "<h1>")+4 : strings.Index(h.String(), "</h1>")]

		// Gemini.
		gtxt := gm.String()
		if !strings.HasPrefix(gtxt, "# "+title+"\n\n") {
			t.Fatalf("%s: gemini title: %q", p, gtxt[:min(80, len(gtxt))])
		}
		var got []link
		for _, m := range geminiLinkRE.FindAllStringSubmatch(gtxt, -1) {
			got = append(got, link{m[1], m[2]})
		}
		if !equalLinks(got, want) {
			t.Fatalf("%s: gemini links differ:\n%v\n%v", p, got, want)
		}
		lastLink := strings.LastIndex(gtxt, "\n=> ")
		if gmLead <= lastLink || gmLead > len(gtxt) {
			t.Fatalf("%s: gemini lead %d does not cover links (last at %d)", p, gmLead, lastLink)
		}
		for _, line := range strings.Split(strings.TrimRight(gtxt, "\n"), "\n") {
			if line == "" || strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "=> /lawn/") {
				continue
			}
			if gemtextSpecial([]byte(line)) {
				t.Fatalf("%s: text line reads as markup: %q", p, line)
			}
		}

		// Gopher.
		ptxt := gp.String()
		if !strings.HasSuffix(ptxt, "\r\n.\r\n") {
			t.Fatalf("%s: gopher menu must end with a lone dot", p)
		}
		got = got[:0]
		lines := strings.Split(strings.TrimSuffix(ptxt, ".\r\n"), "\r\n")
		lines = lines[:len(lines)-1] // after the final CRLF
		if !strings.HasPrefix(lines[0], "i"+title+"\t") {
			t.Fatalf("%s: gopher title line %q", p, lines[0])
		}
		for _, line := range lines {
			f := strings.Split(line, "\t")
			if len(f) != 4 {
				t.Fatalf("%s: gopher line has %d fields: %q", p, len(f), line)
			}
			switch line[0] {
			case 'i':
				if len(f[0])-1 > gopherWidth {
					t.Fatalf("%s: info line longer than %d: %q", p, gopherWidth, f[0])
				}
			case '1':
				if f[2] != "lawn.example" || f[3] != "70" {
					t.Fatalf("%s: link to %s:%s", p, f[2], f[3])
				}
				got = append(got, link{f[1], f[0][1:]})
			default:
				t.Fatalf("%s: unexpected item type %q", p, line[:1])
			}
		}
		if !equalLinks(got, want) {
			t.Fatalf("%s: gopher links differ:\n%v\n%v", p, got, want)
		}
		if lastLink := strings.LastIndex(ptxt, "\r\n1"); gpLead <= lastLink || gpLead > len(ptxt) {
			t.Fatalf("%s: gopher lead %d does not cover links", p, gpLead)
		}
		// Deterministic.
		var again bytes.Buffer
		g.RenderAs(&again, p, FormatGopher, "lawn.example", 70)
		if again.String() != ptxt {
			t.Fatalf("%s: gopher render not deterministic", p)
		}
	}
	// Render's lead for HTML matches LeadLen.
	var b bytes.Buffer
	if lead := g.RenderAs(&b, "/lawn/x", FormatHTML, "", 0); lead != LeadLen(b.Bytes()) {
		t.Errorf("html lead %d != LeadLen %d", lead, LeadLen(b.Bytes()))
	}
}

func equalLinks(a, b []link) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGemtextSpecial(t *testing.T) {
	for line, want := range map[string]bool{"=> x": true, "# h": true, "> q": true, "* item": true, "```": true,
		"=x": false, "*emphasis": false, "plain": false, "": false, "`code`": false} {
		if gemtextSpecial([]byte(line)) != want {
			t.Errorf("%q: want %v", line, want)
		}
	}
}

func TestGopherWrap(t *testing.T) {
	var b bytes.Buffer
	gopherWrap(&b, []byte(strings.Repeat("word ", 40)+strings.Repeat("x", 90)))
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\r\n"), "\r\n") {
		text := strings.SplitN(line, "\t", 2)[0][1:]
		if len(text) > gopherWidth || strings.HasPrefix(text, " ") {
			t.Fatalf("bad wrap: %q", text)
		}
	}
}

func TestRenderAsNoAlloc(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under -race (sync.Pool drops items)")
	}
	g := NewGenerator(testSecret, testChain(t))
	var b bytes.Buffer
	for _, f := range []Format{FormatGemini, FormatGopher} {
		if n := testing.AllocsPerRun(50, func() {
			b.Reset()
			g.RenderAs(&b, "/lawn/abcdefghijklmnop", f, "lawn.example", 70)
		}); n != 0 {
			t.Errorf("format %d: %v allocs per render", f, n)
		}
	}
}
