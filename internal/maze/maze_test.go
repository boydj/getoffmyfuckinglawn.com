package maze

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	corpusOnce  sync.Once
	corpusChain *Chain
	corpusErr   error
)

func testChain(t testing.TB) *Chain {
	t.Helper()
	corpusOnce.Do(func() { corpusChain, corpusErr = LoadCorpus("../../corpus") })
	if corpusErr != nil {
		t.Fatalf("LoadCorpus: %v", corpusErr)
	}
	return corpusChain
}

var testSecret = []byte("test-secret-0123456789abcdef")

func render(g *Generator, path string) string {
	var b bytes.Buffer
	g.Render(&b, path)
	return b.String()
}

// randomPaths returns n varied maze paths: entry pages, real child links
// harvested from rendered pages (with fake segments), and junk.
func randomPaths(g *Generator, n int) []string {
	r := rand.New(rand.NewPCG(1, 2))
	paths := []string{"/lawn", "/lawn/", "/lawn/nonsense", "/lawn/a/b/c/"}
	paths = append(paths, g.EntryURLs(5)...)
	for len(paths) < n {
		if r.IntN(5) == 0 {
			paths = append(paths, fmt.Sprintf("/lawn/%x/%d", r.Uint64(), r.IntN(1000)))
			continue
		}
		links := linkRE.FindAllStringSubmatch(render(g, paths[r.IntN(len(paths))]), -1)
		paths = append(paths, links[r.IntN(len(links))][1])
	}
	return paths[:n]
}

var (
	linkRE  = regexp.MustCompile(`<a href="([^"]*)"`)
	titleRE = regexp.MustCompile(`<title>([^<]*)</title>`)
	childRE = regexp.MustCompile(`^/lawn/(?:[a-z0-9]+/){0,3}[a-z2-7]+$`)
)

func TestDeterministic(t *testing.T) {
	c := testChain(t)
	g1 := NewGenerator(testSecret, c)
	g2 := NewGenerator(testSecret, c)
	for _, p := range randomPaths(g1, 50) {
		a, b := render(g1, p), render(g1, p)
		if a != b {
			t.Fatalf("same generator, path %q: pages differ", p)
		}
		if c := render(g2, p); a != c {
			t.Fatalf("second generator, path %q: pages differ", p)
		}
	}
	if render(g1, "/lawn/x") == render(g1, "/lawn/y") {
		t.Fatal("different paths gave identical pages")
	}
}

func TestSecretSensitivity(t *testing.T) {
	c := testChain(t)
	g1 := NewGenerator(testSecret, c)
	g2 := NewGenerator([]byte("another-secret-0123456789abcdef"), c)
	for _, p := range []string{"/lawn/", "/lawn/abc", "/lawn/archive/2019/aaaa"} {
		if render(g1, p) == render(g2, p) {
			t.Fatalf("path %q: different secrets gave identical pages", p)
		}
	}
	if e1, e2 := g1.EntryURLs(3), g2.EntryURLs(3); e1[0] == e2[0] {
		t.Fatalf("different secrets gave identical entry URLs %v", e1)
	}
}

func TestTokenRoundTrip(t *testing.T) {
	mac := bytes.Repeat([]byte{0xa5}, 32)
	depths := []int{MaxDepth - 1, MaxDepth, 1 << 14, 1<<14 - 1}
	for d := range 301 {
		depths = append(depths, d)
	}
	for _, d := range depths {
		tok := string(appendToken(nil, d, mac))
		if strings.ToLower(tok) != tok || strings.Contains(tok, "=") {
			t.Fatalf("token %q not lowercase/unpadded", tok)
		}
		got, ok := decodeToken(tok)
		if !ok || got != d {
			t.Fatalf("depth %d: token %q decoded to %d ok=%v", d, tok, got, ok)
		}
		if got := Depth("/lawn/archive/2019/" + tok); got != d {
			t.Fatalf("Depth with fake segments: got %d want %d", got, d)
		}
	}
	for _, d := range []int{MaxDepth + 1, 1 << 40} {
		if got, _ := decodeToken(string(appendToken(nil, d, mac))); got != MaxDepth {
			t.Fatalf("depth %d should clamp to %d, got %d", d, MaxDepth, got)
		}
	}
	if got, _ := decodeToken(string(appendToken(nil, -5, mac))); got != 0 {
		t.Fatalf("negative depth should clamp to 0, got %d", got)
	}
}

func TestChildDepth(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	for _, e := range g.EntryURLs(4) {
		if Depth(e) != 0 {
			t.Fatalf("entry %q depth %d", e, Depth(e))
		}
	}
	path := "/lawn/"
	for want := 1; want <= 300; want++ {
		links := linkRE.FindAllStringSubmatch(render(g, path), -1)
		for _, l := range links {
			if d := Depth(l[1]); d != want {
				t.Fatalf("child %q of %q: depth %d want %d", l[1], path, d, want)
			}
		}
		path = links[want%len(links)][1]
	}
}

func TestIsMazePathAndDepth(t *testing.T) {
	maze := map[string]bool{
		"/lawn": true, "/lawn/": true, "/lawn/x": true, "/lawn/a/b/": true,
		"/": false, "/lawnmower": false, "/shame/": false, "": false, "lawn/": false, "/LAWN/": false,
	}
	for p, want := range maze {
		if got := IsMazePath(p); got != want {
			t.Errorf("IsMazePath(%q)=%v want %v", p, got, want)
		}
	}
	tok := string(appendToken(nil, 7, make([]byte, 32)))
	cases := map[string]int{
		"/lawn": 0, "/lawn/": 0, "/lawn//": 0, "/": 0, "/robots.txt": 0,
		"/lawn/" + tok: 7, "/lawn/" + tok + "/": 7, "/lawn/x/" + tok: 7,
		"/lawn/" + strings.ToUpper(tok):     7,
		"/lawn/" + tok + "a":                0, // wrong length
		"/lawn/" + tok[:len(tok)-1]:         0,
		"/lawn/" + tok + "/lawn":            0,
		"/lawn/!!!!":                        0,
		"/lawn/archive":                     0,
		"/lawn/2019":                        0,
		"/other/" + tok:                     0,
		"/lawn/" + strings.Repeat("a", 200): 0,
	}
	for p, want := range cases {
		if got := Depth(p); got != want {
			t.Errorf("Depth(%q)=%d want %d", p, got, want)
		}
	}
}

func TestPageShape(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	checkPages(t, g, randomPaths(g, 500))
}

func TestFallbackChain(t *testing.T) {
	for _, c := range []*Chain{nil, NewChain(), NewChain("too short")} {
		g := NewGenerator(testSecret, c)
		checkPages(t, g, randomPaths(g, 60))
	}
}

func checkPages(t *testing.T, g *Generator, paths []string) {
	t.Helper()
	minSz, maxSz := 1<<30, 0
	for _, p := range paths {
		page := render(g, p)
		minSz, maxSz = min(minSz, len(page)), max(maxSz, len(page))
		if len(page) < minPageBytes || len(page) > maxPageBytes {
			t.Fatalf("path %q: size %d outside [%d,%d]", p, len(page), minPageBytes, maxPageBytes)
		}
		links := linkRE.FindAllStringSubmatch(page, -1)
		if len(links) < minLinks || len(links) > maxLinks {
			t.Fatalf("path %q: %d links", p, len(links))
		}
		for _, l := range links {
			if !childRE.MatchString(l[1]) || !IsMazePath(l[1]) {
				t.Fatalf("path %q: bad link %q", p, l[1])
			}
		}
		if n := strings.Count(page, "<p>"); n < minParagraphs || n > maxParagraphs {
			t.Fatalf("path %q: %d paragraphs", p, n)
		}
		if !strings.Contains(page, `<meta name="robots" content="noindex,nofollow">`) {
			t.Fatalf("path %q: missing robots meta", p)
		}
		lower := strings.ToLower(page)
		for _, bad := range []string{"<script", "<img", "src=", "http://", "https://", "<link", "@import", "url("} {
			if strings.Contains(lower, bad) {
				t.Fatalf("path %q: page contains %q", p, bad)
			}
		}
		if m := titleRE.FindStringSubmatch(page); m == nil || len(m[1]) < 5 {
			t.Fatalf("path %q: no plausible title", p)
		}
		if err := wellFormed(page); err != nil {
			t.Fatalf("path %q: %v\n%s", p, err, page)
		}
	}
	t.Logf("%d pages, size range %d..%d bytes", len(paths), minSz, maxSz)
}

var entityRE = regexp.MustCompile(`^&(?:[a-z]+|#[0-9]+);`)

// wellFormed is a small HTML sanity checker: tags balance (void elements
// aside), text never contains a raw '<' or '>', and every '&' starts an
// entity.
func wellFormed(page string) error {
	void := map[string]bool{"meta": true, "!doctype": true}
	var stack []string
	for i := 0; i < len(page); i++ {
		switch page[i] {
		case '>':
			return fmt.Errorf("stray '>' at %d", i)
		case '&':
			if !entityRE.MatchString(page[i:]) {
				return fmt.Errorf("bare '&' at %d: %q", i, page[i:min(i+12, len(page))])
			}
		case '<':
			end := strings.IndexByte(page[i:], '>')
			if end < 0 {
				return fmt.Errorf("unterminated tag at %d", i)
			}
			tag := page[i+1 : i+end]
			if strings.ContainsRune(tag, '<') {
				return fmt.Errorf("'<' inside tag at %d", i)
			}
			name := strings.ToLower(strings.Fields(strings.TrimPrefix(tag, "/"))[0])
			switch {
			case name == "style":
				j := strings.Index(page[i:], "</style>")
				if j < 0 {
					return fmt.Errorf("unterminated style")
				}
				i += j + len("</style>") - 1
				continue
			case void[name]:
			case strings.HasPrefix(tag, "/"):
				if len(stack) == 0 || stack[len(stack)-1] != name {
					return fmt.Errorf("unbalanced </%s> at %d (stack %v)", name, i, stack)
				}
				stack = stack[:len(stack)-1]
			default:
				stack = append(stack, name)
			}
			i += end
		}
	}
	if len(stack) != 0 {
		return fmt.Errorf("unclosed tags %v", stack)
	}
	return nil
}

func TestEscaping(t *testing.T) {
	nasty := strings.Repeat(`Tom said <script>alert(1)</script> & left. The R&D team wrote "quoted" <b>bold</b> words here. `+
		`Then <a href="x">a link</a> & more & more appeared. It was a dark & stormy night > dawn. `, 20)
	g := NewGenerator(testSecret, NewChain(nasty))
	for _, p := range randomPaths(g, 50) {
		page := render(g, p)
		for _, bad := range []string{"<script", "<b>", `<a href="x"`, "R&D"} {
			if strings.Contains(page, bad) {
				t.Fatalf("unescaped %q in page", bad)
			}
		}
		if err := wellFormed(page); err != nil {
			t.Fatalf("path %q: %v", p, err)
		}
	}
	if !strings.Contains(render(g, "/lawn/"), "&amp;") {
		t.Fatal("expected escaped ampersands in body text")
	}
}

func TestTitlesAvoidProperNames(t *testing.T) {
	c := testChain(t)
	g := NewGenerator(testSecret, c)
	for _, w := range c.vocab {
		if w != strings.ToLower(w) {
			t.Fatalf("vocab word %q is not lowercase", w)
		}
	}
	for _, p := range randomPaths(g, 200) {
		title := titleRE.FindStringSubmatch(render(g, p))[1]
		for _, name := range []string{"Alice", "Wentworth", "Elliot", "Syme", "Austen", "Carroll", "Chesterton", "News", "Breaking"} {
			if strings.Contains(title, name) {
				t.Fatalf("title %q contains %q", title, name)
			}
		}
	}
}

func TestRenderAppends(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	var b bytes.Buffer
	b.WriteString("prefix")
	g.Render(&b, "/lawn/zzz")
	if b.String() != "prefix"+render(g, "/lawn/zzz") {
		t.Fatal("Render into non-empty buffer differs from fresh render")
	}
}

func TestEntryURLs(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	a, b := g.EntryURLs(8), g.EntryURLs(8)
	if len(a) != 8 {
		t.Fatalf("got %d URLs", len(a))
	}
	seen := map[string]bool{}
	for i, u := range a {
		if u != b[i] {
			t.Fatal("EntryURLs not deterministic")
		}
		if seen[u] || !childRE.MatchString(u) || Depth(u) != 0 {
			t.Fatalf("bad entry URL %q", u)
		}
		seen[u] = true
	}
	if len(g.EntryURLs(0)) != 0 {
		t.Fatal("EntryURLs(0) not empty")
	}
}

func TestBufferPool(t *testing.T) {
	b := GetBuffer()
	b.WriteString("junk")
	PutBuffer(b)
	if GetBuffer().Len() != 0 {
		t.Fatal("GetBuffer returned non-empty buffer")
	}
	big := GetBuffer()
	big.Grow(maxPooledBuffer * 2)
	PutBuffer(big) // must not panic; dropped
	PutBuffer(nil)
}

func TestRenderAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under -race")
	}
	g := NewGenerator(testSecret, testChain(t))
	buf := GetBuffer()
	allocs := testing.AllocsPerRun(200, func() {
		buf.Reset()
		g.Render(buf, "/lawn/archive/2019/aaaabbbbccccddddee")
	})
	if allocs > 1 {
		t.Fatalf("Render allocates %.1f times per call", allocs)
	}
}

func TestTrainingSpeed(t *testing.T) {
	if raceEnabled {
		t.Skip("timing is not meaningful under -race")
	}
	start := time.Now()
	if _, err := LoadCorpus("../../corpus"); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("LoadCorpus took %v", d)
	}
}

func TestLoadCorpusErrors(t *testing.T) {
	if _, err := LoadCorpus(t.TempDir()); err == nil {
		t.Fatal("expected error for empty corpus dir")
	}
}

func TestCleanWordAndSkipLine(t *testing.T) {
	words := map[string]string{
		`'and`: "and", `book,'`: "book,", `_very_`: "very", `(as`: "as", `sleepy)`: "sleepy",
		`"Oh!"`: "Oh!", `don't`: "don't", `''`: "", `said.)`: "said.",
	}
	for in, want := range words {
		if got := cleanWord(in); got != want {
			t.Errorf("cleanWord(%q)=%q want %q", in, got, want)
		}
	}
	skip := map[string]bool{
		"[Persuasion by Jane Austen 1818]": true, "CHAPTER I. Down the Rabbit-Hole": true,
		"THE END": true, "": true, "***": true, "Alice was beginning": false, "I said.": false,
	}
	for in, want := range skip {
		if got := skipLine(in); got != want {
			t.Errorf("skipLine(%q)=%v want %v", in, got, want)
		}
	}
}

func BenchmarkRender(b *testing.B) {
	g := NewGenerator(testSecret, testChain(b))
	paths := randomPaths(g, 256)
	buf := GetBuffer()
	total := 0
	for _, p := range paths {
		total += len(render(g, p))
	}
	b.SetBytes(int64(total / len(paths)))
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		buf.Reset()
		g.Render(buf, paths[i%len(paths)])
		i++
	}
}

func BenchmarkLoadCorpus(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := LoadCorpus("../../corpus"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestLinksLeadThePage(t *testing.T) {
	g := NewGenerator(testSecret, testChain(t))
	for _, p := range append(g.EntryURLs(50), "/lawn/", "/lawn/archive/2019/x") {
		var b bytes.Buffer
		g.Render(&b, p)
		page := b.Bytes()
		lead := LeadLen(page)
		if lead <= 0 || lead >= len(page) {
			t.Fatalf("%s: lead %d of %d", p, lead, len(page))
		}
		inLead := bytes.Count(page[:lead], []byte(`href="/lawn/`))
		if total := bytes.Count(page, []byte(`href="/lawn/`)); inLead != total || inLead < 10 {
			t.Fatalf("%s: %d of %d links in the lead", p, inLead, total)
		}
		// The body text comes after the links, so the drip still has work.
		if !bytes.Contains(page[lead:], []byte("<p>")) {
			t.Fatalf("%s: no paragraphs after the lead", p)
		}
		if bytes.Index(page, []byte("<h1>")) > bytes.Index(page, []byte("<nav>")) {
			t.Fatalf("%s: nav before heading", p)
		}
	}
	if LeadLen([]byte("<p>no nav</p>")) != 0 {
		t.Fatal("LeadLen without nav must be 0")
	}
}
