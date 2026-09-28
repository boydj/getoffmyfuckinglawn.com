package maze

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math/rand/v2"
	"strconv"
	"sync"
)

// Page size bounds, in bytes. Render guarantees minPageBytes <= len <=
// maxPageBytes by construction; targetMin/targetMax pick the size aimed for.
const (
	minPageBytes = 2048
	maxPageBytes = 8192
	targetMin    = 2400
	targetMax    = 7000

	minParagraphs = 3
	maxParagraphs = 8
	minLinks      = 10
	maxLinks      = 20

	minSentenceWords = 5
	maxSentenceWords = 40
)

// Generator renders maze pages. It is safe for concurrent use.
type Generator struct {
	secret []byte
	chain  *Chain
	vocab  []string
	states sync.Pool // *renderState
}

// renderState is the per-Render scratch space, pooled so Render allocates
// nothing in steady state.
type renderState struct {
	mac   hash.Hash
	sum   [sha256.Size]byte
	cha   rand.ChaCha8
	rng   *rand.Rand
	path  []byte
	title []byte
	tok   []byte
	num   [20]byte
	idx   [3]byte
	links bytes.Buffer
	lp    bytes.Buffer // one link's path, before it is formatted
	la    bytes.Buffer // one link's anchor text
	para  bytes.Buffer // one paragraph of plain text (gemtext, gophermap)
}

// NewGenerator returns a Generator keyed by secret. A nil or empty chain
// falls back to a small built-in neutral text.
func NewGenerator(secret []byte, chain *Chain) *Generator {
	if chain == nil || len(chain.emit) == 0 {
		chain = NewChain(fallbackText)
	}
	g := &Generator{secret: append([]byte(nil), secret...), chain: chain, vocab: chain.vocab}
	if len(g.vocab) < 8 {
		g.vocab = fallbackVocab
	}
	g.states.New = func() any {
		st := &renderState{
			mac:   hmac.New(sha256.New, g.secret),
			path:  make([]byte, 0, 256),
			title: make([]byte, 0, 128),
			tok:   make([]byte, 0, maxTokenLen),
		}
		st.rng = rand.New(&st.cha)
		st.links.Grow(4096)
		st.lp.Grow(128)
		st.la.Grow(128)
		return st
	}
	return g
}

// pageIDTag separates page IDs from link MACs (which start with 0x00).
var pageIDTag = []byte("\x01id")

// pageID is the 32-bit ID of the page at st.path: HMAC(secret, path ||
// "\x01id"). Child links carry their parent's ID.
func pageID(st *renderState) uint32 {
	return binary.BigEndian.Uint32(st.macSum(pageIDTag)[:4])
}

// IDs returns the page ID of path and, if its URL carries one, the ID of
// the page whose link led here. Both are stable for a given secret.
func (g *Generator) IDs(path string) (page, parent uint32, hasParent bool) {
	st := g.states.Get().(*renderState)
	st.path = append(st.path[:0], path...)
	page = pageID(st)
	g.states.Put(st)
	parent, hasParent = ParentID(path)
	return page, parent, hasParent
}

// macSum computes HMAC(secret, st.path || extra) into st.sum.
func (st *renderState) macSum(extra []byte) []byte {
	st.mac.Reset()
	st.mac.Write(st.path)
	if len(extra) > 0 {
		st.mac.Write(extra)
	}
	return st.mac.Sum(st.sum[:0])
}

const pageHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>`

const pageHeadEnd = `</title>
<style>body{max-width:40em;margin:2em auto;padding:0 1em;font:1.05em/1.6 Georgia,serif;color:#222;background:#fbfaf6}h1,h2{font-weight:normal}a{color:#335}@media(prefers-color-scheme:dark){body{color:#ddd;background:#1b1b1b}a{color:#9ab}}</style>
</head>
<body>
<h1>`

const pageTail = "</body>\n</html>\n"

// Format is the markup a maze page is rendered in. Every format renders
// the same page for a path (title, links, anchors and text all come from
// the same random sequence), so the maze is one maze whichever protocol a
// crawler walks it with.
type Format uint8

const (
	FormatHTML   Format = iota // text/html
	FormatGemini               // text/gemini (gemtext)
	FormatGopher               // a gopher menu (RFC 1436), text as info lines
)

// gopherWidth is the column gopher text is wrapped at (classic 70-column
// clients).
const gopherWidth = 70

// Render writes the full HTML page for path into buf. The output depends
// only on the secret, the chain and path: the same path always yields a
// byte-identical page. Content is appended; buf is not reset.
func (g *Generator) Render(buf *bytes.Buffer, path string) {
	g.RenderAs(buf, path, FormatHTML, "", 0)
}

// RenderAs writes path's page in format f and returns the lead length: the
// bytes through the link block, to be sent at once. host and port are the
// server gopher menu links point at (unused by other formats). Like
// Render it is deterministic and does not allocate in steady state.
func (g *Generator) RenderAs(buf *bytes.Buffer, path string, f Format, host string, port int) int {
	st := g.states.Get().(*renderState)
	defer g.states.Put(st)

	st.path = append(st.path[:0], path...)
	st.cha.Seed([32]byte(st.macSum(nil)))
	r := st.rng
	childDepth := clampDepth(Depth(path) + 1)

	start := buf.Len()
	buf.Grow(maxPageBytes)

	st.title = g.appendTitle(st.title[:0], r)
	paras := minParagraphs + r.IntN(maxParagraphs-minParagraphs+1)
	target := targetMin + r.IntN(targetMax-targetMin+1)

	g.renderLinks(st, r, childDepth, f, host, port)

	switch f {
	case FormatGemini:
		buf.WriteString("# ")
		buf.Write(st.title)
		buf.WriteString("\n\n")
	case FormatGopher:
		gopherInfo(buf, st.title)
		gopherInfo(buf, nil)
	default:
		buf.WriteString(pageHead)
		buf.Write(st.title)
		buf.WriteString(pageHeadEnd)
		buf.Write(st.title)
		buf.WriteString("</h1>\n")
	}
	// Links first: a crawler reading the drip sees where to go next within
	// the lead (sent at once) instead of minutes into the body.
	buf.Write(st.links.Bytes())
	lead := buf.Len() - start

	tail, words := pageTail, wordSet{g.chain.html, g.chain.htmlEnd, g.chain.maxHTML}
	capBytes := maxPageBytes
	switch f {
	case FormatGemini:
		tail, words = "", wordSet{g.chain.plain, g.chain.plainEnd, g.chain.maxPlain}
	case FormatGopher:
		// Info-line framing adds about a fifth to the text.
		tail, words = ".\r\n", wordSet{g.chain.plain, g.chain.plainEnd, g.chain.maxPlain}
		capBytes = maxPageBytes * 3 / 2
	}
	reserved := len(tail)
	textStart := buf.Len()
	textEnd := start + target - reserved
	// limit is the last byte text may reach, leaving room for "</p>\n".
	limit := start + capBytes - reserved - len("</p>\n")
	room := words.max + 8 // one forced word + ". " + "<p>"

	midH2 := -1
	if paras >= 5 && r.IntN(2) == 0 {
		midH2 = paras / 2
	}
	for p := range paras {
		if buf.Len()+room > limit {
			break // size cap wins; unreachable with sane corpora
		}
		if p == midH2 && buf.Len()+64+room < limit {
			h := sectionHeadings[r.IntN(len(sectionHeadings))]
			switch f {
			case FormatGemini:
				buf.WriteString("## ")
				buf.WriteString(h)
				buf.WriteString("\n\n")
			case FormatGopher:
				gopherInfoString(buf, h)
				gopherInfo(buf, nil)
			default:
				buf.WriteString("<h2>")
				buf.WriteString(h)
				buf.WriteString("</h2>\n")
			}
		}
		goal := textStart + (textEnd-textStart)*(p+1)/paras
		if f == FormatHTML {
			buf.WriteString("<p>")
			first := true
			for {
				g.sentence(buf, r, first, limit, words)
				first = false
				if n := buf.Len(); n >= goal || n+room > limit {
					break
				}
			}
			buf.WriteString("</p>\n")
			continue
		}
		// Plain formats: build the paragraph, then frame it.
		base := buf.Len()
		para := &st.para
		para.Reset()
		first := true
		for {
			g.sentence(para, r, first, limit-base, words)
			first = false
			if n := base + para.Len(); n >= goal || n+room > limit {
				break
			}
		}
		if f == FormatGemini {
			if gemtextSpecial(para.Bytes()) {
				buf.WriteByte(' ') // keep it a text line, not a link/heading/list
			}
			buf.Write(para.Bytes())
			buf.WriteString("\n\n")
		} else {
			gopherWrap(buf, para.Bytes())
			gopherInfo(buf, nil)
		}
	}
	buf.WriteString(tail)
	return lead
}

// wordSet is the chain's word table for one output format.
type wordSet struct {
	words, ends []string
	max         int
}

// gopherInfo writes one informational (type i) menu line. Selector, host
// and port are the usual placeholders for lines that lead nowhere.
func gopherInfo(buf *bytes.Buffer, text []byte) {
	buf.WriteByte('i')
	buf.Write(text)
	buf.WriteString("\tfake\t(NULL)\t0\r\n")
}

func gopherInfoString(buf *bytes.Buffer, text string) {
	buf.WriteByte('i')
	buf.WriteString(text)
	buf.WriteString("\tfake\t(NULL)\t0\r\n")
}

// gopherWrap writes text as info lines of at most gopherWidth bytes,
// breaking at spaces.
func gopherWrap(buf *bytes.Buffer, text []byte) {
	for len(text) > 0 {
		cut := len(text)
		if cut > gopherWidth {
			cut = bytes.LastIndexByte(text[:gopherWidth+1], ' ')
			if cut <= 0 {
				cut = gopherWidth
			}
		}
		gopherInfo(buf, text[:cut])
		text = bytes.TrimLeft(text[cut:], " ")
	}
}

// gemtextSpecial reports whether a text line would be read as gemtext
// markup (link, heading, list item, quote or preformat toggle).
func gemtextSpecial(line []byte) bool {
	if len(line) == 0 {
		return false
	}
	switch line[0] {
	case '#', '>':
		return true
	case '=':
		return len(line) > 1 && line[1] == '>'
	case '*':
		return len(line) > 1 && line[1] == ' '
	case '`':
		return bytes.HasPrefix(line, []byte("```"))
	}
	return false
}

// navEnd closes the link block that follows the page heading.
const navEnd = "</nav>\n"

// LeadLen returns how many leading bytes of a rendered page to send at
// once: everything through the link block. 0 if page has none.
func LeadLen(page []byte) int {
	i := bytes.Index(page, []byte(navEnd))
	if i < 0 {
		return 0
	}
	return i + len(navEnd)
}

// sentence writes one Markov sentence using the word table w. The sentence
// is cut short (and closed with a period) if the next word could push past
// limit.
func (g *Generator) sentence(buf *bytes.Buffer, r *rand.Rand, first bool, limit int, w wordSet) {
	c := g.chain
	s := c.starts[r.IntN(len(c.starts))]
	for n := 1; ; n++ {
		word := c.emit[s]
		succ := c.next[c.off[s]:c.off[s+1]]
		done := c.isEnd[word] && n >= minSentenceWords
		force := !done && (n >= maxSentenceWords || len(succ) == 0 || buf.Len()+w.max+4 > limit)
		if force && w.ends[word] == "" {
			buf.WriteByte('.')
			return
		}
		if !first {
			buf.WriteByte(' ')
		}
		first = false
		if force {
			buf.WriteString(w.ends[word])
			buf.WriteByte('.')
			return
		}
		buf.WriteString(w.words[word])
		if done {
			return
		}
		s = succ[r.IntN(len(succ))]
	}
}

func (g *Generator) renderLinks(st *renderState, r *rand.Rand, childDepth int, f Format, host string, port int) {
	lb := &st.links
	lb.Reset()
	heading := linkHeadings[r.IntN(len(linkHeadings))]
	switch f {
	case FormatGemini:
		lb.WriteString("## ")
		lb.WriteString(heading)
		lb.WriteByte('\n')
	case FormatGopher:
		gopherInfoString(lb, heading)
	default:
		lb.WriteString("<nav>\n<h2>")
		lb.WriteString(heading)
		lb.WriteString("</h2>\n<ul>\n")
	}
	n := minLinks + r.IntN(maxLinks-minLinks+1)
	idx := st.idx[:]
	parent := pageID(st) // reuses st.sum; the page seed was consumed in RenderAs
	for i := range n {
		lp, la := &st.lp, &st.la
		lp.Reset()
		lp.WriteString("/lawn/")
		if r.IntN(4) == 0 {
			for range 1 + r.IntN(3) {
				g.writeSegment(lp, st, r)
				lp.WriteByte('/')
			}
		}
		idx[0] = 0
		binary.BigEndian.PutUint16(idx[1:], uint16(i))
		st.tok = appendChildToken(st.tok[:0], childDepth, st.macSum(idx), parent)
		lp.Write(st.tok)
		la.Reset()
		g.writeAnchor(la, st, r)
		switch f {
		case FormatGemini:
			lb.WriteString("=> ")
			lb.Write(lp.Bytes())
			lb.WriteByte(' ')
			lb.Write(la.Bytes())
			lb.WriteByte('\n')
		case FormatGopher:
			lb.WriteByte('1')
			lb.Write(la.Bytes())
			lb.WriteByte('\t')
			lb.Write(lp.Bytes())
			lb.WriteByte('\t')
			lb.WriteString(host)
			lb.WriteByte('\t')
			// st.num is also writeSegment's scratch, so format the port last.
			lb.Write(strconv.AppendInt(st.num[:0], int64(port), 10))
			lb.WriteString("\r\n")
		default:
			lb.WriteString(`<li><a href="`)
			lb.Write(lp.Bytes())
			lb.WriteString(`">`)
			lb.Write(la.Bytes())
			lb.WriteString("</a></li>\n")
		}
	}
	switch f {
	case FormatGemini:
		lb.WriteByte('\n')
	case FormatGopher:
		gopherInfo(lb, nil)
	default:
		lb.WriteString("</ul>\n")
		lb.WriteString(navEnd)
	}
}

func (g *Generator) writeSegment(lb *bytes.Buffer, st *renderState, r *rand.Rand) {
	switch r.IntN(3) {
	case 0:
		lb.Write(strconv.AppendInt(st.num[:0], int64(1900+r.IntN(126)), 10))
	case 1:
		lb.Write(strconv.AppendInt(st.num[:0], int64(1+r.IntN(40)), 10))
	default:
		lb.WriteString(segmentWords[r.IntN(len(segmentWords))])
	}
}

func (g *Generator) noun(r *rand.Rand) string { return g.vocab[r.IntN(len(g.vocab))] }

func appendTitleCase(dst []byte, w string) []byte {
	dst = append(dst, w[0]-('a'-'A'))
	return append(dst, w[1:]...)
}

func (g *Generator) writeAnchor(lb *bytes.Buffer, st *renderState, r *rand.Rand) {
	switch k := r.IntN(10); {
	case k == 0:
		lb.WriteString("Part ")
		lb.WriteString(romans[r.IntN(len(romans))])
		return
	case k == 1:
		lb.WriteString("Notes on the ")
		st.tok = appendTitleCase(st.tok[:0], g.noun(r))
		lb.Write(st.tok)
		return
	case k == 2:
		lb.WriteString("Appendix ")
		lb.WriteString(romans[r.IntN(len(romans))])
		return
	}
	// 1-3 title-cased vocabulary words: "A", "A and B", "A, B and C".
	words := 1 + r.IntN(3)
	for j := range words {
		if j > 0 {
			if j == words-1 {
				lb.WriteString(" and ")
			} else {
				lb.WriteString(", ")
			}
		}
		st.tok = appendTitleCase(st.tok[:0], g.noun(r))
		lb.Write(st.tok)
	}
}

// appendTitle builds a neutral title from generic phrases and corpus
// vocabulary words. Vocabulary words are lowercase-only in the corpus, so
// proper names (people, places, brands) never appear in titles.
func (g *Generator) appendTitle(dst []byte, r *rand.Rand) []byte {
	t := titleTemplates[r.IntN(len(titleTemplates))]
	for _, part := range t {
		switch part {
		case "\x00n":
			dst = appendTitleCase(dst, g.noun(r))
		case "\x00r":
			dst = append(dst, romans[r.IntN(len(romans))]...)
		default:
			dst = append(dst, part...)
		}
	}
	return dst
}

// EntryURLs returns n deterministic depth-0 maze URLs for use as bait in the
// sitemap and on the homepage.
func (g *Generator) EntryURLs(n int) []string {
	st := g.states.Get().(*renderState)
	defer g.states.Put(st)
	out := make([]string, 0, n)
	var idx [4]byte
	for i := range n {
		st.path = append(st.path[:0], "\x00entry"...)
		binary.BigEndian.PutUint32(idx[:], uint32(i))
		tok := appendToken([]byte("/lawn/"), 0, st.macSum(idx[:]))
		out = append(out, string(tok))
	}
	return out
}

var titleTemplates = [][]string{
	{"Notes on the ", "\x00n"},
	{"Collected Papers on ", "\x00n", " and ", "\x00n"},
	{"Appendix ", "\x00r", ": The ", "\x00n"},
	{"On the ", "\x00n", " of the ", "\x00n"},
	{"Remarks Concerning the ", "\x00n"},
	{"A Short Account of the ", "\x00n"},
	{"\x00n", " and ", "\x00n", ": Selected Passages"},
	{"Chapter ", "\x00r", ". The ", "\x00n"},
	{"Further Observations on the ", "\x00n"},
	{"An Index of ", "\x00n", " and ", "\x00n"},
	{"Miscellany: ", "\x00n", ", ", "\x00n", " and ", "\x00n"},
	{"Commonplace Book, Volume ", "\x00r"},
	{"Fragments Concerning the ", "\x00n"},
	{"Marginal Notes, Part ", "\x00r"},
	{"The ", "\x00n", " and Other Essays"},
}

var linkHeadings = []string{
	"Contents", "See also", "Related sections", "Further reading", "Index",
	"Continued in", "Elsewhere in the collection", "Cross-references",
}

var sectionHeadings = []string{
	"Continued", "Remarks", "Notes", "Further remarks", "Commentary", "Marginalia",
}

var segmentWords = []string{
	"archive", "notes", "papers", "collected", "misc", "appendix", "vol", "section",
	"index", "library", "reading", "drafts", "letters", "volumes", "folio",
}

var romans = []string{
	"I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X",
	"XI", "XII", "XIII", "XIV", "XV", "XVI", "XVII", "XVIII", "XIX", "XX",
}

var bufPool = sync.Pool{New: func() any {
	b := new(bytes.Buffer)
	b.Grow(maxPageBytes)
	return b
}}

// maxPooledBuffer is the capacity above which PutBuffer drops a buffer
// instead of pooling it, so one oversized page can't pin memory.
const maxPooledBuffer = 64 << 10

// GetBuffer returns an empty page buffer from the pool.
func GetBuffer() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

// PutBuffer returns b to the pool. Oversized buffers are dropped.
func PutBuffer(b *bytes.Buffer) {
	if b == nil || b.Cap() > maxPooledBuffer {
		return
	}
	b.Reset()
	bufPool.Put(b)
}
