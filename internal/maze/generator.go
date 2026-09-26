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
		return st
	}
	return g
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
<meta name="robots" content="noindex,nofollow">
<title>`

const pageHeadEnd = `</title>
<style>body{max-width:40em;margin:2em auto;padding:0 1em;font:1.05em/1.6 Georgia,serif;color:#222;background:#fbfaf6}h1,h2{font-weight:normal}a{color:#335}@media(prefers-color-scheme:dark){body{color:#ddd;background:#1b1b1b}a{color:#9ab}}</style>
</head>
<body>
<h1>`

const pageTail = "</body>\n</html>\n"

// Render writes the full HTML page for path into buf. The output depends
// only on the secret, the chain and path: the same path always yields a
// byte-identical page. Content is appended; buf is not reset.
func (g *Generator) Render(buf *bytes.Buffer, path string) {
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

	g.renderLinks(st, r, childDepth)

	buf.WriteString(pageHead)
	buf.Write(st.title)
	buf.WriteString(pageHeadEnd)
	buf.Write(st.title)
	buf.WriteString("</h1>\n")

	reserved := st.links.Len() + len(pageTail)
	textStart := buf.Len()
	textEnd := start + target - reserved
	// limit is the last byte text may reach, leaving room for "</p>\n".
	limit := start + maxPageBytes - reserved - len("</p>\n")
	c := g.chain
	room := c.maxHTML + 8 // one forced word + ". " + "<p>"

	midH2 := -1
	if paras >= 5 && r.IntN(2) == 0 {
		midH2 = paras / 2
	}
	for p := range paras {
		if buf.Len()+room > limit {
			break // size cap wins; unreachable with sane corpora
		}
		if p == midH2 && buf.Len()+64+room < limit {
			buf.WriteString("<h2>")
			buf.WriteString(sectionHeadings[r.IntN(len(sectionHeadings))])
			buf.WriteString("</h2>\n")
		}
		goal := textStart + (textEnd-textStart)*(p+1)/paras
		buf.WriteString("<p>")
		first := true
		for {
			g.sentence(buf, r, first, limit)
			first = false
			if n := buf.Len(); n >= goal || n+room > limit {
				break
			}
		}
		buf.WriteString("</p>\n")
	}
	buf.Write(st.links.Bytes())
	buf.WriteString(pageTail)
}

// sentence writes one Markov sentence. The sentence is cut short (and
// closed with a period) if the next word could push past limit.
func (g *Generator) sentence(buf *bytes.Buffer, r *rand.Rand, first bool, limit int) {
	c := g.chain
	s := c.starts[r.IntN(len(c.starts))]
	for n := 1; ; n++ {
		w := c.emit[s]
		succ := c.next[c.off[s]:c.off[s+1]]
		done := c.isEnd[w] && n >= minSentenceWords
		force := !done && (n >= maxSentenceWords || len(succ) == 0 || buf.Len()+c.maxHTML+4 > limit)
		if force && c.htmlEnd[w] == "" {
			buf.WriteByte('.')
			return
		}
		if !first {
			buf.WriteByte(' ')
		}
		first = false
		if force {
			buf.WriteString(c.htmlEnd[w])
			buf.WriteByte('.')
			return
		}
		buf.WriteString(c.html[w])
		if done {
			return
		}
		s = succ[r.IntN(len(succ))]
	}
}

func (g *Generator) renderLinks(st *renderState, r *rand.Rand, childDepth int) {
	lb := &st.links
	lb.Reset()
	lb.WriteString("<h2>")
	lb.WriteString(linkHeadings[r.IntN(len(linkHeadings))])
	lb.WriteString("</h2>\n<ul>\n")
	n := minLinks + r.IntN(maxLinks-minLinks+1)
	idx := st.idx[:]
	for i := range n {
		lb.WriteString(`<li><a href="/lawn/`)
		if r.IntN(4) == 0 {
			for range 1 + r.IntN(3) {
				g.writeSegment(lb, st, r)
				lb.WriteByte('/')
			}
		}
		idx[0] = 0
		binary.BigEndian.PutUint16(idx[1:], uint16(i))
		st.tok = appendToken(st.tok[:0], childDepth, st.macSum(idx))
		lb.Write(st.tok)
		lb.WriteString(`">`)
		g.writeAnchor(lb, st, r)
		lb.WriteString("</a></li>\n")
	}
	lb.WriteString("</ul>\n")
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
