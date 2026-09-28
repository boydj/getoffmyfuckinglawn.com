// Package maze generates the deterministic, infinite tarpit pages served
// under /lawn/: an order-2 word Markov chain for body text, an HMAC-seeded
// page renderer, and the token/URL scheme that encodes crawl depth.
package maze

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// maxWordLen drops pathological tokens (long dash-joined runs, URLs) at
// training time so a single word can never blow the page-size budget.
const maxWordLen = 30

// Chain is an order-2 word Markov chain.
//
// It is stored index-based so generation never hashes strings: every state
// is a (w1, w2) word pair, and each state's successors are stored as state
// ids in a CSR layout (off/next). Walking the chain is pure slice indexing.
type Chain struct {
	html    []string // word id -> HTML-escaped word
	htmlEnd []string // word id -> escaped word with trailing , ; : - trimmed ("" if nothing left)
	isEnd   []bool   // word id -> word ends a sentence
	maxHTML int      // longest entry in html

	plain    []string // word id -> the word as is (gemtext, gophermap)
	plainEnd []string // plain word with trailing , ; : - trimmed
	maxPlain int      // longest entry in plain

	emit   []int32 // state id -> word emitted when entering the state (w2)
	off    []int32 // state id -> start index into next; len = states+1
	next   []int32 // successor state ids
	starts []int32 // states that begin a sentence

	vocab []string // lowercase [a-z]+ content words for titles/anchors
}

// LoadCorpus trains a chain on every *.txt file in dir. Lines of the form
// "[Title by Author Year]" (the corpus file headers) are skipped.
func LoadCorpus(dir string) (*Chain, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, fmt.Errorf("maze: corpus glob: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("maze: no *.txt files in corpus dir %q", dir)
	}
	sort.Strings(files)
	texts := make([]string, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("maze: corpus: %w", err)
		}
		texts = append(texts, string(b))
	}
	c := NewChain(texts...)
	if len(c.emit) == 0 {
		return nil, fmt.Errorf("maze: corpus dir %q produced an empty chain", dir)
	}
	return c, nil
}

// NewChain trains a chain on raw texts. Each text is treated as one
// continuous word stream; texts are not joined to each other.
func NewChain(texts ...string) *Chain {
	b := &builder{
		ids:    make(map[string]int32),
		states: make(map[uint64]int32),
		freq:   nil,
	}
	for _, t := range texts {
		b.addText(t)
	}
	return b.build()
}

type builder struct {
	words   []string
	ids     map[string]int32
	freq    []int32
	nounish []int32 // times the word followed a determiner
	states  map[uint64]int32
	emit    []int32
	first   []int32 // state id -> first word (w1)
	edges   []edge
}

type edge struct{ from, to int32 }

func (b *builder) word(w string) int32 {
	if id, ok := b.ids[w]; ok {
		b.freq[id]++
		return id
	}
	id := int32(len(b.words))
	b.ids[w] = id
	b.words = append(b.words, w)
	b.freq = append(b.freq, 1)
	b.nounish = append(b.nounish, 0)
	return id
}

func (b *builder) state(w1, w2 int32) int32 {
	k := uint64(uint32(w1))<<32 | uint64(uint32(w2))
	if id, ok := b.states[k]; ok {
		return id
	}
	id := int32(len(b.emit))
	b.states[k] = id
	b.emit = append(b.emit, w2)
	b.first = append(b.first, w1)
	return id
}

func (b *builder) addText(text string) {
	var seq []int32
	prevDet := false
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if skipLine(line) {
			continue
		}
		line = strings.ReplaceAll(line, "--", " ")
		for _, f := range strings.Fields(line) {
			w := cleanWord(f)
			if w == "" || len(w) > maxWordLen {
				continue
			}
			id := b.word(w)
			if prevDet {
				b.nounish[id]++
			}
			prevDet = determiners[w]
			seq = append(seq, id)
		}
	}
	if len(seq) < 3 {
		return
	}
	prev := b.state(seq[0], seq[1])
	for i := 2; i < len(seq); i++ {
		cur := b.state(seq[i-1], seq[i])
		b.edges = append(b.edges, edge{prev, cur})
		prev = cur
	}
}

// skipLine reports lines that are not prose: corpus headers like
// "[Title by Author 1865]", chapter headings and all-caps headings.
func skipLine(line string) bool {
	if line == "" {
		return true
	}
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return true
	}
	if len(line) >= 8 && strings.EqualFold(line[:8], "chapter ") {
		return true
	}
	letters, upper := 0, 0
	for _, r := range line {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	return letters == 0 || (letters >= 2 && upper == letters)
}

// cleanWord strips Gutenberg markup (_italics_), quotes and brackets from
// the ends of a whitespace-separated token.
func cleanWord(f string) string {
	if strings.ContainsAny(f, "_*") {
		f = strings.NewReplacer("_", "", "*", "").Replace(f)
	}
	const edge = "\"'`()[]{}“”‘’"
	for {
		t := strings.Trim(f, edge)
		// A trailing quote may hide behind punctuation: "book,'" -> "book,".
		if n := len(t); n > 1 && strings.ContainsRune(".,;:!?", rune(t[n-1])) {
			if u := strings.TrimRight(t[:n-1], edge); len(u) != n-1 {
				t = u + t[n-1:]
			}
		}
		if t == f {
			return f
		}
		f = t
	}
}

var abbreviations = map[string]bool{
	"Mr.": true, "Mrs.": true, "Dr.": true, "St.": true, "Esq.": true, "Mme.": true,
	"Messrs.": true, "Col.": true, "Capt.": true, "Rev.": true, "No.": true,
}

func endsSentence(w string) bool {
	if w == "" || abbreviations[w] {
		return false
	}
	switch w[len(w)-1] {
	case '.', '!', '?':
		return len(w) > 1
	}
	return false
}

func startsUpper(w string) bool {
	return w != "" && w[0] >= 'A' && w[0] <= 'Z'
}

// titleStop are common words that make poor title/anchor nouns.
var titleStop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`about above after again against among another around because
	been before being below between both cannot could didn does doing down during each either else
	every everything from further great have having here herself himself itself just little might
	more most much must myself never nothing often only other ought ourselves over quite rather
	really same shall should some something still such than that their theirs them themselves then
	there these they thing things think this those though thought through thus till together under
	until upon very were what whatever when where whether which while whom whose will with within
	without would yourself yourselves always almost already also although anything come came could
	going gone know knew make made means perhaps said says seemed seems shall since soon sure take
	taken tell told therefore toward towards want wanted well went whole again another enough indeed
	while however instead being certainly nobody everybody somebody anybody become became looked
	looking asked replied answered began began round across along behind beside beyond`) {
		titleStop[w] = true
	}
}

// determiners mark the following word as probably a noun (or adjective),
// which makes for more plausible titles than arbitrary verbs.
var determiners = map[string]bool{
	"the": true, "a": true, "an": true, "his": true, "her": true, "their": true,
	"my": true, "its": true, "our": true, "this": true, "that": true, "The": true,
}

func isVocab(w string) bool {
	if len(w) < 5 || len(w) > 12 || titleStop[w] || strings.HasSuffix(w, "ly") {
		return false
	}
	for i := 0; i < len(w); i++ {
		if w[i] < 'a' || w[i] > 'z' {
			return false
		}
	}
	return true
}

func (b *builder) build() *Chain {
	c := &Chain{
		html:     make([]string, len(b.words)),
		htmlEnd:  make([]string, len(b.words)),
		plain:    make([]string, len(b.words)),
		plainEnd: make([]string, len(b.words)),
		isEnd:    make([]bool, len(b.words)),
		emit:     b.emit,
	}
	for i, w := range b.words {
		c.html[i] = html.EscapeString(w)
		c.htmlEnd[i] = html.EscapeString(strings.TrimRight(w, ",;:-—"))
		c.isEnd[i] = endsSentence(w)
		c.maxHTML = max(c.maxHTML, len(c.html[i]))
		c.plain[i] = w
		c.plainEnd[i] = strings.TrimRight(w, ",;:-—")
		c.maxPlain = max(c.maxPlain, len(w))
		if b.nounish[i] >= 2 && isVocab(w) {
			c.vocab = append(c.vocab, w)
		}
	}
	// CSR: count, prefix-sum, fill.
	n := len(b.emit)
	c.off = make([]int32, n+1)
	for _, e := range b.edges {
		c.off[e.from+1]++
	}
	for i := 1; i <= n; i++ {
		c.off[i] += c.off[i-1]
	}
	c.next = make([]int32, len(b.edges))
	fill := make([]int32, n)
	for _, e := range b.edges {
		c.next[c.off[e.from]+fill[e.from]] = e.to
		fill[e.from]++
	}
	for s := range n {
		if c.isEnd[b.first[s]] && startsUpper(b.words[b.emit[s]]) {
			c.starts = append(c.starts, int32(s))
		}
	}
	if len(c.starts) == 0 {
		for s := range n {
			c.starts = append(c.starts, int32(s))
		}
	}
	return c
}

// fallbackText trains the chain used when a Generator is given an empty
// chain, so Render always has something neutral to say.
const fallbackText = `The garden was quiet in the morning. The path ran along the old wall
and past the pond. Nobody had written anything in the ledger for a long while. The
letters were kept in a box beneath the window. The weather turned in the afternoon and
the lamps were lit early. The river was high after the rain. A careful reader will find
the index at the back of the volume. The notes continue on the following page.`

var fallbackVocab = []string{
	"garden", "letter", "river", "window", "morning", "ledger", "lantern", "meadow",
	"harbour", "orchard", "archive", "volume", "passage", "weather", "journey", "country",
}
