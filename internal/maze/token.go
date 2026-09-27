package maze

import (
	"encoding/base32"
	"encoding/binary"
	"strings"
)

const (
	// tokenMACLen is how many HMAC bytes a token carries after the depth.
	tokenMACLen = 10
	// MaxDepth is the depth at which child depth stops increasing.
	MaxDepth = 1 << 20
	// tokenParentLen is the parent page ID appended to child tokens, so a
	// request says which page's link it followed. Entry tokens (and child
	// tokens issued before this existed) have none.
	tokenParentLen = 4
	// maxTokenRaw is the largest raw token: 3-byte varint (MaxDepth) + MAC
	// + parent ID.
	maxTokenRaw = 3 + tokenMACLen + tokenParentLen
	// maxTokenLen is the base32 length of the largest raw token.
	maxTokenLen = (maxTokenRaw*8 + 4) / 5
)

const b32alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var b32 = base32.NewEncoding(b32alphabet).WithPadding(base32.NoPadding)

var b32dec = func() (t [256]byte) {
	for i := range t {
		t[i] = 0xff
	}
	for i := 0; i < len(b32alphabet); i++ {
		t[b32alphabet[i]] = byte(i)
		if c := b32alphabet[i]; c >= 'a' && c <= 'z' {
			t[c-'a'+'A'] = byte(i)
		}
	}
	return t
}()

// appendToken appends the base32 token for (depth, mac) to dst without
// allocating when dst has room. Used for entry (bait) tokens.
func appendToken(dst []byte, depth int, mac []byte) []byte {
	return appendTokenRaw(dst, depth, mac, 0, false)
}

// appendChildToken appends a child-link token that also carries the
// parent page's ID.
func appendChildToken(dst []byte, depth int, mac []byte, parent uint32) []byte {
	return appendTokenRaw(dst, depth, mac, parent, true)
}

func appendTokenRaw(dst []byte, depth int, mac []byte, parent uint32, withParent bool) []byte {
	var raw [maxTokenRaw]byte
	n := binary.PutUvarint(raw[:], uint64(clampDepth(depth)))
	n += copy(raw[n:], mac[:tokenMACLen])
	if withParent {
		binary.BigEndian.PutUint32(raw[n:], parent)
		n += tokenParentLen
	}
	var enc [maxTokenLen]byte
	m := b32.EncodedLen(n)
	b32.Encode(enc[:m], raw[:n])
	return append(dst, enc[:m]...)
}

func clampDepth(d int) int {
	if d < 0 {
		return 0
	}
	if d > MaxDepth {
		return MaxDepth
	}
	return d
}

// decodeToken returns the depth encoded in tok. ok is false if tok is not a
// well-formed token. It does not (and cannot) verify the MAC: that is keyed
// on the parent path, which the child URL does not carry.
func decodeToken(tok string) (depth int, ok bool) {
	depth, _, _, ok = decodeTokenFull(tok)
	return depth, ok
}

// decodeTokenFull also returns the parent page ID carried by child tokens
// (hasParent false for entry tokens and pre-parent child tokens).
func decodeTokenFull(tok string) (depth int, parent uint32, hasParent, ok bool) {
	if len(tok) == 0 || len(tok) > maxTokenLen {
		return 0, 0, false, false
	}
	var raw [maxTokenRaw + 1]byte
	var acc uint32
	bits, n := 0, 0
	for i := 0; i < len(tok); i++ {
		v := b32dec[tok[i]]
		if v == 0xff {
			return 0, 0, false, false
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if n >= len(raw) {
				return 0, 0, false, false
			}
			raw[n] = byte(acc >> bits)
			n++
		}
	}
	if b32.EncodedLen(n) != len(tok) {
		return 0, 0, false, false
	}
	d, vn := binary.Uvarint(raw[:n])
	if vn <= 0 || d > MaxDepth {
		return 0, 0, false, false
	}
	switch n {
	case vn + tokenMACLen:
		return int(d), 0, false, true
	case vn + tokenMACLen + tokenParentLen:
		return int(d), binary.BigEndian.Uint32(raw[vn+tokenMACLen : n]), true, true
	}
	return 0, 0, false, false
}

// lastSegment returns the final non-empty segment of a maze path, or "" for
// the maze root.
func lastSegment(path string) string {
	p := strings.TrimRight(path, "/")
	seg := p[strings.LastIndexByte(p, '/')+1:]
	if seg == "lawn" {
		return ""
	}
	return seg
}

// ParentID returns the page ID of the page whose link led to path, if the
// URL carries one (child links issued since parent tracking was added).
func ParentID(path string) (uint32, bool) {
	if !IsMazePath(path) {
		return 0, false
	}
	_, parent, has, ok := decodeTokenFull(lastSegment(path))
	return parent, ok && has
}

// IsMazePath reports whether path is inside the maze: "/lawn" or "/lawn/...".
func IsMazePath(path string) bool {
	return path == "/lawn" || strings.HasPrefix(path, "/lawn/")
}

// Depth returns the crawl depth encoded in a maze path. Entry pages
// ("/lawn", "/lawn/", "/lawn/<entry-token>") are depth 0, as is anything
// that is not a maze path or whose last segment is not a valid token.
// Depth is recovered from the last non-empty path segment; fake segments
// such as "/archive/2019/" in front of it are ignored.
func Depth(path string) int {
	if !IsMazePath(path) {
		return 0
	}
	seg := lastSegment(path)
	if seg == "" {
		return 0
	}
	d, _ := decodeToken(seg)
	return d
}
