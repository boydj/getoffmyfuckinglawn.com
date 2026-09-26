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
	// maxTokenRaw is the largest raw token: 3-byte varint (MaxDepth) + MAC.
	maxTokenRaw = 3 + tokenMACLen
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
// allocating when dst has room.
func appendToken(dst []byte, depth int, mac []byte) []byte {
	var raw [maxTokenRaw]byte
	n := binary.PutUvarint(raw[:], uint64(clampDepth(depth)))
	n += copy(raw[n:], mac[:tokenMACLen])
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
	if len(tok) == 0 || len(tok) > maxTokenLen {
		return 0, false
	}
	var raw [maxTokenRaw + 1]byte
	var acc uint32
	bits, n := 0, 0
	for i := 0; i < len(tok); i++ {
		v := b32dec[tok[i]]
		if v == 0xff {
			return 0, false
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			if n >= len(raw) {
				return 0, false
			}
			raw[n] = byte(acc >> bits)
			n++
		}
	}
	if b32.EncodedLen(n) != len(tok) {
		return 0, false
	}
	d, vn := binary.Uvarint(raw[:n])
	if vn <= 0 || n != vn+tokenMACLen || d > MaxDepth {
		return 0, false
	}
	return int(d), true
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
	p := strings.TrimRight(path, "/")
	seg := p[strings.LastIndexByte(p, '/')+1:]
	if seg == "lawn" {
		return 0
	}
	d, _ := decodeToken(seg)
	return d
}
