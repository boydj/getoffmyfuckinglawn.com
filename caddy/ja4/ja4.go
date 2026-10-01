// Package ja4 computes the JA4 fingerprint of a TLS ClientHello.
//
// JA4 is FoxIO's TLS client fingerprint, specified at
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md and
// licensed BSD 3-Clause (see LICENSE-JA4 in this directory). This is an
// independent implementation of that specification for TLS over TCP. The
// rest of JA4+ (JA4H, JA4S, ...) is under a different license and is not
// implemented here.
//
// A Recorder is fed the raw bytes from the start of a connection and
// produces the fingerprint once the ClientHello is complete.
package ja4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// Extension and record numbers used by the fingerprint.
const (
	extSNI               = 0x0000
	extALPN              = 0x0010
	extSignatureAlgs     = 0x000d
	extSupportedVersions = 0x002b

	recordHandshake   = 22
	handshakeHello    = 1
	maxHandshakeBytes = 64 << 10 // a real ClientHello is a few KB
)

// ErrNotClientHello is returned for a stream that does not start with a TLS
// ClientHello.
var ErrNotClientHello = errors.New("ja4: not a TLS ClientHello")

// Hello is the part of a ClientHello that JA4 uses. GREASE values are
// already removed.
type Hello struct {
	Version           uint16   // legacy_version
	Ciphers           []uint16 // in order
	Extensions        []uint16 // in order
	ALPN              []byte   // first ALPN protocol; nil if none
	SupportedVersions []uint16
	SignatureAlgs     []uint16 // in order
}

// isGREASE reports whether v is one of the reserved GREASE values
// (0x0a0a, 0x1a1a, ... 0xfafa), RFC 8701.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// ParseClientHello parses a ClientHello handshake message (starting with
// the handshake type byte, without the TLS record header).
func ParseClientHello(msg []byte) (*Hello, error) {
	r := reader(msg)
	typ, ok1 := r.u8()
	n, ok2 := r.u24()
	if !ok1 || !ok2 || typ != handshakeHello || int(n) != len(r) {
		return nil, ErrNotClientHello
	}
	h := &Hello{}
	var ok bool
	if h.Version, ok = r.u16(); !ok {
		return nil, ErrNotClientHello
	}
	if !r.skip(32) { // random
		return nil, ErrNotClientHello
	}
	if _, ok = r.vec8(); !ok { // session id
		return nil, ErrNotClientHello
	}
	cs, ok := r.vec16()
	if !ok || len(cs)%2 != 0 {
		return nil, ErrNotClientHello
	}
	for c := cs; len(c) >= 2; c = c[2:] {
		if v := binary.BigEndian.Uint16(c); !isGREASE(v) {
			h.Ciphers = append(h.Ciphers, v)
		}
	}
	if _, ok = r.vec8(); !ok { // compression methods
		return nil, ErrNotClientHello
	}
	if len(r) == 0 {
		return h, nil // no extensions (very old clients)
	}
	exts, ok := r.vec16()
	if !ok {
		return nil, ErrNotClientHello
	}
	for len(exts) > 0 {
		typ, ok1 := exts.u16()
		data, ok2 := exts.vec16()
		if !ok1 || !ok2 {
			return nil, ErrNotClientHello
		}
		if isGREASE(typ) {
			continue
		}
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case extALPN:
			// protocol_name_list: u16 length, then u8-prefixed names.
			if list, ok := data.vec16(); ok {
				if p, ok := list.vec8(); ok {
					h.ALPN = append([]byte{}, p...)
				}
			}
		case extSupportedVersions:
			if list, ok := data.vec8(); ok {
				for ; len(list) >= 2; list = list[2:] {
					if v := binary.BigEndian.Uint16(list); !isGREASE(v) {
						h.SupportedVersions = append(h.SupportedVersions, v)
					}
				}
			}
		case extSignatureAlgs:
			if list, ok := data.vec16(); ok {
				for ; len(list) >= 2; list = list[2:] {
					if v := binary.BigEndian.Uint16(list); !isGREASE(v) {
						h.SignatureAlgs = append(h.SignatureAlgs, v)
					}
				}
			}
		}
	}
	return h, nil
}

// Fingerprint returns h's JA4 for a connection over transport t ('t' for
// TCP, 'q' for QUIC).
func (h *Hello) Fingerprint(t byte) string {
	var b strings.Builder
	b.Grow(36)
	b.WriteByte(t)
	b.WriteString(h.version())
	if slices.Contains(h.Extensions, extSNI) {
		b.WriteByte('d')
	} else {
		b.WriteByte('i')
	}
	b.WriteString(count(len(h.Ciphers)))
	b.WriteString(count(len(h.Extensions)))
	b.WriteString(alpn(h.ALPN))
	b.WriteByte('_')

	ciphers := slices.Clone(h.Ciphers)
	slices.Sort(ciphers)
	b.WriteString(hash12(hexList(ciphers), len(ciphers) == 0))
	b.WriteByte('_')

	exts := make([]uint16, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		if e != extSNI && e != extALPN {
			exts = append(exts, e)
		}
	}
	slices.Sort(exts)
	s := hexList(exts)
	if len(h.SignatureAlgs) > 0 {
		s += "_" + hexList(h.SignatureAlgs)
	}
	b.WriteString(hash12(s, len(exts) == 0))
	return b.String()
}

// version is the JA4 version field: the highest supported_versions entry,
// or the legacy version when that extension is absent.
func (h *Hello) version() string {
	v := h.Version
	if len(h.SupportedVersions) > 0 {
		v = slices.Max(h.SupportedVersions)
	}
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func count(n int) string {
	n = min(n, 99)
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// alpn is the first and last character of the first ALPN value, or of its
// hex form when either byte is not ASCII alphanumeric; "00" when absent.
func alpn(p []byte) string {
	if len(p) == 0 {
		return "00"
	}
	first, last := p[0], p[len(p)-1]
	if alnum(first) && alnum(last) {
		return string([]byte{first, last})
	}
	x := hex.EncodeToString(p)
	return string([]byte{x[0], x[len(x)-1]})
}

func alnum(c byte) bool {
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

func hexList(vs []uint16) string {
	var b strings.Builder
	b.Grow(len(vs) * 5)
	var buf [2]byte
	for i, v := range vs {
		if i > 0 {
			b.WriteByte(',')
		}
		binary.BigEndian.PutUint16(buf[:], v)
		b.WriteString(hex.EncodeToString(buf[:]))
	}
	return b.String()
}

func hash12(s string, empty bool) string {
	if empty {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// reader is a byte slice consumed from the front.
type reader []byte

func (r *reader) u8() (uint8, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(*r)
	*r = (*r)[2:]
	return v, true
}

func (r *reader) u24() (uint32, bool) {
	if len(*r) < 3 {
		return 0, false
	}
	v := uint32((*r)[0])<<16 | uint32((*r)[1])<<8 | uint32((*r)[2])
	*r = (*r)[3:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) take(n int) (reader, bool) {
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) vec8() (reader, bool) {
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

func (r *reader) vec16() (reader, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

// Recorder reassembles the ClientHello from the first bytes a client sends
// on a TCP connection (TLS records, possibly fragmented). Feed it every
// chunk read from the connection until Done.
type Recorder struct {
	buf  []byte // raw bytes seen so far
	done bool
	fp   string
	err  error
}

// Write adds bytes read from the connection. It never fails; once the
// ClientHello is complete, or the stream is clearly not one, further
// writes are ignored.
func (rc *Recorder) Write(p []byte) (int, error) {
	if rc.done {
		return len(p), nil
	}
	rc.buf = append(rc.buf, p...)
	msg, more, err := handshakeMessage(rc.buf)
	switch {
	case err != nil:
		rc.finish("", err)
	case !more:
		h, err := ParseClientHello(msg)
		if err != nil {
			rc.finish("", err)
		} else {
			rc.finish(h.Fingerprint('t'), nil)
		}
	case len(rc.buf) > maxHandshakeBytes+1024:
		rc.finish("", ErrNotClientHello)
	}
	return len(p), nil
}

func (rc *Recorder) finish(fp string, err error) {
	rc.done, rc.fp, rc.err, rc.buf = true, fp, err, nil
}

// Done reports whether the recorder has seen enough bytes.
func (rc *Recorder) Done() bool { return rc.done }

// Result is the fingerprint, or the reason there is none.
func (rc *Recorder) Result() (string, error) { return rc.fp, rc.err }

// handshakeMessage joins the payloads of the leading handshake records in
// stream and returns the first handshake message once it is complete.
// more is true while bytes are missing.
func handshakeMessage(stream []byte) (msg []byte, more bool, err error) {
	var payload []byte
	for r := reader(stream); ; {
		if len(r) < 5 {
			break
		}
		if r[0] != recordHandshake || r[1] != 3 {
			return nil, false, ErrNotClientHello
		}
		n := int(binary.BigEndian.Uint16(r[3:5]))
		if len(r) < 5+n {
			break
		}
		payload = append(payload, r[5:5+n]...)
		r = r[5+n:]
	}
	if len(stream) > 0 && stream[0] != recordHandshake || len(stream) > 1 && stream[1] != 3 {
		return nil, false, ErrNotClientHello
	}
	if len(payload) < 4 {
		return nil, true, nil
	}
	if payload[0] != handshakeHello {
		return nil, false, ErrNotClientHello
	}
	n := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n > maxHandshakeBytes {
		return nil, false, ErrNotClientHello
	}
	if len(payload) < 4+n {
		return nil, true, nil
	}
	return payload[:4+n], false, nil
}
