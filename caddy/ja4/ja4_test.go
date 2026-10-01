package ja4

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ext is one extension for buildHello.
type ext struct {
	typ  uint16
	data []byte
}

func u16s(vs ...uint16) []byte {
	b := make([]byte, 2*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func vec16(b []byte) []byte { return append(u16s(uint16(len(b))), b...) }
func vec8(b []byte) []byte  { return append([]byte{byte(len(b))}, b...) }

func buildHello(version uint16, ciphers []uint16, exts []ext) []byte {
	var body []byte
	body = append(body, u16s(version)...)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, vec8(make([]byte, 32))...)
	body = append(body, vec16(u16s(ciphers...))...)
	body = append(body, vec8([]byte{0})...)
	if exts != nil { // nil: no extensions block at all
		var e []byte
		for _, x := range exts {
			e = append(e, u16s(x.typ)...)
			e = append(e, vec16(x.data)...)
		}
		body = append(body, vec16(e)...)
	}
	msg := append([]byte{handshakeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return msg
}

func record(payload []byte) []byte {
	return append([]byte{recordHandshake, 3, 1, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func alpnExt(protos ...string) []byte {
	var l []byte
	for _, p := range protos {
		l = append(l, vec8([]byte(p))...)
	}
	return vec16(l)
}

// specHello is the example from the JA4 specification (technical_details/
// JA4.md), with GREASE values sprinkled in that must be ignored.
func specHello(sigalgs bool) []byte {
	ciphers := []uint16{0x2a2a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	order := []uint16{0x0a0a, 0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015, 0xfafa}
	var exts []ext
	for _, t := range order {
		var d []byte
		switch t {
		case 0x0000:
			d = vec16(append([]byte{0}, vec16([]byte("example.com"))...))
		case 0x0010:
			d = alpnExt("h2", "http/1.1")
		case 0x002b:
			d = vec8(u16s(0x3a3a, 0x0304, 0x0303))
		case 0x000d:
			d = vec16(nil)
			if sigalgs {
				d = vec16(u16s(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))
			}
		}
		exts = append(exts, ext{t, d})
	}
	return buildHello(0x0303, ciphers, exts)
}

func TestSpecExample(t *testing.T) {
	h, err := ParseClientHello(specHello(true))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.Fingerprint('t'), "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Errorf("JA4 = %s, want %s", got, want)
	}
	// With no signature algorithms the extension list is hashed alone
	// (the spec's "6d807ffa2a79").
	h, err = ParseClientHello(specHello(false))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.Fingerprint('t'), "t13d1516h2_8daaf6152771_6d807ffa2a79"; got != want {
		t.Errorf("JA4 without sigalgs = %s, want %s", got, want)
	}
}

func TestALPNField(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "00",
		"h2":               "h2",
		"http/1.1":         "h1",
		"x":                "xx",
		"\xab":             "ab",
		"\x20":             "20",
		"\xab\xcd":         "ad",
		"\x20\x61":         "21",
		"\x30\xab":         "3b",
		"\x61\x20":         "60",
		"\x30\x31\xab\xcd": "3d",
		"\x30\xab\xcd\x31": "01",
	} {
		if got := alpn([]byte(in)); got != want {
			t.Errorf("alpn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	// No extensions at all: TLS version from the legacy field, no SNI, no
	// ALPN, empty extension hash.
	h, err := ParseClientHello(buildHello(0x0301, []uint16{0x002f}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.Fingerprint('t'), "t10i010000_"+hash12("002f", false)+"_000000000000"; got != want {
		t.Errorf("got %s want %s", got, want)
	}
	if got := (&Hello{Version: 0x9999}).Fingerprint('q'); !strings.HasPrefix(got, "q00i0000") || !strings.HasSuffix(got, "_000000000000_000000000000") {
		t.Errorf("empty hello: %s", got)
	}
	if count(150) != "99" || count(7) != "07" {
		t.Error("count")
	}
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%04x is GREASE", v)
		}
	}
	if isGREASE(0x0a1a) || isGREASE(0x1301) {
		t.Error("false GREASE")
	}
	for _, bad := range [][]byte{nil, {1}, {2, 0, 0, 0}, {1, 0, 0, 9, 3, 3}} {
		if _, err := ParseClientHello(bad); !errors.Is(err, ErrNotClientHello) {
			t.Errorf("%x: %v", bad, err)
		}
	}
}

// The Recorder copes with records split across reads and across TLS
// records, and gives up on anything that is not TLS.
func TestRecorder(t *testing.T) {
	msg := specHello(true)
	want := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	streams := map[string][]byte{
		"one record":  record(msg),
		"two records": append(record(msg[:40]), record(msg[40:])...),
	}
	for name, s := range streams {
		var rc Recorder
		for i := range s { // one byte at a time
			if rc.Done() {
				t.Fatalf("%s: done after %d of %d bytes", name, i, len(s))
			}
			rc.Write(s[i : i+1])
		}
		fp, err := rc.Result()
		if !rc.Done() || err != nil || fp != want {
			t.Errorf("%s: %q %v", name, fp, err)
		}
		rc.Write([]byte("more bytes are ignored"))
		if fp2, _ := rc.Result(); fp2 != fp {
			t.Errorf("%s: changed after done", name)
		}
	}
	for _, s := range []string{"GET / HTTP/1.1\r\n", "\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00", "\x16\x02\x00"} {
		var rc Recorder
		rc.Write([]byte(s))
		if _, err := rc.Result(); !rc.Done() || err == nil {
			t.Errorf("%q: done=%v err=%v", s, rc.Done(), err)
		}
	}
	// A hello claiming more than the limit is refused without buffering it.
	var rc Recorder
	rc.Write(record([]byte{1, 0x10, 0, 0}))
	if !rc.Done() {
		t.Error("oversized hello accepted")
	}
}

// A real crypto/tls client produces a fingerprint consistent with what it
// offered.
func TestGoClient(t *testing.T) {
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		cl := tls.Client(c, &tls.Config{ServerName: "lawn.example", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
		cl.SetDeadline(time.Now().Add(2 * time.Second))
		cl.Handshake() // fails once the server side closes
		c.Close()
	}()
	var rc Recorder
	buf := make([]byte, 512)
	s.SetDeadline(time.Now().Add(2 * time.Second))
	for !rc.Done() {
		n, err := s.Read(buf)
		rc.Write(buf[:n])
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
	}
	fp, err := rc.Result()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(fp, "t13d") || fp[8:10] != "h2" || len(fp) != 36 {
		t.Errorf("Go client JA4 %q", fp)
	}
	if bytes.Count([]byte(fp), []byte("_")) != 2 {
		t.Errorf("format: %q", fp)
	}
}
