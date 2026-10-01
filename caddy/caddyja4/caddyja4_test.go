package caddyja4

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// A TLS server behind the wrapped listener sees each request's JA4 in the
// header, over HTTP/1.1 and HTTP/2, and never the client's own value.
func TestHandlerOverTLS(t *testing.T) {
	h := Handler{Header: "X-Lawn-Client-JA4"}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		io.WriteString(w, r.Header.Get("X-Lawn-Client-JA4"))
		return nil
	})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// caddyhttp.SetVar needs Caddy's vars map in the context.
		r = r.WithContext(contextWithVars(r))
		if err := h.ServeHTTP(w, r, next); err != nil {
			t.Error(err)
		}
	}))
	srv.Listener = (&Listener{}).WrapListener(srv.Listener)
	srv.Config.ConnContext = connContext
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	for _, h2 := range []bool{false, true} {
		tr := srv.Client().Transport.(*http.Transport).Clone()
		tr.ForceAttemptHTTP2 = h2
		if !h2 {
			tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		c := &http.Client{Transport: tr}
		req, _ := http.NewRequest("GET", srv.URL, nil)
		req.Header.Set("X-Lawn-Client-JA4", "forged")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got := string(b)
		wantALPN := "h1"
		if h2 {
			wantALPN = "h2"
		}
		if resp.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] || !strings.HasPrefix(got, "t13i") || got[8:10] != wantALPN || len(got) != 36 {
			t.Errorf("h2=%v proto=%s JA4=%q", h2, resp.Proto, got)
		}
	}
}

// Without a recorded connection (HTTP/3, plain HTTP) the header is removed.
func TestHandlerNoConn(t *testing.T) {
	h := Handler{Header: "X-JA4"}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-JA4", "forged")
	r = r.WithContext(contextWithVars(r))
	var seen http.Header
	h.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		seen = r.Header
		return nil
	}))
	if _, ok := seen["X-Ja4"]; ok {
		t.Errorf("client header kept: %v", seen)
	}
	if v := caddyhttp.GetVar(r.Context(), "ja4"); v != "" {
		t.Errorf("var = %v", v)
	}
}

func TestFind(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	jc := &Conn{Conn: a}
	if find(tls.Server(jc, &tls.Config{})) != jc || find(jc) != jc || find(b) != nil {
		t.Error("find")
	}
}

func TestCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser("ja4")
	if err := (&Listener{}).UnmarshalCaddyfile(d); err != nil {
		t.Error(err)
	}
	if err := (&Listener{}).UnmarshalCaddyfile(caddyfile.NewTestDispenser("ja4 extra")); err == nil {
		t.Error("argument accepted")
	}
	m, err := parseHandler(httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser("ja4 X-Foo")})
	if err != nil || m.(*Handler).Header != "X-Foo" {
		t.Errorf("%+v %v", m, err)
	}
	if _, err := parseHandler(httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser("ja4 a b")}); err == nil {
		t.Error("two arguments accepted")
	}
}

func contextWithVars(r *http.Request) context.Context {
	return context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
}
