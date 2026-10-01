// Package caddyja4 adds JA4 TLS client fingerprints to Caddy.
//
// Two modules work together:
//
//   - caddy.listeners.ja4 wraps the TCP listener *before* TLS and records
//     each connection's ClientHello as it is read by the handshake;
//   - http.handlers.ja4 copies that connection's fingerprint into a request
//     header (removing any client-supplied value) and into the
//     {http.vars.ja4} placeholder.
//
// Caddyfile:
//
//	{
//		servers {
//			listener_wrappers {
//				ja4
//				tls
//			}
//		}
//	}
//	example.com {
//		ja4 X-Lawn-Client-JA4
//		reverse_proxy ...
//	}
//
// HTTP/3 (QUIC) connections do not pass through listener wrappers, so they
// carry no fingerprint: the header is removed and the variable left empty.
package caddyja4

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/boydj/getoffmyfuckinglawn.com/caddy/ja4"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Listener{})
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4", parseHandler)
	// Before header, so header and reverse_proxy see the result.
	httpcaddyfile.RegisterDirectiveOrder("ja4", httpcaddyfile.Before, "header")
}

// Listener is the caddy.listeners.ja4 listener wrapper.
type Listener struct{}

// CaddyModule returns the Caddy module information.
func (Listener) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "caddy.listeners.ja4", New: func() caddy.Module { return new(Listener) }}
}

// WrapListener wraps every accepted connection in a *Conn.
func (*Listener) WrapListener(l net.Listener) net.Listener { return &listener{l} }

// UnmarshalCaddyfile sets up the wrapper; it takes no arguments.
func (*Listener) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

type listener struct{ net.Listener }

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: c}, nil
}

// Conn records the ClientHello read from it. Recording stops as soon as
// the hello is complete (or the stream is not TLS), so later reads only
// cost an atomic load.
type Conn struct {
	net.Conn
	mu   sync.Mutex
	rec  ja4.Recorder
	done atomic.Bool
	fp   atomic.Pointer[string]
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.done.Load() {
		c.mu.Lock()
		if !c.rec.Done() {
			c.rec.Write(p[:n])
			if c.rec.Done() {
				fp, _ := c.rec.Result()
				c.fp.Store(&fp)
				c.done.Store(true)
			}
		}
		c.mu.Unlock()
	}
	return n, err
}

// JA4 returns the connection's fingerprint, "" until the ClientHello has
// been read or when it could not be parsed.
func (c *Conn) JA4() string {
	if p := c.fp.Load(); p != nil {
		return *p
	}
	return ""
}

// find returns the *Conn underneath c (e.g. under a *tls.Conn).
func find(c net.Conn) *Conn {
	for range 8 {
		switch v := c.(type) {
		case *Conn:
			return v
		case interface{ NetConn() net.Conn }:
			c = v.NetConn()
		default:
			return nil
		}
	}
	return nil
}

type connKey struct{}

// Handler is the http.handlers.ja4 middleware.
type Handler struct {
	// Header receives the fingerprint. Any value the client sent under
	// this name is removed first. Empty: only {http.vars.ja4} is set.
	Header string `json:"header,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.ja4", New: func() caddy.Module { return new(Handler) }}
}

// Provision makes the server put each request's connection in its context.
// The hook runs when the connection is accepted, before the handshake, so
// the *Conn itself is stored and read once the request arrives.
func (h *Handler) Provision(ctx caddy.Context) error {
	if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok {
		srv.RegisterConnContext(connContext)
	}
	return nil
}

// connContext stores the connection's *Conn in its context, once.
func connContext(ctx context.Context, c net.Conn) context.Context {
	if jc := find(c); jc != nil && ctx.Value(connKey{}) == nil {
		return context.WithValue(ctx, connKey{}, jc)
	}
	return ctx
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var fp string
	if jc, ok := r.Context().Value(connKey{}).(*Conn); ok {
		fp = jc.JA4()
	}
	if h.Header != "" {
		r.Header.Del(h.Header)
		if fp != "" {
			r.Header.Set(h.Header, fp)
		}
	}
	caddyhttp.SetVar(r.Context(), "ja4", fp)
	return next.ServeHTTP(w, r)
}

// parseHandler parses "ja4 [<header>]".
func parseHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	h.Next()
	if h.NextArg() {
		m.Header = h.Val()
	}
	if h.NextArg() {
		return nil, h.ArgErr()
	}
	return &m, nil
}

var (
	_ caddy.ListenerWrapper       = (*Listener)(nil)
	_ caddyfile.Unmarshaler       = (*Listener)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
