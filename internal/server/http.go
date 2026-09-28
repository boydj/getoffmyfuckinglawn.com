package server

import (
	"bytes"
	"html"
	"net/http"
	"time"

	"github.com/boydj/getoffmyfuckinglawn.com/internal/maze"
)

// NewPublicServer wraps h with the self-protection timeouts from SPEC.md
// section 5.3. WriteTimeout must outlast the longest drip, so it is
// maxDrip plus a margin for the fast finish.
func NewPublicServer(addr string, h http.Handler, maxDrip time.Duration) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      maxDrip + 2*time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// NewAdminServer serves /metrics and /healthz; bind it to localhost only.
// With pages set it also serves an unlogged maze preview: /lawn/... renders
// exactly what the public site would, at once, with no drip, no limits and
// no log row, so the operator can browse the maze through an SSH tunnel
// without landing in their own reports.
func NewAdminServer(addr string, metrics http.Handler, pages PageRenderer) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	if pages != nil {
		index := previewIndex(pages.EntryURLs(8))
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(index)
		})
		preview := func(w http.ResponseWriter, r *http.Request) {
			buf := maze.GetBuffer()
			defer maze.PutBuffer(buf)
			pages.Render(buf, r.URL.Path)
			h := w.Header()
			h.Set("Content-Type", "text/html; charset=utf-8")
			h.Set("Cache-Control", "no-store")
			h.Set("X-Robots-Tag", "noindex")
			w.Write(buf.Bytes())
		}
		mux.HandleFunc("GET /lawn", preview)
		mux.HandleFunc("GET /lawn/", preview)
	}
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// previewIndex is the admin listener's landing page: the sitemap's entry
// points into the maze, previewed without logging.
func previewIndex(entries []string) []byte {
	var b bytes.Buffer
	b.WriteString(`<!doctype html><meta charset="utf-8"><title>lawn admin</title>
<h1>lawn admin</h1>
<p>Maze preview: pages exactly as the public site renders them, served at once
and never logged. Only reachable from the server itself (use an SSH tunnel).</p>
<ul>
<li><a href="/lawn/">/lawn/</a></li>
`)
	for _, e := range entries {
		b.WriteString(`<li><a href="`)
		b.WriteString(html.EscapeString(e))
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(e))
		b.WriteString("</a></li>\n")
	}
	b.WriteString(`</ul>
<p><a href="/metrics">/metrics</a></p>
`)
	return b.Bytes()
}
