package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
)

// HomeData feeds the "home" template.
type HomeData struct {
	RobotsTxt string
	Bait      []string // hidden /lawn/ entry links
	BaseURL   string
	Onion     string // onion mirror hostname, "" = none
	// gopher:// and gemini:// URLs of the small-web mirrors ("" = none).
	// template.URL because html/template only lets http(s) and mailto
	// through as links; these come from our own config, never from input.
	Gopher template.URL
	Gemini template.URL
}

// RenderHome renders the static homepage once at startup. It parses every
// top-level *.html in fsys so shared partials are available.
func RenderHome(fsys fs.FS, d HomeData) ([]byte, error) {
	t, err := template.ParseFS(fsys, "*.html")
	if err != nil {
		return nil, fmt.Errorf("server: parse templates: %w", err)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "home", d); err != nil {
		return nil, fmt.Errorf("server: render home: %w", err)
	}
	return buf.Bytes(), nil
}
