package web

import (
	"html/template"
	"io/fs"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	fsys := Templates("")
	for _, want := range []string{"home.html", "partials.html"} {
		if _, err := fs.Stat(fsys, want); err != nil {
			t.Errorf("embedded %s: %v", want, err)
		}
	}
	tpl, err := template.ParseFS(fsys, "*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"home", "style", "footer"} {
		if tpl.Lookup(name) == nil {
			t.Errorf("template %q not defined", name)
		}
	}
	// A disk override is honoured.
	if _, err := fs.Stat(Templates("templates"), "home.html"); err != nil {
		t.Errorf("dir override: %v", err)
	}
}
